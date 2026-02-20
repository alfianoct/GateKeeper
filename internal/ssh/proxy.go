package ssh

import (
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type ProxySession struct {
	ID       string
	HostID   string
	HostName string
	HostAddr string
	Username string
	UserID   string

	client  *ssh.Client
	session *ssh.Session
	stdin   chan []byte
	stdout  chan []byte
	resize  chan TermSize

	bytesTX int64
	bytesRX int64
	mu      sync.Mutex

	done chan struct{}
	once sync.Once
}

type TermSize struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

type ConnectConfig struct {
	Host            string
	Port            int
	Username        string
	Password        string
	PrivateKey      []byte // PEM-encoded
	Timeout         time.Duration
	HostKeyCallback ssh.HostKeyCallback
}

// Connect dials the host, sets up a PTY, and wires stdin/stdout channels.
func Connect(cfg ConnectConfig) (*ProxySession, error) {
	auths := []ssh.AuthMethod{}

	if len(cfg.PrivateKey) > 0 {
		signer, err := ssh.ParsePrivateKey(cfg.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		auths = append(auths, ssh.PublicKeys(signer))
	}

	if cfg.Password != "" {
		auths = append(auths, ssh.Password(cfg.Password))
	}

	if len(auths) == 0 {
		return nil, fmt.Errorf("no authentication method provided")
	}

	// never allow InsecureIgnoreHostKey, TOFU or bust
	hostKeyCallback := cfg.HostKeyCallback
	if hostKeyCallback == nil {
		return nil, fmt.Errorf("host key callback is required — cannot connect without host key verification")
	}

	sshConfig := &ssh.ClientConfig{
		User:            cfg.Username,
		Auth:            auths,
		Timeout:         cfg.Timeout,
		HostKeyCallback: hostKeyCallback,
	}

	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshConfig)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake %s: %w", addr, err)
	}

	client := ssh.NewClient(c, chans, reqs)

	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("new session: %w", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm-256color", 24, 80, modes); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("request pty: %w", err)
	}

	stdinPipe, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("stdin pipe: %w", err)
	}

	stdoutPipe, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	stderrPipe, err := session.StderrPipe()
	if err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := session.Shell(); err != nil {
		session.Close()
		client.Close()
		return nil, fmt.Errorf("start shell: %w", err)
	}

	ps := &ProxySession{
		HostAddr: addr,
		client:   client,
		session:  session,
		stdin:    make(chan []byte, 256),
		stdout:   make(chan []byte, 256),
		resize:   make(chan TermSize, 8),
		done:     make(chan struct{}),
	}

	go func() {
		for {
			select {
			case data := <-ps.stdin:
				n, err := stdinPipe.Write(data)
				if err != nil {
					slog.Warn("SSH stdin write error", "err", err)
					ps.Close()
					return
				}
				ps.mu.Lock()
				ps.bytesTX += int64(n)
				ps.mu.Unlock()
			case <-ps.done:
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				out := make([]byte, n)
				copy(out, buf[:n])
				ps.mu.Lock()
				ps.bytesRX += int64(n)
				ps.mu.Unlock()
				select {
				case ps.stdout <- out:
				case <-ps.done:
					return
				}
			}
			if err != nil {
				ps.Close()
				return
			}
		}
	}()

	// stderr gets merged into stdout channel
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				out := make([]byte, n)
				copy(out, buf[:n])
				ps.mu.Lock()
				ps.bytesRX += int64(n)
				ps.mu.Unlock()
				select {
				case ps.stdout <- out:
				case <-ps.done:
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		for {
			select {
			case size := <-ps.resize:
				if err := session.WindowChange(size.Rows, size.Cols); err != nil {
					slog.Warn("SSH window change error", "err", err)
				}
			case <-ps.done:
				return
			}
		}
	}()

	go func() {
		session.Wait()
		ps.Close()
	}()

	return ps, nil
}

func (ps *ProxySession) Write(data []byte) {
	select {
	case ps.stdin <- data:
	case <-ps.done:
	}
}

func (ps *ProxySession) Read() <-chan []byte {
	return ps.stdout
}

func (ps *ProxySession) Resize(cols, rows int) {
	select {
	case ps.resize <- TermSize{Cols: cols, Rows: rows}:
	case <-ps.done:
	}
}

func (ps *ProxySession) Done() <-chan struct{} {
	return ps.done
}

func (ps *ProxySession) BytesTX() int64 {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.bytesTX
}

func (ps *ProxySession) BytesRX() int64 {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	return ps.bytesRX
}

func (ps *ProxySession) Close() {
	ps.once.Do(func() {
		close(ps.done)
		if ps.session != nil {
			ps.session.Close()
		}
		if ps.client != nil {
			ps.client.Close()
		}
		slog.Info("SSH session closed", "user", ps.Username, "addr", ps.HostAddr)
	})
}
