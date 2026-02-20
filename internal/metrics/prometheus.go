package metrics

import (
	"fmt"
	"net/http"

	"github.com/judsenb/gatekeeper/internal/instance"
)

// PrometheusHandler serves /metrics in the text exposition format.
func PrometheusHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		snap := GetSnapshot()
		iid := instance.ID()

		fmt.Fprintf(w, "# HELP gatekeeper_logins_success_total Successful logins\n# TYPE gatekeeper_logins_success_total counter\n")
		fmt.Fprintf(w, "gatekeeper_logins_success_total{instance_id=%q} %d\n", iid, snap.LoginsSuccess)
		fmt.Fprintf(w, "# HELP gatekeeper_logins_failed_total Failed logins\n# TYPE gatekeeper_logins_failed_total counter\n")
		fmt.Fprintf(w, "gatekeeper_logins_failed_total{instance_id=%q} %d\n", iid, snap.LoginsFailed)
		fmt.Fprintf(w, "# HELP gatekeeper_ssh_connects_total SSH connections established\n# TYPE gatekeeper_ssh_connects_total counter\n")
		fmt.Fprintf(w, "gatekeeper_ssh_connects_total{instance_id=%q} %d\n", iid, snap.SSHConnects)
		fmt.Fprintf(w, "# HELP gatekeeper_ssh_disconnects_total SSH disconnections\n# TYPE gatekeeper_ssh_disconnects_total counter\n")
		fmt.Fprintf(w, "gatekeeper_ssh_disconnects_total{instance_id=%q} %d\n", iid, snap.SSHDisconnects)
		fmt.Fprintf(w, "# HELP gatekeeper_audit_events_total Audit events logged\n# TYPE gatekeeper_audit_events_total counter\n")
		fmt.Fprintf(w, "gatekeeper_audit_events_total{instance_id=%q} %d\n", iid, snap.AuditEvents)
		fmt.Fprintf(w, "# HELP gatekeeper_sessions_active Current active SSH sessions\n# TYPE gatekeeper_sessions_active gauge\n")
		fmt.Fprintf(w, "gatekeeper_sessions_active{instance_id=%q} %d\n", iid, snap.SessionsActive)
	})
}
