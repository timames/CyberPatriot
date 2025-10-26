# 🛡️ CyberPatriot Competition Resources

<div align="center">

![CyberPatriot](https://img.shields.io/badge/CyberPatriot-Competition-blue?style=for-the-badge)
![Hawaii Baptist Academy](https://img.shields.io/badge/Hawaii_Baptist_Academy-Team-gold?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-green?style=for-the-badge)

**Comprehensive reference guide and resources for AFA CyberPatriot competitions**

*Developed by Hawaii Baptist Academy CyberPatriot Team*

[📖 Documentation](#documentation) • [🚀 Quick Start](#quick-start) • [⚡ Features](#features) • [📋 Checklists](#competition-checklists) • [🤝 Contributing](#contributing)

</div>

---

## 📖 About

This repository contains a comprehensive **Competition Reference Guide** for the Air Force Association's CyberPatriot National Youth Cyber Defense Competition. The guide provides prioritized checklists, commands, and best practices for securing Windows, Linux, and Cisco networking systems during competition rounds.

### 🎯 Purpose

- **Quick Reference**: Instant access to critical security commands during 6-hour competition windows
- **Prioritized Content**: Organized by point value and common vulnerability patterns
- **Best Practices**: Compiled from previous competition winners and official CyberPatriot resources
- **Multi-Platform**: Covers Windows, Linux (Ubuntu/Debian), and Cisco IOS

### 🏫 About Hawaii Baptist Academy

**Location**: Pearl City, Hawaii  
**Mission**: Defending Networks • Building Character • Serving Christ  
**Motto**: *"Be strong and courageous."* - Joshua 1:9

---

## 🚀 Quick Start

### Accessing the Reference Guide

1. **Clone the repository**:
   ```bash
   git clone https://github.com/timames/CyberPatriot.git
   cd CyberPatriot
   ```

2. **Open the reference guide**:
   - Open `HBA_CyberPatriot_Reference_Guide.html` in any web browser
   - Use during practice rounds and competition (if allowed by competition rules)
   - Bookmark for quick access

3. **Search functionality**:
   - Use the built-in search boxes to quickly find specific commands
   - Filter by keywords like "user", "firewall", "password", etc.

---

## ⚡ Features

### 🎨 Interactive HTML Guide
- **Tabbed Interface**: Separate tabs for Windows, Linux, and Cisco
- **Search Functionality**: Quickly find commands by keyword
- **Color-Coded Priorities**: 
  - 🔴 **CRITICAL** - Must-do items (Forensics, Backdoors)
  - 🟠 **HIGH** - High-value items (15-30 points typically)
  - 🔵 **MEDIUM** - Important but lower priority

### 📋 Comprehensive Coverage

#### Windows
- First Steps & Competition Workflow
- User Management (15-30 points)
- Password Policy Configuration
- Service Hardening
- Firewall & Windows Defender
- Registry Hardening & Backdoor Removal
- Scheduled Tasks Analysis
- Local Security Policies
- Network Shares Management
- Media File Detection
- Program Management
- Windows Features
- Browser Hardening
- SysInternals Tools

#### Linux (Ubuntu/Debian)
- First Steps & Competition Workflow
- User Management & sudo Configuration
- Password Policy & PAM Configuration
- UFW Firewall Setup
- SSH Hardening
- Package Management & Updates
- Service Management
- Backdoor Detection (cron, rc.local)
- Kernel Hardening (sysctl)
- Antivirus (ClamAV, rkhunter, chkrootkit)
- File Permissions & Security
- Network Security

#### Cisco Networking
- Basic Security Configuration
- Interface Configuration
- VLAN Setup
- Static & Dynamic Routing (OSPF)
- Access Control Lists (ACLs)
- SSH Configuration
- DHCP Setup
- Port Security
- Verification Commands

---

## 📋 Competition Checklists

### 🚨 Universal First Steps (ALL Operating Systems)

1. **READ README THOROUGHLY** - Note authorized users, admins, required services
2. **ANSWER FORENSICS QUESTIONS FIRST** - Before ANY system changes!
3. Take screenshot of initial score
4. Document all changes made
5. Backup current configurations

### Windows Priority Order

```
1. Forensics Questions (FIRST!)
2. User Management (15-30 pts)
   - Disable guest account
   - Delete unauthorized users
   - Remove unauthorized admins
   - Set strong passwords
3. Password Policy
4. Firewall - Enable all profiles
5. Windows Defender - Enable & scan
6. Services - Start critical, disable dangerous
7. Windows Update - Enable
8. Local Security Policies
9. Scheduled Tasks - Check for backdoors
10. Registry Hardening
11. Network Shares - Review/delete
12. Media Files - Search and remove
13. Programs - Uninstall unauthorized
14. Windows Features - Disable dangerous ones
15. Browser Hardening
```

### Linux Priority Order

```
1. Forensics Questions (FIRST!)
2. Lock root account
3. User Management (15-30 pts)
   - Check UID 0 users
   - Delete unauthorized users
   - Remove unauthorized sudo
4. Password Policy (BEFORE changing passwords!)
   - Install libpam-cracklib
   - Configure /etc/login.defs
   - Configure PAM
5. UFW Firewall - Enable
6. SSH Hardening
7. Updates - apt-get update && upgrade
8. Services - Disable dangerous services
9. Backdoor Detection - cron, rc.local, ports
10. Kernel Hardening - sysctl
11. Remove prohibited packages
12. Antivirus - Run scans
13. Media Files - Search and remove
14. File Permissions
```

---

## 🔧 Installation & Setup

### Prerequisites

- Modern web browser (Chrome, Firefox, Edge, Safari)
- No installation required - pure HTML/CSS/JavaScript

### For Competition Use

1. Download `HBA_CyberPatriot_Reference_Guide.html`
2. Open in browser
3. Bookmark or keep tab open during competition
4. Use search functionality to quickly find commands

### Offline Use

The reference guide works completely offline - no internet connection required once downloaded.

---

## 📚 Documentation

### Command Structure

Each command in the guide includes:
- **Comment**: What the command does
- **Code**: Exact command to run
- **Context**: When and why to use it
- **Warnings**: Important notes and gotchas

### Example Entry

```
# Disable guest account (ALWAYS do this!)
net user guest /active:no
```

### Search Keywords

Each section is tagged with keywords for easy searching:
- Windows: `user`, `password`, `firewall`, `services`, `registry`, `scheduled tasks`
- Linux: `user`, `sudo`, `firewall`, `ufw`, `ssh`, `cron`, `sysctl`
- Cisco: `vlan`, `ospf`, `acl`, `ssh`, `interface`, `routing`

---

## ⚠️ Important Disclaimers

### Competition Rules

1. **Read README First**: Always follow the scenario instructions
2. **No Automation During Competition**: CyberPatriot rules prohibit automated scripts during competition rounds
3. **Reference Only**: This guide is for reference and learning - not for automated execution
4. **Understand Commands**: Know what each command does before running it
5. **Practice First**: Use this guide during practice rounds to become familiar

### Educational Use

This repository is intended for:
- ✅ Learning cybersecurity concepts
- ✅ Practice rounds and training
- ✅ Reference during competition (if allowed)
- ✅ Post-competition analysis
- ❌ NOT for automated script execution during competition

---

## 🎓 Learning Resources

### Official CyberPatriot Resources

- [CyberPatriot Official Website](https://www.uscyberpatriot.org/)
- [CyberPatriot Training Materials](https://www.uscyberpatriot.org/competition/training-materials)
- [Cisco NetAcad](https://www.netacad.com/) - Free networking courses

### Additional Resources

- [Marshall Cyber Club Checklists](https://marshallcyberclub.github.io/)
- [GitHub CyberPatriot Topics](https://github.com/topics/cyberpatriot)
- [Windows Security Baseline](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-security-baselines)
- [Ubuntu Security Guide](https://ubuntu.com/security)
- [Cisco IOS Security Configuration Guide](https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html)

---

## 🤝 Contributing

### How to Contribute

We welcome contributions from the CyberPatriot community! Here's how you can help:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/new-command`
3. **Make your changes**
4. **Test thoroughly**
5. **Submit a pull request**

### Contribution Guidelines

- Add commands that are commonly useful in competition
- Include clear comments explaining what commands do
- Test all commands before submitting
- Follow existing formatting and structure
- Cite sources when applicable

### What to Contribute

- Additional commands or techniques
- Corrections to existing content
- New sections or categories
- Improved explanations
- Updated documentation

---

## 📜 Credits & Acknowledgments

### Sources

This guide was compiled from multiple sources including:

- **Official CyberPatriot Training Materials**
- **DoD STIG (Security Technical Implementation Guides)**
- **Marshall Cyber Club Resources**
- **UAA Cyber (University of Alaska Anchorage) Windows Hardening Guide**
- **Community GitHub Repositories**: 
  - CAMS-CyberPatriot/Linux-Checklist
  - ponkio/CyberPatriot
  - Multiple team repositories and checklists
- **Previous Competition Experience**
- **Microsoft Security Documentation**
- **Cisco IOS Documentation**

### Special Thanks

- Air Force Association for organizing CyberPatriot
- Hawaii Baptist Academy for supporting the team
- All previous CyberPatriot competitors who shared their knowledge
- Open source contributors in the cybersecurity community

---

## 📄 License

This project is licensed for **Educational Use**.

### Usage Terms

- ✅ Use for learning and educational purposes
- ✅ Use during CyberPatriot practice and competition (following competition rules)
- ✅ Modify and adapt for your team's needs
- ✅ Share with other teams and educators
- ❌ Do not use for malicious purposes
- ❌ Do not violate CyberPatriot competition rules

### Disclaimer

This guide is provided "as-is" without warranty. Always verify commands before execution. The authors are not responsible for any system damage or competition penalties resulting from use of this guide.

---

## 🔗 Repository Structure

```
CyberPatriot/
├── HBA_CyberPatriot_Reference_Guide.html    # Main reference guide
├── HBA_Branding_Summary.md                   # Branding documentation
├── README.md                                 # This file
└── resources/                                # Additional resources (if any)
```

---

## 💡 Tips for Success

### Before Competition

- [ ] Review the entire reference guide
- [ ] Practice with training images
- [ ] Memorize critical commands
- [ ] Understand what each command does
- [ ] Test your team's workflow
- [ ] Assign roles (Windows, Linux, Cisco specialist)

### During Competition

- [ ] Read README thoroughly
- [ ] Answer forensics questions FIRST
- [ ] Document all changes
- [ ] Take screenshots of score progress
- [ ] Communicate with team members
- [ ] Don't skip password policy setup
- [ ] Check for backdoors (scheduled tasks, cron jobs)
- [ ] Save configurations frequently

### After Competition

- [ ] Review scoring report
- [ ] Document what worked
- [ ] Note missed vulnerabilities
- [ ] Update reference guide with new findings
- [ ] Share knowledge with team

---

## 📞 Contact & Support

### Hawaii Baptist Academy CyberPatriot Team

- **Location**: Pearl City, Hawaii
- **GitHub**: [timames/CyberPatriot](https://github.com/timames/CyberPatriot)

### Getting Help

- Open an [Issue](https://github.com/timames/CyberPatriot/issues) for bugs or questions
- Submit a [Pull Request](https://github.com/timames/CyberPatriot/pulls) for contributions
- Check [CyberPatriot Official Support](https://www.uscyberpatriot.org/Pages/About/Contact-Us.aspx) for competition questions

---

## 🌟 Star This Repository

If you find this guide helpful, please consider:
- ⭐ Starring this repository
- 🔀 Forking for your team
- 📢 Sharing with other CyberPatriot teams
- 🤝 Contributing improvements

---

<div align="center">

### 🛡️ Defending Networks • Building Character • Serving Christ 🛡️

**"Be strong and courageous." - Joshua 1:9**

*Good luck to all CyberPatriot competitors!*

---

**Made with ⚔️ by Hawaii Baptist Academy CyberPatriot Team**

[![GitHub stars](https://img.shields.io/github/stars/timames/CyberPatriot?style=social)](https://github.com/timames/CyberPatriot/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/timames/CyberPatriot?style=social)](https://github.com/timames/CyberPatriot/network/members)

</div>
