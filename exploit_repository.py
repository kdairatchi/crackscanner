# exploit_repository.py

# A dictionary of exploits associated with specific CVEs and ports
EXPLOIT_REPOSITORY = {
    21: {
        "CVE-2019-11043": {
            "description": "FTP: Anonymous login vulnerability",
            "exploit": "Use Metasploit module `auxiliary/scanner/ftp/anonymous`."
        }
    },
    22: {
        "CVE-2016-0777": {
            "description": "SSH: Potential weak ciphers",
            "exploit": "Consider disabling weak ciphers or using `ssh-audit`."
        }
    },
    23: {
        "description": "Telnet: Cleartext transmission of sensitive information",
        "exploit": "Use a secure alternative like SSH."
    },
    25: {
        "description": "SMTP: Open relay vulnerability",
        "exploit": "Check for open relay configuration."
    },
    80: {
        "CVE-2021-22963": {
            "description": "HTTP: Directory traversal vulnerability",
            "exploit": "Check for files outside the web root."
        }
    },
    443: {
        "CVE-2014-3566": {
            "description": "HTTPS: SSLv3 POODLE vulnerability",
            "exploit": "Disable SSLv3 on the server."
        }
    },
    3306: {
        "CVE-2012-2122": {
            "description": "MySQL: Remote root access vulnerability",
            "exploit": "Restrict remote root access."
        }
    },
    3389: {
        "CVE-2019-0708": {
            "description": "RDP: BlueKeep vulnerability",
            "exploit": "Use Metasploit module `exploit/windows/rdp/cve_2019_0708_bluekeep_rce`."
        }
    },
    5222: {
        "CVE-2020-12695": {
            "description": "XMPP (Jabber): Potential for remote code execution",
            "exploit": "Review XMPP server configurations."
        }
    },
    # Add more ports and vulnerabilities as needed
}
