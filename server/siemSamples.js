/**
 * Enterprise SIEM Telemetry Dataset
 * Real-world security logs across heterogeneous enterprise formats:
 * - Cisco ASA Firewall Deny/Permit logs
 * - Palo Alto / ArcSight CEF (Port Scans, Log4j Exploit, SYN Floods)
 * - Linux Syslog RFC 5424 (SSH Brute Force, Sudo Shadow Inspection)
 * - Nginx / Apache Web Access (SQLi Injection, Directory Traversal, Auth)
 * - Windows Security Audit Events (Event 4625 Failed Logon, 4688 Suspicious Process Creation, 4720 Backdoor Account)
 * - Fortinet FortiOS UTM & AWS CloudTrail JSON
 */

export const ENTERPRISE_SIEM_LOGS = [
  // 1. Palo Alto Networks CEF - Exploit Attempt
  {
    source_id: 'src-paloalto-perimeter',
    source_name: 'PaloAlto-Edge-Firewall',
    source_type: 'Perimeter NextGen Firewall',
    vendor: 'Palo Alto Networks',
    format: 'CEF',
    raw: 'CEF:0|Palo Alto Networks|PAN-OS|10.1.0|threat|Vulnerability Exploit Detected|9|src=198.51.100.200 dst=10.0.2.15 spt=44120 dpt=80 suser=attacker proto=TCP act=blocked cn1=0 msg=Apache Log4j RCE Attempt (CVE-2021-44228) in User-Agent header'
  },
  // 2. CheckPoint SmartDefense CEF - SYN Flood
  {
    source_id: 'src-checkpoint-gw',
    source_name: 'CheckPoint-Gateway-01',
    source_type: 'Perimeter Gateway',
    vendor: 'Check Point',
    format: 'CEF',
    raw: 'CEF:0|CheckPoint|SmartDefense|R80|drop|Syn Flood Detected|8|src=45.33.32.156 dst=10.0.0.1 spt=51234 dpt=443 proto=TCP act=drop msg=High volume TCP SYN flood detected on external DMZ interface'
  },
  // 3. Cisco ASA Firewall - Deny Access List
  {
    source_id: 'src-cisco-asa-dmz',
    source_name: 'Cisco-ASA-DMZ',
    source_type: 'Network Firewall',
    vendor: 'Cisco',
    format: 'Cisco ASA',
    raw: '%ASA-4-106023: Deny tcp src outside:203.0.113.55/49210 dst inside:192.168.10.5/443 by access-group "OUTSIDE-IN" [0x0, 0x0]'
  },
  // 4. Cisco ASA Firewall - Inbound Teardown
  {
    source_id: 'src-cisco-asa-dmz',
    source_name: 'Cisco-ASA-DMZ',
    source_type: 'Network Firewall',
    vendor: 'Cisco',
    format: 'Cisco ASA',
    raw: '%ASA-6-302014: Teardown TCP connection 481923 for outside:198.51.100.4/80 to inside:10.0.1.15/48201 duration 0:02:15 bytes 14820 TCP FINs'
  },
  // 5. Linux Auth Syslog - SSH Brute Force Failure 1
  {
    source_id: 'src-linux-prod-bastion',
    source_name: 'Linux-Bastion-Host',
    source_type: 'Linux Server Telemetry',
    vendor: 'OpenSSH',
    format: 'Syslog',
    raw: '<86>1 2026-09-16T14:48:12.000Z srv-linux-prod sshd 4192 - - Failed password for invalid user admin from 198.51.100.77 port 38921 ssh2'
  },
  // 6. Linux Auth Syslog - SSH Brute Force Failure 2
  {
    source_id: 'src-linux-prod-bastion',
    source_name: 'Linux-Bastion-Host',
    source_type: 'Linux Server Telemetry',
    vendor: 'OpenSSH',
    format: 'Syslog',
    raw: '<86>1 2026-09-16T14:48:14.000Z srv-linux-prod sshd 4193 - - Failed password for invalid user root from 198.51.100.77 port 38925 ssh2'
  },
  // 7. Linux Auth Syslog - Sudo Elevation to /etc/shadow
  {
    source_id: 'src-linux-prod-bastion',
    source_name: 'Linux-Bastion-Host',
    source_type: 'Linux Server Telemetry',
    vendor: 'Linux Sudo',
    format: 'Syslog',
    raw: '<85>1 2026-09-16T14:50:02.000Z srv-linux-prod sudo 5021 - - deployer : TTY=pts/1 ; PWD=/home/deployer ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow'
  },
  // 8. Linux Auth Syslog - Legitimate Operator Login
  {
    source_id: 'src-linux-prod-bastion',
    source_name: 'Linux-Bastion-Host',
    source_type: 'Linux Server Telemetry',
    vendor: 'OpenSSH',
    format: 'Syslog',
    raw: '<86>1 2026-09-16T14:52:18.000Z srv-linux-prod sshd 4205 - - Accepted publickey for secops from 10.0.1.55 port 54122 ssh2: RSA SHA256:4t7a/8fB9Z'
  },
  // 9. Nginx Web Access - SQL Injection Attack
  {
    source_id: 'src-nginx-web-cluster',
    source_name: 'Nginx-Frontend-Cluster',
    source_type: 'Web Application Server',
    vendor: 'Nginx',
    format: 'Web Access',
    raw: '198.51.100.14 - - [16/Sep/2026:20:15:32 +0530] "GET /api/v1/users?id=1%27%20UNION%20SELECT%20null,username,password_hash%20FROM%20admin_credentials-- HTTP/1.1" 403 284 "-" "sqlmap/1.6#stable"'
  },
  // 10. Nginx Web Access - Directory Traversal Probe
  {
    source_id: 'src-nginx-web-cluster',
    source_name: 'Nginx-Frontend-Cluster',
    source_type: 'Web Application Server',
    vendor: 'Nginx',
    format: 'Web Access',
    raw: '203.0.113.99 - - [16/Sep/2026:20:18:05 +0530] "GET /../../../../etc/passwd HTTP/1.1" 400 168 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
  },
  // 11. Nginx Web Access - Legitimate API Request
  {
    source_id: 'src-nginx-web-cluster',
    source_name: 'Nginx-Frontend-Cluster',
    source_type: 'Web Application Server',
    vendor: 'Nginx',
    format: 'Web Access',
    raw: '10.0.2.80 - alice [16/Sep/2026:20:20:41 +0530] "POST /api/v2/auth/mfa-verify HTTP/1.1" 200 4520 "https://portal.internal/login" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"'
  },
  // 12. Windows Security Event 4625 - Account Lockout / Failed Logon
  {
    source_id: 'src-win-dc-security',
    source_name: 'Windows-DC01-Security',
    source_type: 'Active Directory Domain Controller',
    vendor: 'Microsoft Windows',
    format: 'JSON',
    raw: JSON.stringify({
      eventSource: 'Microsoft-Windows-Security-Auditing',
      eventId: 4625,
      level: 'Warning',
      timestamp: new Date(Date.now() - 120000).toISOString(),
      vendor: 'Microsoft Windows',
      product: 'Active Directory Domain Controller',
      user_name: 'Administrator',
      source_ip: '192.168.100.45',
      destination_ip: '10.0.0.5',
      action: 'Logon Failure',
      message: 'An account failed to log on. Subject: Security ID: S-1-0-0, Account Name: -, Logon Type: 3 (Network), Failure Reason: Unknown user name or bad password. Workstation Name: WORKSTATION-X'
    })
  },
  // 13. Windows Security Event 4688 - Suspicious PowerShell Execution (EDR / Living off the Land)
  {
    source_id: 'src-win-dc-security',
    source_name: 'Windows-DC01-Security',
    source_type: 'Active Directory Domain Controller',
    vendor: 'Microsoft Windows',
    format: 'JSON',
    raw: JSON.stringify({
      eventSource: 'Microsoft-Windows-Security-Auditing',
      eventId: 4688,
      level: 'Critical',
      timestamp: new Date(Date.now() - 90000).toISOString(),
      vendor: 'Microsoft Windows',
      product: 'Active Directory Domain Controller',
      user_name: 'SYSTEM',
      action: 'Process Creation',
      message: 'A new process has been created. Creator Process: cmd.exe (PID 1420), New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -enc SUVYKE5ldy1PYmplY3QgTmV0LldlYkNsaWVudCkuRG93bmxvYWRTdHJpbmco...'
    })
  },
  // 14. Windows Security Event 4720 - Backdoor User Account Created
  {
    source_id: 'src-win-dc-security',
    source_name: 'Windows-DC01-Security',
    source_type: 'Active Directory Domain Controller',
    vendor: 'Microsoft Windows',
    format: 'JSON',
    raw: JSON.stringify({
      eventSource: 'Microsoft-Windows-Security-Auditing',
      eventId: 4720,
      level: 'Warning',
      timestamp: new Date(Date.now() - 60000).toISOString(),
      vendor: 'Microsoft Windows',
      product: 'Active Directory Domain Controller',
      user_name: 'Administrator',
      action: 'Account Management',
      message: 'A user account was created. Target Account Name: svc_backup_hidden, Target Domain: CORP, Subject User: Administrator'
    })
  },
  // 15. Fortinet FortiOS UTM - Web Filter Warning
  {
    source_id: 'src-fortinet-branch',
    source_name: 'FortiGate-Branch-Office',
    source_type: 'UTM Security Gateway',
    vendor: 'Fortinet',
    format: 'Key-Value',
    raw: 'date=2026-09-16 time=20:25:15 devname=FGT60D devid=FGT60D4614041793 logid=0000000013 type=traffic subtype=forward level=warning vd=root srcip=192.168.1.105 srcport=54812 dstip=172.217.16.206 dstport=443 proto=6 action=accept policyid=1 app=HTTPS duration=15 sentbyte=4821 rcvdbyte=18402 msg="SSL traffic permitted"'
  },
  // 16. AWS CloudTrail - Unauthorized Access Key Generation
  {
    source_id: 'src-aws-cloudtrail',
    source_name: 'AWS-CloudTrail-Global',
    source_type: 'Cloud Infrastructure Audit',
    vendor: 'Amazon Web Services',
    format: 'JSON',
    raw: JSON.stringify({
      eventVersion: '1.08',
      eventTime: new Date(Date.now() - 45000).toISOString(),
      eventSource: 'iam.amazonaws.com',
      eventName: 'CreateAccessKey',
      awsRegion: 'us-east-1',
      sourceIPAddress: '198.51.100.88',
      userAgent: 'aws-cli/2.7.0 Python/3.9.12 Linux',
      user_name: 'compromised_dev',
      level: 'Critical',
      action: 'IAM Policy Alteration',
      message: 'AWS IAM CreateAccessKey API executed by compromised_dev from non-corporate IP 198.51.100.88 targeting master root account keys'
    })
  },
  // 17. Suricata Network IDS - Malware CobaltStrike C2 Beaconing
  {
    source_id: 'src-suricata-nids',
    source_name: 'Suricata-NIDS-Core',
    source_type: 'Network Intrusion Detection',
    vendor: 'Suricata',
    format: 'JSON',
    raw: JSON.stringify({
      timestamp: new Date(Date.now() - 30000).toISOString(),
      event_type: 'alert',
      src_ip: '10.0.1.104',
      src_port: 49812,
      dest_ip: '185.220.101.5',
      dest_port: 8443,
      proto: 'TCP',
      alert: {
        action: 'blocked',
        signature_id: 2028912,
        signature: 'ET MALWARE Cobalt Strike Beaconing Detected via malleable HTTP profile',
        category: 'A Network Trojan was detected',
        severity: 1
      },
      message: 'ET MALWARE Cobalt Strike Beaconing Detected via malleable HTTP profile to known C2 server 185.220.101.5:8443'
    })
  }
];
