# 1 Device Setup And Administration
## 1.1 General Settings
### 1.1.1 Ensure admin session 'lock', 'logout' for inactivity and 'block' is configured for failed sign-in (Automated)
Navigate to `System > Administration > Admin and user settings`
Set ` Lock admin session after _ Minutes of inactivity` is checked and configured with no more than 3 minutes of default value.
Set  ` Logout admin session after _ Minutes of inactivity` is checked and configured with no more than 10 minutes of default value.
Set `Block login` is checked.
### 1.1.2 Ensure login disclaimer is set (Automated)
Navigate to `System > Administration > Admin and user settings > Login Disclaimer Settings`.
`Enable login disclaimer` is checked and set the disclaimer message appropriately.
### 1.1.3 Ensure NTP servers are configured appropriately (Automated) (you to set it manuelly !!)
Navigate to ` System > Administration > Time`.
Set `Time Zone` correctly.
Set ` Use pre-defined NTP Server ` Or ` Use custom NTP Server ` is checked and 
synchronize the device's clock.
### 1.1.5 Ensure password complexity check is enabled (Automated)
Navigate to ` System > Administration > Admin and user settings > Administrator password complexity settings > Enable password complexity check `.
Set Enable password complexity check
Set that the various password settings to values that are appropriate to your organization. It is suggested that there at least be some special characters enforced, and that a minimum length be set. Ensure that Minimum Uppercase, Lowercase and Special Characters. 
Operationally, dictionary words should be avoided for all passwords - passphrases are a much better alternative.
### 1.1.6 Ensure management access to the device is restricted from selected IP addresses and disable from WAN Zone (Automated)
Navigate to `System > Administration > Device Access > Local service ACL`.
Uncheck `HTTPS,SSH,PING/PING6,DNS,SMTP RELAY, SNMP` on `WAN Zone`.


## 1.2 SNMP & Device Notification Settings
### 1.2.1 Ensure SNMPv3 is selected for queries and traps (Manual)
Navigate to `System > Administration > SNMP`.
Remove insecure SNMPv1 and v2 configurations.
Set `SNMPv3 users and traps > Encryption algorithm` is configured with either 
AES or DES. Set appropriate password strength for both authentication and encryption.
### 1.2.2 Ensure notification is configured to send system and security events (Manual)
Navigate to `System > Administration > Notification settings`.
    When `built-in email server` is used.
        Set the `from email address` of the sender.
        Set the `Send notifications to email address` of the administrators’ email address.
        Set `Management interface IP address` to send notification from.
    When `External mail server` is used.
        Set the `Mail server IPv4 address/FQDN – Port` is set to the outgoing mail server.
        Set `username` and `password` to authenticate to the outgoing mail server.
        Set `connection security` to `STARTTLS` or `SSL/TLS`.

Navigate to `Configure > System services > Notification list`.
Set the appropriate admin, system and security events to send email notification and/or SNMP traps.

## 2 User Identification & Authentication
## 2.2 Ensure Encrypted connection is used in connecting external Active Directory and LDAP (Manual)
Navigate to `Configure > Authentication > Servers > Edit or Add` and set `connection security` with either `SSL/TLS` or `STARTTLS` and `Validate server certificate` is checked.
## 3 System Services, Firmware and Updates
### 3.1 Ensure "Fully Synchronized" High Availability peer is configured (Manual)
Navigate to `System Services > High Availability > High Availability Status`.
    When `Local` and `Peer` devices are shown as `Standalone` or `Faulty`, connection to the auxiliary device could be lost or becomes a faulty node, re-configure HA and sync auxiliary device to a working state. 

Navigate to `High Availability Configuration > Select ports to be monitored`. 
Set the correct interfaces to be monitored.
Configure default value of `Keepalive request interval` to `250` milliseconds and `Keepalive attempts` to `16` attempts or set to optimal setting respectively.
### 3.2 Ensure 'Pattern updates' is set to download and install updates every 15 minutes (Manual)
Navigate to `System > Backup & Firmware > Pattern Updates`.
Set `Pattern download/installation > Auto update` to `ON`.
Set the download `Interval` to `Every 15 minutes`.
    When the `Pattern` `Last successful update` is not showing `Success`, 
    click `Update pattern now` to download the updates manually.
### 3.4 Ensure XG takes encrypted backup of the configuration and send to designated email address with scheduled frequency (Manual)
Navigate to `System > Backup & Firmware > Backup & Restore > Backup`.
Backup mode is set to either `FTP` or `Email`. 
    When `Backup mode` is set to `FTP`,
        configure `FTP server IP`, `Username` or `FTP password`.
    When `Backup mode` is set to `Email`,
        configure `Email Address` to the administrators' email address.
        `Frequency` is set to `Daily, Weekly or Monthly`.
Set strong `Encryption password` and ensure that encrypted backup can be sent successfully. Store the `Encryption password` in secure location for future recovery.
### 3.5 Ensure No Expired Subscription Licenses (Manual)
Navigate to `System > Administration > Licensing`.
Under `Module subscription details` and click `Synchronize` to connect to the 
licensing server to get latest subscription details. Or contact Sophos 
immediately to renew the expired licenses.
## 4 Advanced Threat & Synchronised Security
## 5 Protection Rules And Profiles
### 5.7 Ensure DoS & Spoof Protection is enabled with the appropriate settings (Manual)
Navigate to `Protect > Intrusion Prevention > DoS & Spoof Protection`
Set `Enable spoof prevention` is checked on LAN and DMZ zones.
Set `Apply Flag` is checked on `SYN flood`, `UDP flood`, `TCP flood`, `ICMP/ICMPv6` flood on both Source and Destination.
Set `Apply Flag` is checked on `Dropped source routed packets`, `Disable ICMP/ICMPv6 redirect packet`, `ARP hardening` on Destination.
Validate `DoS bypass rule` is not added with wide range of source or destination networks that will reduce integrity of overall DoS protection.
### 5.8 Ensure Firewall Rules with SMB, Netbios, RDP and other unencrypted protocols should not be directly accessible from WAN Zone (Manual)
Navigate to `Rules and policies > Firewall rules`.
Disable or only allow with specific source IP address in `Firewall rules` 
    with `Source zone` `WAN` with service ports `TCP/UDP 445,137-139,3389,21,79,23,113,135,513,389,1433,5800,5900`. 
    When absolute necessary to allow access from Internet, consider the use of VPN.
### 5.9 Ensure Wireless Protection is configured with secure configuration (Manual)
Navigate to `Wireless > Wireless networks`
Set the existing `Wireless` settings with `Security mode`, either `WPA2 Personal` or `WPA2 Enterprise`.
Under `Advanced settings`
Set `Encryption` to `AES[secure]`
Set `Time-based access` to `Enable` with `Select active time` and configure 
appropriate schedule to limit the availability.
Set `Client isolation` to `Enabled`.
### 5.10 Ensure No Firewall Rules with source `ANY`, service `ANY` and destination `ANY` from `WAN` Zone (Manual)
Navigate to `Protect > Rules and policies > Firewall rules`.
Filter `Destination zone` to `LAN` or `DMZ`.
Remove allowed firewall rules from `WAN` zone with service definition `ANY` to `LAN` or `DMZ` zone with destination network set to `ANY`. Or change the rule to specific source/Destination with target service definition.
