# 1 Device Setup And Administration
## 1.1 General Settings
### 1.1.4 Ensure SSL server certificate for remote SSL VPN is configured correctly (Manual)
Create a CSR and install a certificate from a public CA.
Navigate to `System > Administration > Admin and user settings > Admin console and end-user interaction > Certificate`.
Set a valid certificate to the User portal.
Navigate to `Configure > Show VPN settings > SSL VPN settings > SSL server certificate`.
Set a valid certificate for the SSL VPN Gateway.

### 1.1.7 Ensure valid certificate is set for web browser used to access Webadmin interface (Automated)
If a new administrative Certificate is needed, acquire a Certificate that meets the stated criteria and upload it to the XG Firewall. Optionally, download the appliance Certificate Authority to the web browser used for administration.
Navigate to `System > Certificates > Certificates > Add`
Import an appropriate Certificate for your administrative session, from a trusted Certificate Authority.
Navigate to `System > Administration > Admin and user settings > Admin console and end-user interaction > Certificate`
Choose the correct certificate to use for the web based administrative session.
# 2 User Identification & Authentication
## 2.1 Ensure Firewall rules are configured to identify users before authorizing access (Manual)
To enable user based firewall rule:
Navigate to `Protect > Rules and policies > Firewall rules` edit existing policies or when creating a new firewall policy `match known users` is checked. 
`Log firewall traffic` is checked to log for allowed traffic.
Configure authentication server to use for firewall connections.
Navigate to `Configure > Authentication > Services > Firewall authentication methods` move the primary authentication server at the top.
Configure Clientless users for devices such as printers and IoT devices that unable to authenticate with standard authentication options.
To add the devices to clientless users, navigate to `Configure > Authentication > Clientless users > Add or Add range`
In Active directory environment AD SSO can be configured to allow unauthenticated web access.
Navigate to `Configure > Authentication > Web Authentication > Authorize unauthenticated users for web access > Kerberos & NTLM` and `show captive portal link` is checked.
In Window only environment clientless SSO can be configured to authenticate with XG based on security logon events at the Domain Controllers.
Navigate to `Configure > Authentication > STAS > Enable Sophos Transparent Authentication Suite > Add new collector` and `Restrict client traffic during identity probe > Yes`.
Refer to the reference section for more information with the configuration.
# 3 System Services, Firmware and Updates
## 3.1 Ensure "Fully Synchronized" High Availability peer is configured (Manual)
Navigate to `System Services > High Availability > High Availability Status`.
    When `Local` and `Peer` devices are shown as `Standalone` or `Faulty`, connection to the auxiliary device could be lost or becomes a faulty node, re-configure HA and sync auxiliary device to a working state. 

Navigate to `High Availability Configuration > Select ports to be monitored`. 
Set the correct interfaces to be monitored.
Configure default value of `Keepalive request interval` to `250` milliseconds nd `Keepalive attempts` to `16` attempts or set to optimal setting respectively.

## 3.6 Ensure Site-to-Site IPSec VPN is not configured with "Aggressive Mode" (Manual)
Navigate to `Configure > Site to site VPN`.
Remove any active `IPsec policy` configured with `Encryption` = `IKEv1` and `Authentication mode` = `Aggressive mode`and replace with `IKEv2` or `Main mode`.
## 3.7 Ensure Logging is enabled on firewall rules and configured to send logs to the external syslog server (Manual)
Navigate to `Protect > Rules and policies`.
Set `Log firewall traffic` is checked for configured firewall rules.

Navigate to `Configure > System services > Log settings`.
Configure external syslog server and set to send system, security events to external syslog server.

# 4 Advanced Threat & Synchronised Security
## 4.1 Ensure 'Enable advanced threat protection' is set to ‘ON’ and Policy is set to ‘Log and drop’ (Manual)
Navigate to `Advanced protection > Advanced threat protection > Enable advanced threat protection`.
Verify that `Enable advanced threat protection` is set to `ON`.
Set the policy to `Log and drop`.
Remove unnecessary exception from network and threat exceptions.

## 4.2 Ensure Sandstorm is enabled at the firewall rule for web protection and does not exclude any file type from Sandstorm analysis (Manual) (alternatives)
Navigate to `Protect > Rules and policies > Firewall rules` existing firewall rule with allowed outbound traffic and configure `Security features > Web filtering > Malware and content scanning > Scan HTTP and decrypted HTTPS`, `Detect zero-day threats with Sandstorm` and `Scan FTP for malware` is checked.

Navigate to `Protect > Advanced protection > Advenced security settings` and `Inspect all content` is checked

## 4.4 Ensure Synchronised Security Heartbeat is enforced on Firewall Rules (Manual)
Navigate to `System > Sophos Central`.
Register Sophos XG Firewall to Sophos Central, set `Security Heartbeat` to `ON`.

Navigate to `Protect > Rules and Policies`.
Filter `Rule type > Network` and `User`, filter `source zone > LAN` and `DMZ`.

Navigate to configured firewall rule with `Configure Synchronized Security Heartbeat`. 
Set `Minimum source HB permitted` to `Green` or `Yellow`.

If the rule is configured to allow Egress traffic with Sophos Endpoints are connecting resources on `WAN` zone, set `Minimum source HB permitted` to either `Green` or `Yellow` for tighter security control.

If the rule is configured to allow traffic between `LAN` to `DMZ` zones with communication between Sophos protected Endpoints and Server, configure additional control with setting both `Minimum source HB permitted` and `Minimum destination HB permitted` to either `Green` or `Yellow`.

# 5 Protection Rules And Profiles
## 5.1 Ensure Web Policy is configured to block inappropriate URLs, Malware and content scanning is configured correctly. (Manual) (the configuration of this rule is totally changed) (somewhat automated !!!!!)

Navigate to `Protect > Web > Categories`
Create category from `objectionable classification`

Navigate to `Protect > Web > policies`
Set the web policy to block categories with `objectionable classification` and change the status to `ON`.
Within the web policy set the `Enable logging and reporting`.

Navigate to `Protect > Web > General settings > Protection > Malware and content scanning` Action on `malware scan failure` is set to `Block(best protection)`.
Enable `Block potentially unwanted applications`.

Navigate to `Protect > Web > Exceptions`

Remove/edit `exceptions` with `URL patterns, website categories and destination IP address (website address)` that could reduce security effectiveness to the `source IP address (end-users' address)`.

## 5.2 Ensure SSL/TLS inspection rules is enabled to all relevant firewall policies (Manual)
Navigate to `Rules and policies > SSL/TLS inspection rules > SSL/TLS inspection settings`.

Set `Non-decryptable traffic > SSL 2.0 and SSL 3.0` to `Reject` or `Drop`.
Set `SSL compression` to `Reject` or `Drop`.
Set `When SSL/TLS connections exceed limit` to `Drop` or `Reject`.
Set `TLS 1.3 decryption` to `Decrypt as 1.3`.
Set `Advanced settings > SSL/TLS engine` to `Enabled`.

Navigate to configured `SSL/TLS inspection rule` and set the `Action` to `Decrypt` and `Log connections` is checked. Set the rule position to above rules configured with `Action` set to `Don't decrypt`.

Navigate to the configured `Firewall rules`. Set `Scan HTTP and decrypted HTTPS` and `Use zero-day protection` is checked.

## 5.3 Ensure Application filter is set to block high risk (Risk Level 4 and 5) applications (Manual)
Navigate to `Protect > Rules and policies > Firewall rules`.
Set the configured outgoing firewall rules with `Identify and control applications (App control)` to `Block high risk (Risk Level 4 and 5) apps`.

## 5.4 Ensure Intrusion Prevention(IPS) policy is configured on active firewall rules (Manual)
Navigate to `Protect > Rules and policies > Firewall rules`.
Navigate to configured firewall rules. Set `Detect and prevent exploits (IPS)` with appropriate IPS rule based on the direction of the traffic. 
Configure IPS policy with gerenalpolicy, lantowan_strict, lantowan_general, dmzpolicy, LAN TO WAN, LAN TO DMZ, WAN TO DMZ, WAN TO LAN, DMZ TO WAN, DMZ TO LAN or “custom IPS rule”.

## 5.5 Ensure Web Application Firewall (WAF) is configured with appropriate protection policies in all the WAF rules in use (Manual)
Navigate to `Protect > Web server > General settings > Slow HTTP protection settings`.
Set `Time-out for request headers` to `ON`. 
Set the minimum amount of time to receive a request `Soft limit` to optimal configuration. Default setting is `10`. 
Set the maximum amount of time to receive the request header `Hard limit` to optimal configuration. Default setting is `30`. 
Set the amount of data, in bytes, to extend the time-out set by the soft limit. Every time the rate is exceeded, the soft limit is increased by one second. The default extension rate is `5000`.
Set `TLS version settings > TLS version` to TLS 1.2. Select the minimum TLS version that is allowed to connect to the WAF. Note that if TLS version 1.2 is selected, clients like Microsoft Internet Explorer 8 or earlier and those running on Window XP won’t be able to connect to the WAF.

Navigate to the configure WAF rules `Rules and policies > Firewall rules`, filter `Rule type > WAF`. 

Under `Advanced > Protection > edit protection policy` set `Mode` to `Reject`. 
Set `Cookie signing` to `ON`. 
Set `Static URL hardening` to `ON` with specify the URLs you want to serve. 
Note that this feature isn’t effective for dynamic URLs created by the client, for example, using JavaScript.
Set `Form hardening` to `ON`. 
Set `Antivirus` to `ON` with scanning `Mode` to either `Sophos` or `Dual scan`. And Direction of the scanning is set to `Uploads and Downloads`.
Set `Block unscannable content` to `ON`.
Set `Block clients with bad reputation` to `ON`.
Set `Common threat filter` to `ON`. Remove these rule IDs (901100,901110,949100,949190,949110,959100,980100,980110,980120,980130,980140) added to the Skip filter rules.
Set `Application attacks` to enable.
Set `SQL injection attacks` to enable.
Set `XSS attacks` to enable.
Set `Protocol enforcement` to enable.
Set `Scanner detection` to enable.
Set `Data leakage` to enable.
Within the configured firewall rule with WAF verify that Intrusion prevention is set to either `WAN TO LAN` or `WAN TO DMZ` or custom IPS rule with target server platform.

## 5.6 Ensure Email protection is configured with appropriate protection policies (Manual)
Navigate to `Protect > Email > General settings`. Set the appropriate `SMTP deployment mode` to `MTA mode` when possible. `legacy mode` is not compatible with Sandstorm for Email and reduce the security effectiveness.
Navigate to `SMTP settings`.

Set `Reject based on IP reputation` to Enable. XG Firewall checks the sender's IP reputation before the spam checks specified in the SMTP policy. 

Set `SMTP DoS settings` to Enable. XG Firewall protects the network from SMTP denial-of-service attacks.

Navigate to `SMTP TLS configuration`. Set `Disable legacy TLS protocols` to Enable. To overcome TLS vulnerabilities, it is recommended to turn off legacy TLS protocols.

Navigate to `POP and IMAP TLS configuration`. Set `Disable legacy TLS protocols` to Enable.

Navigate to `Malware protection`. Set `Primary antivirus engine` to `Sophos`. 

If `Avira` is selected XG Firewall will turn off Sandstorm in SMTP policies with single antivirus scan.

Navigate to `DKIM verification`. Set `DKIM verification` to `ON` and `DKIM verification failed`, `Invalide DKIM signature`, `No DKIM signature found` are set to `Quarantine` or `Reject`.
 With DKIM XG validates the source domain name and message integrity through cryptographic authentication, preventing email spoofing. DKIM verification is applied to inbound emails. Note that XG Firewall quarantines DKIM-signed emails that use RSA SHA-1 or have key length less than 1024 or more than 2048 bits.

Navigate to `Protect > Email > Relay settings > Host based relay`.
Remove `ANY` from the `allow relay from hosts/networks`. Adding `ANY` will result in an open relay, allowing anyone on the internet to send emails through XG Firewall. Set only the specified host or enable authenticated relay.

Navigate to `Protect > Email > Policy & exceptions`. Set the configured SMTP policy `Malware protection > Selected antivirus action` to `Drop` and `Quarantine unscannable content` is checked and `Detect zero-day threats with Sandstorm Scanned file size` is set to 10 MB.


