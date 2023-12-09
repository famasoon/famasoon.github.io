---
title: "Atack of Titan"
date: "2023-12-09"
draft: "false"
---

This is Day 9 of the monicle Advent Calendar!
https://adventar.org/calendars/8977

## tl;dr
Active Directory exploitation involves unauthorized actions by attackers to compromise, manipulate, or gain unauthorized access to an organization's Active Directory infrastructure. This can include stealing credentials, using password hashes, forging tickets, escalating privileges, moving laterally within the network, and establishing persistent access. Organizations should implement security measures to detect and mitigate these threats.

## What is Active Directory

Active Directory (AD) is a directory service developed by Microsoft for Windows domain networks. It is included in most Windows Server operating systems and plays a crucial role in managing and organizing resources within a network, such as computers, users, groups, and other devices.

Key features and functions of Active Directory include:

Directory Service: Active Directory functions as a centralized and hierarchical directory service, organizing and storing information about network resources. This information is organized in a logical and hierarchical structure called the Active Directory Domain Services (AD DS) namespace.

Authentication and Authorization: Active Directory provides authentication and authorization services, allowing users to log in to the network and access resources based on their permissions. It uses the Kerberos protocol for authentication.

Domain Controller: Active Directory relies on servers known as domain controllers, which store a copy of the Active Directory database and authenticate users. Multiple domain controllers within a network provide fault tolerance and redundancy.

Organizational Units (OUs): OUs are containers within an Active Directory domain that allow administrators to organize and manage resources, such as users, groups, and computers, in a more granular way.

Group Policy: Active Directory enables the application of Group Policies, which are sets of rules and configurations that administrators can enforce across the network. Group Policies help maintain consistency and security settings for users and computers.

LDAP Protocol: Active Directory uses the Lightweight Directory Access Protocol (LDAP) to provide a standard way for accessing and interacting with directory services.

DNS Integration: Active Directory relies on Domain Name System (DNS) for name resolution. Proper DNS configuration is essential for the correct functioning of Active Directory.

Global Catalog: The Global Catalog is a distributed data repository that contains a subset of the most commonly used attributes from all objects in the forest. It facilitates searches and queries across multiple domains in a forest.

Active Directory is widely used in enterprise environments to simplify the management of network resources, enhance security through centralized authentication and access control, and streamline administrative tasks. It is a fundamental component for the deployment and management of Windows-based networks.

## Why Should We Care About AD?
Active Directory (AD) is a critical component in Windows-based network environments, and there are several reasons why organizations should care about AD:

Centralized Management: Active Directory provides a centralized and hierarchical structure for organizing and managing network resources. This includes users, computers, groups, and other devices. This centralized management simplifies administrative tasks, making it easier to maintain and control resources across the entire network.

User Authentication and Authorization: AD serves as a central authentication and authorization service. Users can log in to the network using their credentials, and administrators can control access to resources based on permissions assigned through AD. This enhances security and ensures that only authorized individuals can access specific data or applications.

Security Policies through Group Policies: Active Directory allows administrators to enforce security policies and configurations across the network using Group Policies. This ensures consistency in security settings for users and computers, reducing the risk of vulnerabilities and unauthorized access.

Single Sign-On (SSO): With Active Directory, users can often benefit from Single Sign-On, meaning they only need to log in once to access various resources within the network. This improves user experience and reduces the burden of managing multiple passwords.

Resource Organization with OUs: Active Directory's Organizational Units (OUs) enable organizations to structure and organize resources in a way that reflects their business or operational requirements. This makes it easier to apply policies, delegate administrative tasks, and manage resources efficiently.

Scalability and Redundancy: AD supports the deployment of multiple domain controllers, providing scalability and redundancy. This ensures that even if one domain controller fails, others can continue to authenticate users and provide access to resources, contributing to high availability.

Integration with Other Microsoft Services: Active Directory integrates seamlessly with various Microsoft services and products, such as Exchange Server, SharePoint, and Microsoft 365. This integration streamlines user management and access to these services.

Audit and Compliance: Active Directory offers tools for auditing and monitoring changes to the directory service. This is crucial for maintaining compliance with regulatory requirements and internal security policies.

Collaboration and Productivity: Through integration with Microsoft collaboration tools like SharePoint and Exchange, Active Directory facilitates collaboration among users. It provides a foundation for creating shared resources, managing email accounts, and supporting collaborative workflows.

Support for Hybrid and Cloud Environments: As organizations increasingly adopt hybrid or cloud-based IT infrastructures, Active Directory plays a role in extending identity and access management to these environments. Services like Azure Active Directory provide integration with cloud services.

In summary, Active Directory is a fundamental component for managing and securing Windows-based network environments. Its features contribute to efficient administration, enhanced security, and improved user productivity, making it a crucial consideration for organizations of all sizes.


## Exploit tools
| Tool | Description |
| --- | --- |
| https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1 https://github.com/dmchell/SharpView | A PowerShell tool and a .NET port of the same used to gain situational awareness in AD. These tools can be used as replacements for various Windows net* commands and more. PowerView and SharpView can help us gather much of the data that BloodHound does, but it requires more work to make meaningful relationships among all of the data points. These tools are great for checking what additional access we may have with a new set of credentials, targeting specific users or computers, or finding some "quick wins" such as users that can be attacked via Kerberoasting or ASREPRoasting. |
|★ https://github.com/BloodHoundAD/BloodHound | Used to visually map out AD relationships and help plan attack paths that may otherwise go unnoticed. Uses the https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors PowerShell or C# ingestor to gather data to later be imported into the BloodHound JavaScript (Electron) application with a https://neo4j.com/ database for graphical analysis of the AD environment. |
| https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors | The C# data collector to gather information from Active Directory about varying AD objects such as users, groups, computers, ACLs, GPOs, user and computer attributes, user sessions, and more. The tool produces JSON files which can then be ingested into the BloodHound GUI tool for analysis. |
| https://github.com/fox-it/BloodHound.py | A Python-based BloodHound ingestor based on the https://github.com/CoreSecurity/impacket/. It supports most BloodHound collection methods and can be run from a non-domain joined attack host. The output can be ingested into the BloodHound GUI for analysis. |
|★ https://github.com/ropnop/kerbrute | A tool written in Go that uses Kerberos Pre-Authentication to enumerate Active Directory accounts, perform password spraying, and brute-forcing. |
| https://github.com/SecureAuthCorp/impacket | A collection of tools written in Python for interacting with network protocols. The suite of tools contains various scripts for enumerating and attacking Active Directory. |
|★ https://github.com/lgandx/Responder | Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions. |
| https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1 | Similar to Responder, a PowerShell tool for performing various network spoofing and poisoning attacks. |
| https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh | The C# version of Inveigh with a semi-interactive console for interacting with captured data such as username and password hashes. |
| https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rpcinfo | The rpcinfo utility is used to query the status of an RPC program or enumerate the list of available RPC services on a remote host. The "-p" option is used to specify the target host. For example the command "rpcinfo -p 10.0.0.1" will return a list of all the RPC services available on the remote host, along with their program number, version number, and protocol. Note that this command must be run with sufficient privileges. |
| https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html | A part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote RPC service. |
| https://github.com/byt3bl33d3r/CrackMapExec | CME is an enumeration, attack, and post-exploitation toolkit which can help us greatly in enumeration and performing attacks with the data we gather. CME attempts to "live off the land" and abuse built-in AD features and protocols like SMB, WMI, WinRM, and MSSQL. |
| https://github.com/GhostPack/Rubeus | Rubeus is a C# tool built for Kerberos Abuse. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py | Another Impacket module geared towards finding Service Principal names tied to normal users. |
| https://hashcat.net/hashcat/ | A great hash cracking and password recovery tool. |
| https://github.com/CiscoCXSecurity/enum4linux | A tool for enumerating information from Windows and Samba systems. |
| https://github.com/cddmp/enum4linux-ng | A rework of the original Enum4linux tool that works a bit differently. |
| https://linux.die.net/man/1/ldapsearch | Built-in interface for interacting with the LDAP protocol. |
| https://github.com/ropnop/windapsearch | A Python script used to enumerate AD users, groups, and computers using LDAP queries. Useful for automating custom LDAP queries. |
| https://github.com/dafthack/DomainPasswordSpray | DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. |
| https://github.com/leoloobeek/LAPSToolkit | The toolkit includes functions written in PowerShell that leverage PowerView to audit and attack Active Directory environments that have deployed Microsoft's Local Administrator Password Solution (LAPS). |
| https://github.com/ShawnDEvans/smbmap | SMB share enumeration across a domain. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py | Part of the Impacket toolkit, it provides us with Psexec-like functionality in the form of a semi-interactive shell. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py | Part of the Impacket toolkit, it provides the capability of command execution over WMI. |
| https://github.com/SnaffCon/Snaffler | Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py | Simple SMB server execution for interaction with Windows hosts. Easy way to transfer files within a network. |
| https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11) | Adds, reads, modifies and deletes the Service Principal Names (SPN) directory property for an Active Directory service account. |
|★ https://github.com/ParrotSec/mimikatz | Performs many functions. Notably, pass-the-hash attacks, extracting plaintext passwords, and Kerberos ticket extraction from memory on a host. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py | Remotely dump SAM and LSA secrets from a host. |
| https://github.com/Hackplayers/evil-winrm | Provides us with an interactive shell on a host over the WinRM protocol. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py | Part of the Impacket toolkit, it provides the ability to interact with MSSQL databases. |
| https://github.com/Ridter/noPac | Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py | Part of the Impacket toolset, RPC endpoint mapper. |
| https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py | Printnightmare PoC in python. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py | Part of the Impacket toolset, it performs SMB relay attacks. |
| https://github.com/topotam/PetitPotam | PoC tool for CVE-2021-36942 to coerce Windows hosts to authenticate to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions. |
| https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py | Tool for manipulating certificates and TGTs. |
| https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py | This tool will use an existing TGT to request a PAC for the current user using U2U. |
| https://github.com/dirkjanm/adidnsdump | A tool for enumerating and dumping DNS records from a domain. Similar to performing a DNS Zone transfer. |
| https://github.com/t0thkr1s/gpp-decrypt | Extracts usernames and passwords from Group Policy preferences files. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py | Part of the Impacket toolkit. Used to perform the ASREPRoasting attack to list and obtain AS-REP hashes for users with the 'Do not require Kerberos preauthentication' set. These hashes are then fed into a tool such as Hashcat for attempts at offline password cracking. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py | SID bruteforcing tool. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py | A tool for creation and customization of TGT/TGS tickets. It can be used for Golden Ticket creation, child to parent trust attacks, etc. |
| https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py | Part of the Impacket toolkit, It is a tool for automated child to parent domain privilege escalation. |
| https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer | Active Directory Explorer (AD Explorer) is an AD viewer and editor. It can be used to navigate an AD database and view object properties and attributes. It can also be used to save a snapshot of an AD database for offline analysis. When an AD snapshot is loaded, it can be explored as a live version of the database. It can also be used to compare two AD database snapshots to see changes in objects, attributes, and security permissions. |
| https://www.pingcastle.com/documentation/ | Used for auditing the security level of an AD environment based on a risk assessment and maturity framework (based on https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration adapted to AD security). |
| https://github.com/Group3r/Group3r | Group3r is useful for auditing and finding security misconfigurations in AD Group Policy Objects (GPO). |
| https://github.com/adrecon/ADRecon | A tool used to extract various data from a target AD environment. The data can be output in Microsoft Excel format with summary views and analysis to assist with analysis and paint a picture of the environment's overall security state. |

## Starting Responder
Responder is a powerful tool used for network analysis and penetration testing, particularly for conducting attacks like LLMNR (Link-Local Multicast Name Resolution) and NBT-NS (NetBIOS Name Service) poisoning. Here's a basic guide on how to start Responder on a Linux system:

Install Responder:
Before you start, make sure you have Responder installed on your Linux machine. You can typically install it using a package manager such as apt or yum. For example:

```bash
sudo apt-get update
sudo apt-get install responder
```

Note: Responder is often included in penetration testing distributions like Kali Linux.

Choose a Network Interface:
Determine the network interface that is connected to the target network. You can use the ifconfig command to list your network interfaces. For example:

```bash
ifconfig
```

Identify the interface you want to use (e.g., eth0).

Start Responder:
Open a terminal and run Responder with the chosen network interface. For example:

```bash
sudo responder -I eth0
```

Replace eth0 with the appropriate network interface.

Monitor Output:
Once Responder is running, it will start capturing and analyzing network traffic. You'll see output indicating the different protocols and services it's listening for.

Monitor the output for any captured credentials or hashes. Responder is designed to respond to certain network requests and capture authentication information.

Perform LLMNR/NBT-NS Poisoning:
Responder primarily works by poisoning LLMNR and NBT-NS requests. When a Windows system on the network tries to resolve a hostname, Responder responds with a spoofed answer, potentially capturing authentication credentials.

Keep in mind that using Responder for any unauthorized activities is illegal and unethical. Only use Responder on systems and networks for which you have explicit permission.

Cleanup:
When you're done with your testing, remember to clean up and stop Responder. You can typically do this by pressing Ctrl+C in the terminal where Responder is running.

Always ensure that you have the legal right and authorization to use tools like Responder on any network. Unauthorized use can lead to serious consequences. Responder and similar tools should only be used in controlled, ethical, and authorized testing environments, such as during penetration tests or security assessments.


## LLMNR/NBT-NS Poisoning - from Linux
Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) poisoning are types of attacks that exploit weaknesses in the way Windows systems resolve hostnames. These attacks are often used to perform man-in-the-middle (MitM) attacks or gather information about a target network. Here's an overview of each and how they might be carried out from a Linux environment:

LLMNR Poisoning:

LLMNR is a protocol used in Windows environments to resolve the names of neighboring computers without the use of a DNS server. LLMNR poisoning involves responding to LLMNR requests with malicious responses in order to redirect traffic or capture sensitive information.

To perform LLMNR poisoning from a Linux machine, tools like Responder or Inveigh can be used. These tools listen for LLMNR requests on the network and respond with spoofed answers. Here's a basic example using Responder:

```bash
sudo python Responder.py -I eth0
```

Replace eth0 with the appropriate network interface. When a Windows machine on the same network sends an LLMNR request, the tool responds with a spoofed answer, potentially redirecting the target to an attacker-controlled system.

NBT-NS Poisoning:

NetBIOS Name Service (NBT-NS) is an older protocol that resolves NetBIOS names to IP addresses. Like LLMNR poisoning, NBT-NS poisoning involves responding to NetBIOS requests with malicious responses.

Tools such as NBNSpoof from the dsniff package can be used for NBT-NS poisoning. Here's a basic example:

```bash
sudo arpspoof -i eth0 -t <target_ip> <gateway_ip>
sudo NBNSpoof -i eth0
```

This example combines ARP spoofing with NBT-NS poisoning. The ARP spoofing redirects traffic through the attacker's machine, and NBNSpoof responds to NBT-NS queries.

It's important to note that these activities could be considered unethical or illegal if performed without proper authorization. Ethical hacking and penetration testing should always be conducted within the bounds of the law and with explicit permission from the network owner.

Additionally, modern Windows environments may have defenses against these types of attacks, such as SMB signing and the use of secure protocols. Always ensure that you have permission to perform any security testing, and be aware of the potential legal consequences.

## Enumerating the Password Policy - from Linux - Credentialed
Enumerating the password policy of a Windows domain from a Linux machine, especially in a credentialed manner, involves querying Active Directory for information about the domain's password policies. This typically requires a tool that can interact with the LDAP service on the domain controller. One such tool is ldapsearch. Here's a basic guide:

Install LDAP Utilities:
Ensure that you have the LDAP utilities installed on your Linux machine. On Debian-based systems (like Ubuntu), you can install it using:

```bash
sudo apt-get install ldap-utils
```

On Red Hat-based systems (like CentOS), you might use:

```bash
sudo yum install openldap-clients
```

Query Active Directory for Password Policy:
Use ldapsearch to query the Active Directory LDAP service for password policy information. You'll need a valid username and password with sufficient permissions to perform the query. Adjust the following command with your domain details:

```bash
ldapsearch -x -H ldap://<domain_controller_ip> -D "DOMAIN\\username" -W -b "CN=Default Domain Policy,CN=Password Settings Container,CN=System,DC=domain,DC=com" "(objectClass=*)"
```

Replace the following placeholders:

```
<domain_controller_ip>: IP address of your domain controller.
DOMAIN: Your Active Directory domain name.
username: A valid username with sufficient permissions.
DC=domain,DC=com: Your Active Directory domain components.
```

You'll be prompted to enter the password for the specified user (-W flag).

Interpret the Results:
The output will contain information about the password policy settings. Look for attributes like maxPwdAge, minPwdLength, lockoutDuration, etc. These values represent settings such as the maximum password age, minimum password length, and lockout duration.

Here's an example of how part of the output might look:

```
maxPwdAge: -864000000000
minPwdLength: 7
lockoutDuration: -18000000000
```

These values are in 100-nanosecond intervals. You might need to convert them to a more human-readable format.

Remember to replace the placeholder values with the appropriate information for your Active Directory environment. Additionally, ensure that you have the necessary permissions to query Active Directory, and always follow ethical guidelines and legal requirements when performing any kind of security testing or enumeration.


## Password Spraying - Making a Target User List
## Detailed User Enumeration
User enumeration is a critical phase in penetration testing and security assessments, as it helps identify valid usernames on a target system. Enumerating users is often the first step in attempting to gain unauthorized access to a system. Here are various techniques and tools for detailed user enumeration:

LDAP Enumeration:

Use tools like ldapsearch to query LDAP directories. For example:

```bash
ldapsearch -x -h <target_IP> -D "cn=admin,dc=example,dc=com" -W -b "dc=example,dc=com" "(objectClass=user)"
```

Replace <target_IP> and LDAP credentials with appropriate values.
Nmap Scripting Engine (NSE):

Utilize Nmap with the NSE scripts designed for user enumeration. For example:

```bash
nmap -p 139,445 --script smb-enum-users --script-args smbuser=<username>,smbpass=<password> <target_IP>
```

Replace <username> and <password> with valid credentials.
RPCClient:

Use rpcclient to enumerate users from a Windows system:

```bash
rpcclient -U "" <target_IP>
enumdomusers
```

Enum4Linux:
Enum4Linux is a tool designed specifically for enumerating information from Windows and Samba systems.

```bash
enum4linux -a <target_IP>
```
    
CrackMapExec (CME):
CrackMapExec is a powerful post-exploitation tool that includes user enumeration capabilities.

```bash
crackmapexec smb <target_IP> -u <username> -p <password> --shares
```

Replace <username> and <password> with valid credentials.

PowerShell Scripts:

PowerShell can be used for user enumeration on Windows systems.

```powershell
Get-NetUser | Select-Object SamAccountName
```

Kerbrute:
Kerbrute is a tool for Kerberos-based attacks and includes user enumeration.

```bash
kerbrute userenum --dc <target_IP> -d <domain_name> <user_file>
```
    
Replace <domain_name> and <user_file> with appropriate values.
SMTP User Enumeration:

Enumerate users through SMTP using tools like smtp-user-enum or smtp-user-enum.pl.

```bash
smtp-user-enum -M VRFY -U /path/to/userlist.txt -t <target_IP>
```

Replace <target_IP> and provide a list of usernames in userlist.txt.
HTTP User Enumeration:

Enumerate users through HTTP using tools like Burp Suite or custom scripts.
Use Burp Suite's Intruder with a username list and check for different responses.
Custom scripts can be created to brute-force user enumeration through login pages.
SNMP Enumeration:

Use SNMP enumeration tools like snmpwalk to gather information about users.

```bash
snmpwalk -v 2c -c public <target_IP> 1.3.6.1.2.1.25.1.5.0
```
    
## SMB NULL Session to Pull User List
Exploiting SMB (Server Message Block) NULL sessions for user enumeration was a common technique in the past. However, modern Windows systems are configured to be more secure by default, and NULL sessions are often disabled due to security concerns. Additionally, NULL sessions can be easily detected and logged by security monitoring tools.

If you're in a controlled and authorized testing environment where NULL sessions are allowed or you have the necessary permissions, you can attempt to pull user information using the rpcclient tool in a Linux environment. Keep in mind that exploiting NULL sessions on unowned or unauthorized systems is illegal and unethical.

Here's a basic example using rpcclient:

Install rpcclient:
Ensure that rpcclient is installed on your Linux machine. It's part of the Samba suite, which is commonly included in many Linux distributions. If it's not installed, you can typically install it using your package manager.

For example, on Debian-based systems (e.g., Ubuntu):

```bash
sudo apt-get install smbclient
```

Attempt to Connect with NULL Session:
Use rpcclient to connect to the target system with a NULL session:

```bash
rpcclient -U "" -N -c "enumdomusers" <target_IP>
```

Replace <target_IP> with the IP address of the target system.

-U "": Specifies an empty username.
-N: Indicates a NULL session.
Review the Output:
If the target system allows NULL sessions, rpcclient will attempt to enumerate domain users. The output will display a list of user accounts.

```
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[user1] rid:[0x450]
```
    

This output provides a list of users along with their RIDs (Relative Identifiers).

Remember:

Always ensure that you have explicit authorization to perform security testing or penetration testing on the target system.
NULL sessions can be considered a security risk and are typically disabled in secure environments.
Unauthorized access or testing can lead to legal consequences.
Modern Windows systems often have additional security measures in place, such as SMB signing and other protections, which may prevent successful exploitation of NULL sessions. Always follow ethical hacking practices and conduct security assessments responsibly.
    
## Kerbrute User Enumeration
Kerbrute is a tool designed for Kerberos-based attacks, and it includes a user enumeration module that can be used to identify valid usernames on a target Active Directory domain. Here's a basic guide on using Kerbrute for user enumeration:

Install Kerbrute:
First, you need to install Kerbrute on your Linux machine. You can download the binary from the official GitHub repository: https://github.com/ropnop/kerbrute

Make the binary executable and move it to a directory in your system's PATH. For example:

```bash
chmod +x kerbrute_linux_amd64
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

Replace kerbrute_linux_amd64 with the appropriate binary for your system.

Run Kerbrute User Enumeration:
Use Kerbrute to enumerate users on the target Active Directory domain. You'll need to provide the domain name and a file containing a list of usernames.

```bash
kerbrute userenum --dc <target_IP> -d <domain_name> <user_file>
```

<target_IP>: The IP address of the domain controller.
<domain_name>: The name of the Active Directory domain.
<user_file>: A file containing a list of usernames to enumerate.
Review Output:
Kerbrute will attempt to enumerate users on the target domain using Kerberos. The output will display information about successful enumerations.

Example output snippet:

```
[+] Valid User: administrator
[+] Valid User: john.doe
[+] Valid User: alice.smith
```

The tool will list the usernames that have been successfully enumerated on the target Active Directory domain.

Remember:

Always ensure that you have explicit authorization to perform security testing or penetration testing on the target system.
User enumeration can have legal consequences and should only be performed on systems for which you have permission.
Be responsible and follow ethical hacking practices.
Kerbrute is a powerful tool, and it's important to use it responsibly and in accordance with the law. Additionally, Kerbrute can be used for various Kerberos-based attacks beyond user enumeration, so be sure to familiarize yourself with its documentation for a complete understanding of its capabilities.