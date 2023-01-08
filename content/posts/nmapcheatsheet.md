---
title: "nmap cheat sheet"
date: "2023-01-08"
draft: "false"
---

# Nmap cheat sheet

```jsx
$ nmap <scan types> <options> <target>
```

`-sn`Disables port scanning.

`-oA tnet`Stores the results in all formats starting with the name 'tnet'.

`-iL`Performs defined scans against targets in provided 'hosts.lst' list.

| -PE | Performs the ping scan by using 'ICMP Echo requests' against the target. |
| --- | --- |
| --packet-trace | Shows all packets sent and received |

`--reason`Displays the reason for specific result.
`--top-ports=10`Scans the specified top ports that have been defined as most frequent.

| -p 21 | Scans only the specified port. |
| --- | --- |
| --packet-trace | Shows all packets sent and received. |
| -n | Disables DNS resolution. |
| --disable-arp-ping | Disables ARP ping. |

`-Pn`Disables ICMP Echo requests.

| -F | Scans top 100 ports. |
| --- | --- |
| -sU | Performs a UDP scan. |

`-sV`Performs a service scan.

`xsltproc target.xml -o target.html`

`-p-`Scans all ports.

`--stats-every=5s`Shows the progress of the scan every 5 seconds.

`--script banner,smtp-commands`Uses specified NSE scripts.

`-A`Performs service detection, OS detection, traceroute and uses defaults scripts to scan the target.

| -sV | Performs service version detection on specified ports. |
| --- | --- |
| --script vuln | Uses all related scripts from specified category. |

`-sS` SYN scan

| -sS | Performs SYN scan on specified ports. |
| --- | --- |
| -Pn | Disables ICMP Echo requests. |
| -n | Disables DNS resolution. |
| --disable-arp-ping | Disables ARP ping. |
| --packet-trace | Shows all packets sent and received. |
| -D RND:5 | Generates five random IP addresses that indicates the source IP the connection comes from. |

| -O | Performs operation system detection scan. |
| --- | --- |
| -S | Scans the target by using different source IP address. |
| 10.129.2.200 | Specifies the source IP address. |
| -e tun0 | Sends all requests through the specified interface. |