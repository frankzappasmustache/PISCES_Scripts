## **KQL Query to remove all suricata specific signatures:**

```
NOT suricata.eve.alert.signature:SURICATA\*
```

## **KQL Query to show only internal traffic:**

```
source.address:(172.16.\* OR 192.168.\* OR 10.\*)
```

## **KQL Query to show only external traffic:**

```
NOT source.address:(10.\* OR 172.16.\* OR 192.168.\*)
```

## **KQL Query to show netflow view into large uploads, SYN-scan, null scans, and unusually high port traffic to foreign countries:**

```
suricata.eve.event_type:"flow" AND NOT destination.address:(172.16.\* OR 192.168.\* OR 10.\*) AND ( 
  suricata.eve.flow.bytes_toserver > 1000000 
  OR ( 
    suricata.eve.flow.pkts_toserver < 3  
    AND suricata.eve.flow.protocol:"TCP"
    ) 
  OR tcp.tcp_flags:0x00
  OR (
    suricata.eve.flow.dest_port > 1024  
    AND NOT destination.geo.country:"US"
    )
    ) 
```

## **Base Filter for Netflow Logs:**

```
suricata.eve.event_type:flow
``` 

## **High Uploads (Potential Exfil):**

```
suricata.eve.event_type:flow AND suricata.eve.flow.bytes_toserver > 10000000
```

## **Small Connections (Potential Scanning):**

```
suricata.eve.event_type:flow AND suricata.eve.flow.pkts_toserver < 3
```

## **Flows that triggered Alerts:**

```
suricata.eve.event_type:flow AND suricata.eve.flow.alerted: true
```

## **Long Duration Connections:**

```
suricata.eve.event_type:flow AND suricata.eve.flow.age > 3600
```

## **Timed Out Flows:**

```
suricata.eve.event_type:flow AND suricata.eve.flow.reason: "timeout"
```

## **Base Filter for DNS Logs:**

```
suricata.eve.event_type:dns
```

## **Suspicious Top Level Domain (TLD) Super-Filter:**

```
suricata.eve.event_type:dns AND 

suricata.eve.dns.rrname: ( 

  \*.xyz or \*.top or \*.gq or \*.tk or \*.ml or \*.cf or 

  \*.club or \*.online or \*.site or \*.store or \*.click or 

  \*.work or \*.cam or \*.bid or \*.men or \*.loan or 

  \*.trade or \*.space or \*.win or \*.buzz or \*.press or 

  \*.cn or \*.ru or \*.su or \*.by or \*.ir or \*.kp or 

  \*.zip or \*.mov 

)
```

## **Dynamic DNS Providers:**

```
suricata.eve.event_type:dns AND suricata.eve.dns.rrname: (\*.duckdns.org or \*.no-ip.com or \*.dyn.\*)
```

## **External DNS Resolvers:**

```
suricata.eve.event_type:dns AND NOT destination.address: ("10.\*" or "172.16.\*" or "192.168.\*")
```

## **Queries with Long Subdomains (Domain Generation Algorithms or Exfil):**

```
suricata.eve.event_type:dns AND Suricata.eve.dns.rrname: \*.\*.\*.\*
```

## **Alerts with malicious or suspicious content minus false positives:**

```
suricata.eve.alert.signature:\* AND suricata.eve.alert.signature : ("\*MALWARE\*" OR "\*TROJAN\*" OR "\*VIRUS\*" OR "\*BACKDOOR\*" OR "\*BOTNET\*" OR "\*EXPLOIT\*" OR "\*SHELLCODE\*" OR "\*INJECTION\*" OR "\*C2\*" OR "\*COMMAND AND CONTROL\*" OR "\*METERPRETER\*" OR "\*EMOTET\*" OR "\*QAKBOT\*" OR "\*TRICKBOT\*" OR "\*ICEDID\*" OR "\*DRIDEX\*" OR "\*AGENT TESLA\*" OR "\*RAT\*" OR "\*REMOTE ACCESS\*" OR "\*REVERSE SHELL\*" OR "\*EXECUTION\*" OR "\*DLL INJECTION\*") AND NOT suricata.eve.alert.signature:(SURICATA\* OR "ET MALWARE Windows qwinsta Microsoft Windows DOS prompt command exit OUTBOUND" OR "ET INFO EXE IsDebuggerPresent (Used in Malware Anti-Debugging)")
```
