# Suricata
A rule/signature consists of the following:

*  The action, determining what happens when the rule    matches.

*  The header, defining the protocol, IP addresses, ports and direction of the rule.

*  The rule options, defining the specifics of the rule.

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```
* alert -- action
* http $HOME_NET any -> $EXTERNAL_NET any -- header
* The rest defines the rule options

Valid actions are:

* alert - generate an alert.

* pass - stop further inspection of the packet.

* drop - drop packet and generate alert.

* reject - send RST/ICMP unreach error to the sender of the matching packet.

* rejectsrc - same as just reject.

* rejectdst - send RST/ICMP error packet to receiver of the matching packet.

* rejectboth - send RST/ICMP error packets to both sides of the conversation.

The protocol value will limit what protocol(s) the signature will be applied to:

* ip (ip stands for 'all IP packets' or 'any IP packet')

* tcp (for TCP traffic)

* udp

* icmp (both ICMPv4 and ICMPv6)

* icmpv4

* icmpv6

* ipv4/ip4 - just IPv4

* ipv6/ip6 - just IPv6

* pkthdr (for matching on packets with decoder events)

* ether - Ethernet packets

* arp - ARP packets specifically

## Testing ICMP on Suricata

With Suricata already installed, check suricata status:

```
systemctl status suricata.services
```
the command may require adminstrative priviledges. In kali this achieved by using sudo before the command.

To start suricata:
```
sudo systemctl start suricata.services
```

Suricata's yaml/configuration accessed by: 
```
sudo nano /etc/suricata/suricata.yaml
```

The file should have the following configurations:

* $HOME_NET - set to the network the devices are in.
* af-packet - set the interface to the interface within the states network in $HOME_NET. confirm it by:

```
ip a
```
Suricata has a file with configured rules. To configure your file in the yaml file:

At rule.files change the suricata.rules files to your file.
Copy this path:
/var/lib/suricata/rules

Save the configurations by: ctrl+o then ctrl+x to exit.

Edit the rule file you specified:
```
sudo nano /var/lib/suricata/rules/filename.rules
```

Add the rule below:
```
alert icmp any any -> any any (msg:"ALERT ALERT ICMP FLOOD SEEMS TO BE DETECTED"; sid: 10000;)
```

Save and exit.

Run the command below to check for any syntax error in the rule created: 
```
sudo suricata -T -c  /etc/suricata/suricata.yaml -v
```
To view the logs run: 
```
 sudo tail -f /var/log/suricata/fast.log
 ```

To simulate a ping flood, use another different terminal to run:
```
sudo hping3 -1 -i u5000 -c 100 target-IP
```

The logs in fast.log will be as shown:

![ping flood log](./image/Screenshot%20From%202026-05-09%2013-47-51.png)

Suricata here is being used as an IDS.

## Port Scan Detection

Add the rule in your rules file:
```
alert tcp any any -> $HOME_NET any \
(msg:"PORT SCAN DETECTED"; flags:S; \
detection_filter:track by_src, count 20, seconds 5; \
classtype:attempted-recon; sid:10002; rev:1;)
```
Run scan:

```
nmap -sS target-ip
```

Check to logs:

```
sudo tail -f /var/log/suricata/fast.log
```

## Suspicious HTTP Access
The rule to be added:

```
alert http any any -> $HOME_NET any \
(msg:"SUSPICIOUS HTTP REQUEST"; content:"/admin"; http_uri; \
classtype:web-application-attack; sid:10003; rev:1;)
```
Simulate the attack:
```
curl http-url
```

Check the fast.log file for logs.

One can also use:
```
sudo tail -f /var/log/suricata/eve.json
```
For better json format logs.









