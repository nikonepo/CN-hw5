# CN-hw5

## Simple implementation raw socket firewall

Build:

```go build```

Run:

```./hw5 -iface1=<iface1_name> -iface2=<iface2_name>```

Example:

```./hw5 -iface1=eth0 -iface2=eth1```

## Rules

Rules are stored in `rules.json` file. 

Protocols ```ARP, STP, LLDP``` are always skipped.

- This example file contains 2 rules, that delete ICMP packets between 2 hosts:
```json
[
  {
    "Type": "delete",
    "SrcIp": "10.1.0.1",
    "DstIp": "10.1.0.2",
    "Protocol": "icmp"
  },
  {
    "Type": "delete",
    "SrcIp": "10.1.0.2",
    "DstIp": "10.1.0.1",
    "Protocol": "icmp"
  }
]
```

- This example file contains 1 rule, that skips TCP packets sent 
- from ```10.1.0.2:8080``` to ```10.1.0.1:8080``` with ```TTL <= 50```, the remaining packets will be deleted:
```json
[
  {
    "Type": "skip",
    "SrcIp": "10.1.0.2",
    "SrcPort": 8080,
    "DstIp": "10.1.0.1",
    "DstPort": 8080,
    "TTL": 50,
    "Protocol": "tcp"
  }
]
```


There are 2 types of rules:
- `delete` - delete packets that match the rule
- `skip` - skip packets that match the rule

**Protocol** can be one of the following:
- `icmp`
- `tcp`
- `udp`

**Port** can be only for `tcp` and `udp` protocols.
