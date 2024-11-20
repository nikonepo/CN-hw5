# CN-hw5

## Simple implementation raw socket firewall

Build:

```go build```

Run:

```./hw5 -iface1=<iface1_name> -iface2=<iface2_name>```

Example:

```./hw5 -iface1=eth0 -iface2=eth1```

## Rules

Rules are stored in `rules.json` file. Each rule is a line in the following format:
```json
[
  {
    "Type": "delete",
    "SrcIp": "10.1.0.1",
    "SrcPort": 8080,
    "DstIp": "10.1.0.2",
    "DstPort": 8080,
    "TTL": 50,
    "Protocol": "icmp"
  },
  {
    "Type": "delete",
    "SrcIp": "10.1.0.2",
    "SrcPort": 8080,
    "DstIp": "10.1.0.1",
    "DstPort": 8080,
    "TTL": 50,
    "Protocol": "icmp"
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
