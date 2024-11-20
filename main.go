package main

import (
    "encoding/binary"
    "encoding/json"
    "flag"
    "fmt"
    "golang.org/x/sys/unix"
    "net"
    "os"
)

type Rule struct {
    Type     string
    SrcIP    net.IP
    SrcPort  uint16
    DstIP    net.IP
    DstPort  uint16
    TTL      uint16
    Protocol string
}

type RuleJson struct {
    Type     string
    SrcIP    string
    SrcPort  uint16
    DstIP    string
    DstPort  uint16
    TTL      uint16
    Protocol string
}

const IPV4 = 0x0800

// skip protocols
const ARP = 0x0806
const STP = 0x0822

const TCP = 0x06
const UDP = 0x11
const ICMP = 0x01

func main() {
    iface1Name := flag.String("iface1", "eth0", "Interface 1")
    iface2Name := flag.String("iface2", "eth1", "Interface 2")
    fileName := flag.String("file", "rules.json", "File with rules")

    flag.Parse()

    rules := parseRules(fileName)
    lastRule := rules[len(rules)-1]
    rules = rules[:len(rules)-1]

    isWhite := lastRule.Type == "white"

    fmt.Printf("Creating sockets\n")
    fd1, _ := createSocket(iface1Name)
    fd2, _ := createSocket(iface2Name)

    defer unix.Close(fd1)
    defer unix.Close(fd2)

    fmt.Printf("Starting traffic\n")
    go handleTraffic(fd1, fd2, rules, isWhite)
    go handleTraffic(fd2, fd1, rules, isWhite)

    select {}
}

func parseRules(fileName *string) []Rule {
    file, err := os.ReadFile(*fileName)
    if err != nil {
        fmt.Printf("Failed to read file: %v\n", err)
        return make([]Rule, 0)
    }

    var rulesJson []RuleJson

    err = json.Unmarshal(file, &rulesJson)
    if err != nil {
        fmt.Printf("Failed to parse rules: %v\n", err)
        return make([]Rule, 0)
    }

    rules := make([]Rule, len(rulesJson))
    for i, ruleJson := range rulesJson {
        rules[i] = Rule{
            Type:     ruleJson.Type,
            SrcIP:    net.ParseIP(ruleJson.SrcIP),
            SrcPort:  ruleJson.SrcPort,
            DstIP:    net.ParseIP(ruleJson.DstIP),
            DstPort:  ruleJson.DstPort,
            TTL:      ruleJson.TTL,
            Protocol: ruleJson.Protocol,
        }
    }

    return rules
}

func createSocket(ifaceName *string) (int, error) {
    fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
    if err != nil {
        fmt.Printf("Failed to create socket: %v\n", err)
    }

    iface, _ := net.InterfaceByName(*ifaceName)

    addr := unix.SockaddrLinklayer{
        Protocol: htons(unix.ETH_P_ALL),
        Ifindex:  iface.Index,
    }

    err = unix.Bind(fd, &addr)
    if err != nil {
        fmt.Printf("Failed to bind to interface: %s %v", *ifaceName, err)
    }

    return fd, nil
}

func handleTraffic(srcFd, dstFr int, rules []Rule, isWhite bool) {
    for {
        fmt.Printf("Reading packet from %s to %s\n", srcFd, dstFr)
        buf := make([]byte, 1024)
        n, _, err := unix.Recvfrom(srcFd, buf, 0)
        if err != nil {
            fmt.Printf("Failed to read packet: %v\n", err)
            continue
        }

        if checkPacket(buf[:n], rules, isWhite) {
            _, err = unix.Write(dstFr, buf[:n])
            if err != nil {
                fmt.Printf("Failed to send packet: %v\n", err)
            }
        } else {
            fmt.Printf("Packet dropped\n")
        }
    }
}

func checkPacket(packet []byte, rules []Rule, isWhite bool) bool {
    // 12-13 bytes is ethernet type
    ethType := binary.BigEndian.Uint16(packet[12:14])

    // skip arp packet
    if ethType == ARP || ethType == STP {
        return true
    }

    // check IPV4 packet
    if ethType == IPV4 {
        ipHeader := packet[14:34]
        protocol := ipHeader[9]
        ttl := uint16(ipHeader[8])

        srcIP := net.IP(ipHeader[12:16])
        dstIP := net.IP(ipHeader[16:20])

        for _, rule := range rules {
            ruleProtocol := parseProtocol(&rule.Protocol)
            if ttl > 0 && ttl > rule.TTL && !isWhite {
                return isWhite
            }

            if (ruleProtocol == 0 || ruleProtocol == protocol) &&
                (rule.SrcIP == nil || rule.SrcIP.Equal(srcIP)) &&
                (rule.DstIP == nil || rule.DstIP.Equal(dstIP)) &&
                (ttl == 0 || ttl <= rule.TTL) {

                if protocol == UDP {
                    udpHeader := packet[34:42]
                    srcPort := binary.BigEndian.Uint16(udpHeader[0:2])
                    dstPort := binary.BigEndian.Uint16(udpHeader[2:4])

                    if (rule.SrcPort == 0 || rule.SrcPort == srcPort) &&
                        (rule.DstPort == 0 || rule.DstPort == dstPort) {
                        return isWhite
                    }
                } else if protocol == TCP {
                    tcpHeader := packet[34:54]
                    srcPort := binary.BigEndian.Uint16(tcpHeader[0:2])
                    dstPort := binary.BigEndian.Uint16(tcpHeader[2:4])

                    if (rule.SrcPort == 0 || rule.SrcPort == srcPort) &&
                        (rule.DstPort == 0 || rule.DstPort == dstPort) {
                        return isWhite
                    }
                } else {
                    return isWhite
                }
            }
        }

        return !isWhite
    }

    return true
}

func htons(value uint16) uint16 {
    return (value<<8)&0xff00 | (value>>8)&0x00ff
}

func parseProtocol(protocol *string) uint8 {
    if *protocol == "tcp" {
        return TCP
    } else if *protocol == "udp" {
        return UDP
    } else if *protocol == "icmp" {
        return ICMP
    }

    return 0
}
