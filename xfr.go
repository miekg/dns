package dns

import (
        "net"
        )

// Outgoing AXFR and IXFR implementations

// Read from m until it is closed. Group the RRs until
// no space is left and send the messages.
// How do I know the message still fits in 64 K???
func AxfrTCP(c *net.TCPConn, a net.Addr, m chan Xfr) {
        msg := new(Msg)
        msg.Answer = make([]RR, 1000)
        i := 0
        var soa *RR_SOA
        for r := range m {
                msg.Answer[i] = r.RR
                if soa == nil {
                        if r.RR.Header().Rrtype != TypeSOA {
                                // helegaar geen SOA
                        } else {
                                soa = r.RR.(*RR_SOA)
                        }
                }
                i++
                if i > 1000 {
                        // send it
                        msg.Answer = msg.Answer[:0]
                        i = 0
                }
        }
        // Last one, what if was 1000 send lonely soa?? No matter
        // what, add the SOA and send the msg
        msg.Answer[i] = soa
        // send it
}
