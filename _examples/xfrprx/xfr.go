package main

import (
        "os"
	"dns"
        "net"
        "fmt"
)

func handleNotify(d *dns.Conn, i *dns.Msg) {
        if i.IsNotify() {
                fmt.Printf("Notify seen\n")
                q := new(dns.Msg)
                q.SetReply(i)
                answer, ok := q.Pack()
                if !ok {
                        return
                }
                d.Write(answer)
                doXfr(i)
        }
}

func doXfr(i *dns.Msg) ([]dns.RR, os.Error) {
        q := new(dns.Msg)
        q.SetAxfr(i.Question[0].Name)

        m := make(chan dns.Xfr)
        fmt.Printf("Preparing Xfr for %s\n", i.Question[0].Name)

        // Fill and setup the dns.Conn.
        d := new(dns.Conn)
        c, err := net.Dial("tcp", "", "127.0.0.1:53")
        if err != nil {
                return nil, err
        }
        fmt.Printf("Calling 127.0.0.1 successful\n")
        d.TCP = c.(*net.TCPConn)
        d.Addr = d.TCP.RemoteAddr()
        go d.XfrRead(q, m)
        for x := range m {
                fmt.Printf("%v %v\n", x.Add, x.RR)
        }
        return nil, nil
}
