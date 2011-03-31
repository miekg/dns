package main

import (
	"os"
	"dns"
	"fmt"
)

func handleXfrOut(d *dns.Conn, i *dns.Msg) os.Error {
	if i.IsAxfr() {
		fmt.Printf("Incoming Axfr request seen\n")
		if i.Question[0].Name == Zone.name {
			fmt.Printf("Matchies current zone\n")
                        if !Zone.correct {
                                fmt.Printf("Zone was not deemed correct\n")
                                if err := d.WriteMsg(i); err != nil {
                                        return err
                                }
                                return nil
                        } else {
                                fmt.Printf("Zone was correct\n")
                        }

			m := make(chan *dns.Xfr)
			e := make(chan os.Error)
			go d.XfrWrite(i, m, e)
			for j := 0; j < Zone.size; j++ {
				select {
				case m <- &dns.Xfr{Add: true, RR: Zone.rrs[j]}: //
				case err := <-e:
					return err
				}
			}
			close(m)
		} else {
                        fmt.Printf("No matching zone found\n")
                        if err := d.WriteMsg(i); err != nil {
                                return err
                        }
                }
	}
	return nil
}

func handleNotify(d *dns.Conn, i *dns.Msg) os.Error {
	if i.IsNotify() {
		fmt.Printf("Incoming notify seen\n")
		q := new(dns.Msg)
		q.SetReply(i)
		err := d.WriteMsg(q)
		if err != nil {
			return err
		}
		err = handleXfrIn(i)
                if err != nil {
                        return err
                }
	}
        return nil
}

func handleXfrIn(i *dns.Msg) os.Error {
	q := new(dns.Msg)
	q.SetAxfr(i.Question[0].Name)

	m := make(chan *dns.Xfr)
	fmt.Printf("Preparing Xfr for %s\n", i.Question[0].Name)

	d := new(dns.Conn)
	d.RemoteAddr = "127.0.0.1:53"
	err := d.Dial("tcp")
	if err != nil {
		return err
	}
	defer d.Close()

	fmt.Printf("Calling 127.0.0.1 successful\n")
	go d.XfrRead(q, m)

	Zone.name = i.Question[0].Name
	j := 0
	for x := range m {
		Zone.rrs[j] = x.RR
		j++
	}
        fmt.Printf("Success retrieved %s\n", Zone.name)
	Zone.size = j
	return nil
}

func handleNotifyOut(addr string) {
        if Zone.name == "" || !Zone.correct {
                return
        }
        d := new(dns.Conn)
        d.RemoteAddr = addr
        m := new(dns.Msg)
        m.SetNotify(Zone.name)
        fmt.Printf("Sending notifies: zone is ok\n")
        dns.QueryRequest <- &dns.Query{Conn: d, Query: m}
}
