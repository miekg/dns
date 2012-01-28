package main

import (
	"dns"
	"flag"
	"fmt"
	"os"
	"strconv"
)

func q(w dns.RequestWriter, m *dns.Msg) {
	w.Send(m)
	r, err := w.Receive()
	if err != nil {
		fmt.Printf("%s\n", err.Error())
	}
	w.Write(r)
}

func main() {
	port := flag.Int("port", 53, "port number to use")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [-port 53] [@server]\n", os.Args[0])
		flag.PrintDefaults()
	}

	conf, _ := dns.ClientConfigFromFile("/etc/resolv.conf")
	nameserver := "@" + conf.Servers[0]
	flag.Parse()

	for i := 0; i < flag.NArg(); i++ {
		// If it starts with @ it is a nameserver
		if flag.Arg(i)[0] == '@' {
			nameserver = flag.Arg(i)
			break
		}
	}
	nameserver = string([]byte(nameserver)[1:]) // chop off @
	nameserver += ":" + strconv.Itoa(*port)
	c := dns.NewClient()
        prints, _ := fingerPrintFromFile("data/q")
	for _, f := range prints {
		f1 := probe(c, nameserver, f)
		println(f.String(), f1.String())
	}
}
