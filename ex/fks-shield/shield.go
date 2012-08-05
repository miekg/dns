/* 
 * Funkensturm, a versatile DNS proxy
 * Miek Gieben <miek@miek.nl> (c) 2011
 * GPLv2
 */

package main

import (
	"dns"
	"flag"
	"log"
	"os/signal"
	"strings"
)

func doFunkenSturm(pkt *dns.Msg) (ret []byte) {
	// No matter what, we refuse to answer requests with the response bit set.
	if pkt.MsgHdr.Response == true {
		return nil
	}

	// Loop through the Funks and decide what to do with the packet.
	for _, f := range f.Funk {
		if m, ok := f.Match(pkt); ok {
			ret = f.Action(m)
			return
		}
	}
	if f.Default == nil {
		println("No f.Default set!")
		return
	}
	ret = f.Default(pkt)
	return
}

func serve(w dns.ResponseWriter, req *dns.Msg) {
	if out := doFunkenSturm(req); out != nil {
		w.Write(out)
	}
}

func listenAndServe(add, net string) {
	if err := dns.ListenAndServe(add, net, nil); err != nil {
		log.Printf("fks-shield: failed to setup:", net, add)
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8053", "set the listener address")
	server := flag.String("server", "127.0.0.1:53", "remote server address(es), seperate with commas")
	verbose = flag.Bool("verbose", false, "Print packet as it flows through")
	flag.Usage = func() {
		flag.PrintDefaults()
	}
	flag.Parse()

	clients := strings.Split(*server, ",")
	qr = make([]*FunkClient, len(clients))
	for i, ra := range clients {
		qr[i] = new(FunkClient)
		qr[i].Client = dns.NewClient()
		qr[i].Addr = ra
	}

	f = NewFunkenSturm()
	ok := f.Setup()
	if !ok {
		println("Setup failed")
		return
	}

	dns.HandleFunc(".", serve)
	go listenAndServe(*listen, "tcp")
	go listenAndServe(*listen, "udp")

	sig := make(chan os.Signal)

forever:
	for {
		select {
		case <-sig:
			log.Printf("fks-shield: signal received, stopping")
			break forever
		}
	}
}
