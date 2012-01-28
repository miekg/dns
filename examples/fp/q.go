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
	report := flag.Bool("report", false, "show fingerprint for (yet) unknown server")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS...] [@server]\n", os.Args[0])
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
	results := make([]*fingerprint, 0)
        if *report {
                fmt.Printf("# Fingerprint of <Nameserver> <version>\n# Supplied by <Name> on <Date>\n#\n")
        }
	for _, f := range prints {
		f1 := probe(c, nameserver, f)
		results = append(results, f1)
		if *report {
			fmt.Printf("%s\n", f1.String())
		}
	}
	if *report {
		return
	}

	// For now, just list them:
	files := []string{"data/Bind9", "data/Nsd3"}
        fmt.Printf("%s\t%s\t%s\t\t\t\t\t\t\t\t%s\n", "Server type", "Diffs", "Received", "Sent")
	for _, file := range files {
                diff := 0
		prints, _ := fingerPrintFromFile(file)
		for i, f := range prints {
			d := f.compare(results[i])
                        diff += d
                        fmt.Printf("%s\t%d\t%s %s\n", file, d, f.String(), results[i].String())
		}
                fmt.Printf("\t\t==\nDifferences:\t%d\n\n", diff)
	}
}
