package main

import (
	"dns"
	"strings"
)

// fks config
type Config struct {
	Zones map[string]*dns.Zone
}

func NewConfig() *Config {
	c := new(Config)
	c.Zones = make(map[string]*dns.Zone)
	return c
}

func config(w dns.ResponseWriter, req *dns.Msg, c *Config) {
	// Set question to fks. IN TXT otherwise error
	// tsig signed, key = user
	// config stuff in Auth section (just as dynamic updates (*hint* *hint*)
	// SUBSYSTEM. IN TXT "OPERATION<SPACE>OPTIONS..."
	// ZONE. IN TXT "READ origin /z/bloep" - absolute path in fs

	if !req.IsUpdate() {
		logPrintf("non config command")
		m := new(dns.Msg)
		w.Write(m.SetRcode(req, dns.RcodeFormatError))
		return
	}

	// TODO: check tsig
	logPrintf("config commmand")
	for _, rr := range req.Ns {
		t, ok := rr.(*dns.RR_TXT)

		if !ok {
			// Not the TXT record -> error
			return
		}
		switch strings.ToUpper(t.Header().Name) {
		case "ZONE.":
			configZONE(t, c)
		default:
			return
			// error back
		}
	}
}

// Deal with the zone options
func configZONE(t *dns.RR_TXT, c *Config) error {
	sx := strings.Split(t.Txt[0], " ")
	if len(sx) == 0 {
		return nil
	}
	switch strings.ToUpper(sx[0]) {
	case "READ":
		logPrintf("config: READ %s %s\n", dns.Fqdn(sx[1]), sx[2])
		if e := c.ReadZone(dns.Fqdn(sx[1]), sx[2]); e != nil {
			logPrintf("failed to read %s: %s\n", sx[2], e.Error())
			return e
		}
		return nil
	}
	return nil
}
