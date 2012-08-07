package main

import (
	"dns"
	"strings"
	"time"
)

const (
	R_NONE  = 0 // Right to do nada
	R_LIST  = 1 // Right to list stuff
	R_WRITE = 2 // Right to write stuff
	R_DROP  = 4 // Right to drop stuff
	R_USER  = 8 // Right to add users
)

// fks config
type Config struct {
	Server *dns.Server	    // Server instance for this configuration
	Zones  map[string]*dns.Zone // All zones we are authoritative for
	Rights map[string]int       // Rights for all users
}

func NewConfig() *Config {
	c := new(Config)
	c.Zones = make(map[string]*dns.Zone)
	c.Rights = make(map[string]int)
	return c
}

func formerr(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.MsgHdr.Opcode = dns.OpcodeUpdate
	if req.IsTsig() {
		m.SetTsig(userFromTsig(req), dns.HmacMD5, 300, time.Now().Unix())
	}
	w.Write(m.SetRcode(req, dns.RcodeFormatError))
}

func noerr(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.MsgHdr.Opcode = dns.OpcodeUpdate
	m.SetTsig(userFromTsig(req), dns.HmacMD5, 300, time.Now().Unix())
	w.Write(m.SetReply(req))
}

func userFromTsig(req *dns.Msg) string {
	return req.Extra[len(req.Extra)-1].Header().Name
}

// Check if the user has any rights
func configRights(user string, c *Config) {

}

// config stuff in Auth section (just as dynamic updates (*hint* *hint*)
// SUBSYSTEM. IN TXT "OPERATION<SPACE>OPTIONS..."
// ZONE. IN TXT "READ origin /z/bloep" - absolute path in fs
func config(w dns.ResponseWriter, req *dns.Msg, c *Config) {
	logPrintf("config command")

	if !req.IsTsig() {
		logPrintf("non config command (no tsig)")
		formerr(w, req)
		return
	}

	if !req.IsUpdate() {
		logPrintf("non config command (no update)")
		formerr(w, req)
		return
	}

	if e := w.TsigStatus(); e != nil {
		logPrintf("non config command (tsig fail): %s", e.Error())
		formerr(w, req)
		return
	}

	// No need to check the user, if the tsig checks out, the user exists
	logPrintf("config command ok")

	for _, rr := range req.Ns {
		t, ok := rr.(*dns.RR_TXT)

		if !ok {
			formerr(w, req)
			return
		}
		switch strings.ToUpper(t.Header().Name) {
		case "ZONE.":
			if e := configZONE(w, req, t, c); e != nil {
				formerr(w, req)
				return
			}
		case "USER.":
			if userFromTsig(req) != dns.Fqdn(*superuser) {
				logPrintf("user management is only for the superuser\n")
				formerr(w, req)
				return
			}

			if e := configUSER(w, req, t, c); e != nil {
				formerr(w, req)
				return
			}
		default:
			formerr(w, req)
			return
		}
	}
}

// Deal with the zone options
func configZONE(w dns.ResponseWriter, req *dns.Msg, t *dns.RR_TXT, c *Config) error {
	sx := strings.Split(t.Txt[0], " ")
	if len(sx) == 0 {
		return nil
	}
	switch strings.ToUpper(sx[0]) {
	case "READ":
		if len(sx) != 3 {
			return nil
		}
		logPrintf("config READ %s %s\n", dns.Fqdn(sx[1]), sx[2])
		if e := c.ReadZoneFile(dns.Fqdn(sx[1]), sx[2]); e != nil {
			logPrintf("failed to read %s: %s\n", sx[2], e.Error())
			return e
		}
		logPrintf("config added: READ %s %s\n", dns.Fqdn(sx[1]), sx[2])
		noerr(w, req)
	case "READXFR":
		if len(sx) != 3 {
			return nil
		}
		logPrintf("config READXFR %s %s\n", dns.Fqdn(sx[1]), sx[2])
		if e := c.ReadZoneXfr(dns.Fqdn(sx[1]), sx[2]); e != nil {
			logPrintf("failed to axfr %s: %s\n", sx[2], e.Error())
			return e
		}
		logPrintf("config added: READXFR %s %s\n", dns.Fqdn(sx[1]), sx[2])
		noerr(w, req)
	case "DROP":
		if len(sx) != 2 {
			return nil
		}
		logPrintf("config DROP %s\n", dns.Fqdn(sx[1]))
		if e := c.DropZone(dns.Fqdn(sx[1])); e != nil {
			logPrintf("Failed to drop %s: %s\n", dns.Fqdn(sx[1]), e.Error())
			return e
		}
		logPrintf("config dropped: DROP %s\n", dns.Fqdn(sx[1]))
		noerr(w, req)
	case "LIST":
		logPrintf("config LIST\n")
		m := new(dns.Msg)
		m.SetReply(req)
		// Add the zones to the additional section
		for zone, _ := range c.Zones {
			a, _ := dns.NewRR("ZONE. TXT \"" + zone + "\"")
			m.Extra = append(m.Extra, a)
		}
		m.SetTsig(userFromTsig(req), dns.HmacMD5, 300, time.Now().Unix())
		w.Write(m)
	}
	return nil
}

// Deal with the user options
func configUSER(w dns.ResponseWriter, req *dns.Msg, t *dns.RR_TXT, c *Config) error {
	sx := strings.Split(t.Txt[0], " ")
	if len(sx) == 0 {
		return nil
	}
	switch strings.ToUpper(sx[0]) {
	case "ADD":
		if len(sx) != 3 {
			return nil
		}
		logPrintf("config ADD %s with %s\n", dns.Fqdn(sx[1]), sx[2])
		c.Server.TsigSecret[dns.Fqdn(sx[1])] = sx[2]
		c.Rights[dns.Fqdn(sx[1])] = R_NONE
		noerr(w, req)
	case "DROP":
		if len(sx) != 2 {
			return nil
		}
		logPrintf("config DROP %s\n", dns.Fqdn(sx[1]))
		delete(c.Server.TsigSecret, dns.Fqdn(sx[1]))
		delete(c.Rights, dns.Fqdn(sx[1]))
		noerr(w, req)
	case "LIST":
		for u, p := range c.Server.TsigSecret {
			logPrintf("config USER %s: %s\n", u, p)
		}
		fallthrough
	case "ADDPOWER":
		fallthrough
	case "DROPPOWER":
		noerr(w, req)
	}
	return nil
}
