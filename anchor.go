package dns

import (
	"encoding/xml"
	"io"
	"time"
)

// Interally used for parsing from and to the XML
type XMLKeyDigest struct {
	Id         string `xml:"id,attr"`
	ValidFrom  string `xml:"validFrom,attr"`
	ValidUntil string `xml:"validUntil,attr,omitempty"`
	KeyTag     uint16 `xml:"KeyTag"`
	Algorithm  uint8  `xml:"Algorithm"`
	DigestType uint8  `xml:"DigestType"`
	Digest     string `xml:"Digest"`
}

// Interally used for parsing from and to the XML
type XMLTrustAnchor struct {
	Id        string          `xml:"id,attr,omitempty"`
	Source    string          `xml:"source,attr,omitempty"`
	Zone      string          `xml:"Zone"`
	KeyDigest []*XMLKeyDigest `xml:"KeyDigest"`
}

// A TrustAnchor represents the trust anchors used in the DNS root.
type TrustAnchor struct {
	Id         string    // TrustAnchor id attribute
	Source     string    // TrustAnchor source attribute
	AnchorId   string    // KeyDigest id 
	Anchor     *RR_DS    // The digest encoded as an DS record
	ValidFrom  time.Time // Validity specification
	ValidUntil time.Time // Validaty specification
}

// TrustAnchorString convert a TrustAnchor to a string encoded as XML.
func TrustAnchorString(t []*TrustAnchor) string {
	xta := new(XMLTrustAnchor)
	xta.KeyDigest = make([]*XMLKeyDigest, 0)
	for _, ta := range t {
		xta.Id = ta.Id // Sets the everytime, but that is OK.
		xta.Source = ta.Source
		xta.Zone = ta.Anchor.Hdr.Name
		xkd := new(XMLKeyDigest)
		xkd.Id = ta.AnchorId
		xkd.ValidFrom = ta.ValidFrom.Format("2006-01-02T15:04:05-07:00")
		if !ta.ValidUntil.IsZero() {
			xkd.ValidUntil = ta.ValidUntil.Format("2006-01-02T15:04:05-07:00")
		}
		xkd.KeyTag = ta.Anchor.KeyTag
		xkd.Algorithm = ta.Anchor.Algorithm
		xkd.DigestType = ta.Anchor.DigestType
		xkd.Digest = ta.Anchor.Digest
		xta.KeyDigest = append(xta.KeyDigest, xkd)
	}
	b, _ := xml.MarshalIndent(xta, "", "\t")
	return string(b)
}

// ReadTrustAnchor reads a root trust anchor from: http://data.iana.org/root-anchors/root-anchors.xml
// and returns the data or an error.
func ReadTrustAnchor(q io.Reader) ([]*TrustAnchor, error) {
	d := xml.NewDecoder(q)
	t := new(XMLTrustAnchor)
	if e := d.Decode(t); e != nil {
		return nil, e
	}
	ta := make([]*TrustAnchor, 0)
	var err error
	for _, digest := range t.KeyDigest {
		t1 := new(TrustAnchor)
		t1.Id = t.Id
		t1.Source = t.Source
		t1.AnchorId = digest.Id
		if t1.ValidFrom, err = time.Parse("2006-01-02T15:04:05-07:00", digest.ValidFrom); err != nil {
			return nil, err
		}
		if digest.ValidUntil != "" {
			if t1.ValidUntil, err = time.Parse("2006-01-02T15:04:05-07:00", digest.ValidUntil); err != nil {
				return nil, err
			}
		}
		d := new(RR_DS)
		d.Hdr = RR_Header{Name: t.Zone, Class: ClassINET, Rrtype: TypeDS}
		d.KeyTag = digest.KeyTag
		d.Algorithm = digest.Algorithm
		d.DigestType = digest.DigestType
		d.Digest = digest.Digest
		t1.Anchor = d
		// Some checks here too?
		ta = append(ta, t1)
	}
	return ta, nil
}

var (
	// This the root anchor in XML format.
	rootAnchorXML = `<?xml version="1.0" encoding="UTF-8"?>
<TrustAnchor id="AD42165F-3B1A-4778-8F42-D34A1D41FD93" source="http://data.iana.org/root-anchors/root-anchors.xml">
<Zone>.</Zone>
<KeyDigest id="Kjqmt7v" validFrom="2010-07-15T00:00:00+00:00">
<KeyTag>19036</KeyTag>
<Algorithm>8</Algorithm>
<DigestType>2</DigestType>
<Digest>49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5</Digest>
</KeyDigest>
</TrustAnchor>`
	// This is the root zone used for priming a resolver.
	namedRoot = `;       This file holds the information on root name servers needed to
;       initialize cache of Internet domain name servers
;       (e.g. reference this file in the "cache  .  <file>"
;       configuration file of BIND domain name servers).
;
;       This file is made available by InterNIC 
;       under anonymous FTP as
;           file                /domain/named.cache
;           on server           FTP.INTERNIC.NET
;       -OR-                    RS.INTERNIC.NET
;
;       last update:    Jun 8, 2011
;       related version of root zone:   2011060800
;
; formerly NS.INTERNIC.NET
;
.                        3600000  IN  NS    A.ROOT-SERVERS.NET.
A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:BA3E::2:30
;
; FORMERLY NS1.ISI.EDU
;
.                        3600000      NS    B.ROOT-SERVERS.NET.
B.ROOT-SERVERS.NET.      3600000      A     192.228.79.201
;
; FORMERLY C.PSI.NET
;
.                        3600000      NS    C.ROOT-SERVERS.NET.
C.ROOT-SERVERS.NET.      3600000      A     192.33.4.12
;
; FORMERLY TERP.UMD.EDU
;
.                        3600000      NS    D.ROOT-SERVERS.NET.
D.ROOT-SERVERS.NET.      3600000      A     128.8.10.90
D.ROOT-SERVERS.NET.	 3600000      AAAA  2001:500:2D::D
;
; FORMERLY NS.NASA.GOV
;
.                        3600000      NS    E.ROOT-SERVERS.NET.
E.ROOT-SERVERS.NET.      3600000      A     192.203.230.10
;
; FORMERLY NS.ISC.ORG
;
.                        3600000      NS    F.ROOT-SERVERS.NET.
F.ROOT-SERVERS.NET.      3600000      A     192.5.5.241
F.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:2F::F
;
; FORMERLY NS.NIC.DDN.MIL
;
.                        3600000      NS    G.ROOT-SERVERS.NET.
G.ROOT-SERVERS.NET.      3600000      A     192.112.36.4
;
; FORMERLY AOS.ARL.ARMY.MIL
;
.                        3600000      NS    H.ROOT-SERVERS.NET.
H.ROOT-SERVERS.NET.      3600000      A     128.63.2.53
H.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:1::803F:235
;
; FORMERLY NIC.NORDU.NET
;
.                        3600000      NS    I.ROOT-SERVERS.NET.
I.ROOT-SERVERS.NET.      3600000      A     192.36.148.17
I.ROOT-SERVERS.NET.      3600000      AAAA  2001:7FE::53
;
; OPERATED BY VERISIGN, INC.
;
.                        3600000      NS    J.ROOT-SERVERS.NET.
J.ROOT-SERVERS.NET.      3600000      A     192.58.128.30
J.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:C27::2:30
;
; OPERATED BY RIPE NCC
;
.                        3600000      NS    K.ROOT-SERVERS.NET.
K.ROOT-SERVERS.NET.      3600000      A     193.0.14.129
K.ROOT-SERVERS.NET.      3600000      AAAA  2001:7FD::1
;
; OPERATED BY ICANN
;
.                        3600000      NS    L.ROOT-SERVERS.NET.
L.ROOT-SERVERS.NET.      3600000      A     199.7.83.42
L.ROOT-SERVERS.NET.      3600000      AAAA  2001:500:3::42
;
; OPERATED BY WIDE
;
.                        3600000      NS    M.ROOT-SERVERS.NET.
M.ROOT-SERVERS.NET.      3600000      A     202.12.27.33
M.ROOT-SERVERS.NET.      3600000      AAAA  2001:DC3::35
; End of File`
)
