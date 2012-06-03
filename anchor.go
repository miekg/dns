package dns

import (
	"encoding/xml"
	"fmt"
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
	ValidUntil time.Time
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

// ReadTrustAnchor read a root trust anchor from: http://data.iana.org/root-anchors/root-anchors.xml
// and return the data or an error.
func ReadTrustAnchor(q io.Reader) ([]*TrustAnchor, error) {
	d := xml.NewDecoder(q)
	t := new(XMLTrustAnchor)
	e := d.Decode(t)
	if e != nil {
		println(e.Error())
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
	fmt.Printf("%+v %+v\n", t, t.KeyDigest[0])
	return ta, nil
}
