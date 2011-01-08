package dns

// The following values must be put in wireformat, so that
// the MAC can be calculated
// RFC 2845, section 3.4.2. TSIG Variables
type tsig_generation_fmt struct {
	// From RR_HEADER
	Name  string "domain-name"
	Class uint16
	Ttl   uint32
	// Rdata of the TSIG
	Algorithm  string "domain-name"
	TimeSigned [3]uint16
	Fudge      uint16
	// MACSize, MAC and OrigId excluded
	Error     uint16
	OtherLen  uint16
	OtherData string
}

func (rr *RR_TSIG) GenerateMAC() bool {
	buf := make([]byte, 2048) // TODO(mg) bufsize!
	tsigbuf := new(tsig_generation_fmt)

	// Fill the struct and generate the wiredata
	tsigbuf.Name = rr.Header().Name
	tsigbuf.Class = rr.Header().Class
	tsigbuf.Ttl = rr.Header().Ttl
        tsigbuf.Algorithm = rr.Algorithm
        tsigbuf.TimeSigned = rr.TimeSigned
        tsigbuf.Fudge = rr.Fudge
        tsigbuf.Error = rr.Error
        tsigbuf.OtherLen = rr.OtherLen
        tsigbuf.OtherData = rr.OtherData
        packStruct(tsigbuf, buf, 0)
	return true
}
