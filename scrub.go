package dns

// Scrub truncates the reply message so that it will fit the requested
// buffer size.
//
// It will first check if the reply fits without compression and then with
// compression. If it won't fit with compression, Scrub then walks the
// record adding as many records as possible without exceeding the
// requested buffer size.
//
// The TC bit will be set if any answer records were excluded from the
// message. This indicates to that the client should retry over TCP.
//
// The appropriate buffer size can be retrieved from the requests OPT
// record, if present, and is transport specific otherwise. dns.MinMsgSize
// should be used for UDP requests without an OPT record, and
// dns.MaxMsgSize for TCP requests without an OPT record.
func (dns *Msg) Scrub(size int, req *Msg) {
	if dns.IsTsig() != nil {
		// To simplify this implementation, we don't perform
		// scrubbing on responses with a TSIG record.
		return
	}

	l := msgLenWithCompressionMap(dns, nil) // uncompressed length
	if l <= size {
		// Don't waste effort compressing this message.
		dns.Compress = false
		return
	}

	dns.Compress = true

	reqEDNS0 := req.IsEdns0()
	dnsEDNS0 := dns.IsEdns0()
	if reqEDNS0 != nil {
		// Account for the OPT record that gets added at the end,
		// by subtracting that length from our budget.
		size -= 12 // OPT record length.

		if dnsEDNS0 != nil {
			// Remove the OPT record and handle it separately.
			//
			// TODO(tmthrgd): IsEdns0 checks more than just the
			// last record. This could remove the wrong record.
			dns.Extra = dns.Extra[:len(dns.Extra)-1]
		}
	}

	compression := make(map[string]struct{})

	l = 12 // Message header is always 12 bytes
	for _, r := range dns.Question {
		l += r.len(l, compression)
	}

	var numAnswer int
	if l < size {
		l, numAnswer = dns.truncateLoop(dns.Answer, size, l, compression)
	}

	var numNS int
	if l < size {
		l, numNS = dns.truncateLoop(dns.Ns, size, l, compression)
	}

	var numExtra int
	if l < size {
		l, numExtra = dns.truncateLoop(dns.Extra, size, l, compression)
	}

	// According to RFC 2181, the TC bit should only be set if not all
	// of the answer RRs cannot be included.
	dns.Truncated = len(dns.Answer) > numAnswer

	dns.Answer = dns.Answer[:numAnswer]
	dns.Ns = dns.Ns[:numNS]
	dns.Extra = dns.Extra[:numExtra]

	if reqEDNS0 != nil {
		// Add OPT record to message. This may be the same OPT
		// record that was already part of the message.

		o := dnsEDNS0
		if o == nil {
			o = new(OPT)
		}

		o.Hdr.Name = "."
		o.Hdr.Rrtype = TypeOPT
		o.SetVersion(0)
		o.Hdr.Ttl &^= 0xffff // clear flags
		o.SetDo(reqEDNS0.Do())
		o.SetUDPSize(reqEDNS0.UDPSize())

		dns.Extra = append(dns.Extra, o)
	}
}

func (dns *Msg) truncateLoop(rrs []RR, size, l int, compression map[string]struct{}) (int, int) {
	for i, r := range rrs {
		if r == nil {
			continue
		}

		l += r.len(l, compression)
		if l > size {
			// Return size, rather than l prior to this record,
			// to prevent any further records being added.
			return size, i
		}
		if l == size {
			return l, i + 1
		}
	}

	return l, len(rrs)
}
