package dns

// A structure for handling zone data

import (
	"github.com/petar/GoLLRB/llrb"
)

type Zone struct {
	Name       string // Name of the zone
	*llrb.Tree        // Zone data
}

type ZoneData struct {
	Name       string                 // Domain name for this node
	RR         map[uint16][]RR        // Map ...
	Signatures map[uint16][]*RR_RRSIG // DNSSEC signatures
	Glue       bool                   // True if the A and AAAA record are glue
	// nsec3, next
}
