
// line 1 "zparse.rl"
package dns

// Parse RRs
// With the thankful help of gdnsd and the Go examples for Ragel 

import (
    "os"
    "fmt"
    "net"
    "strconv"
)


// line 17 "zparse.go"
var z_start int = 1
var z_first_final int = 281
var z_error int = 0

var z_en_main int = 1


// line 16 "zparse.rl"


func Zparse(data string) (r RR, err os.Error) {
        cs, p, pe, eof := 0, 0, len(data), len(data)
        j := 0; j = j // Needed for compile.
        k := 0; k = k // "
        mark := 0
        hdr := new(RR_Header)
        txt := make([]string, 7)
        num := make([]int, 7)

        
// line 38 "zparse.go"
	cs = z_start

// line 41 "zparse.go"
	{
	if p == pe { goto _test_eof }
	switch cs {
	case -666: // i am a hack D:
	fallthrough
case 1:
	switch data[p] {
		case 9: goto st2
		case 32: goto st2
		case 46: goto st280
		case 92: goto st280
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st280 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st280 }
	} else {
		goto st280
	}
	goto st0
st0:
cs = 0;
	goto _out;
tr604:
// line 29 "zparse.rl"
	{ hdr.Name = data[mark:p] }
	goto st2
tr605:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st2
tr607:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st2
tr610:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st2
tr612:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st2
tr619:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st2
tr624:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st2
tr630:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st2
tr635:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st2
tr648:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st2
tr650:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st2
tr653:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr655:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr664:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr670:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr684:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr708:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st2
tr717:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st2
tr736:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st2
tr768:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st2
tr770:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st2
tr780:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st2
tr786:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st2
tr805:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st2
tr838:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st2
tr862:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st2
tr882:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st2
tr887:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st2
tr937:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st2
tr942:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st2
tr953:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st2
tr999:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr1008:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr1016:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr1023:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr1057:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr1067:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr1145:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr1184:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr1197:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr1204:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
tr1378:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st2
tr1387:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st2
tr1448:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st2
st2:
	p++
	if p == pe { goto _test_eof2 }
	fallthrough
case 2:
// line 840 "zparse.go"
	switch data[p] {
		case 9: goto st2
		case 32: goto st2
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr3 }
	goto st0
tr3:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st3
st3:
	p++
	if p == pe { goto _test_eof3 }
	fallthrough
case 3:
// line 876 "zparse.go"
	switch data[p] {
		case 9: goto tr13
		case 32: goto tr13
	}
	if 48 <= data[p] && data[p] <= 57 { goto st3 }
	goto st0
tr13:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st4
st4:
	p++
	if p == pe { goto _test_eof4 }
	fallthrough
case 4:
// line 892 "zparse.go"
	switch data[p] {
		case 9: goto st4
		case 32: goto st4
		case 65: goto tr16
		case 67: goto tr17
		case 68: goto tr18
		case 72: goto tr19
		case 73: goto tr20
		case 77: goto tr21
		case 78: goto tr22
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr16
		case 99: goto tr17
		case 100: goto tr18
		case 104: goto tr19
		case 105: goto tr20
		case 109: goto tr21
		case 110: goto tr22
		case 114: goto tr23
		case 115: goto tr24
	}
	goto st0
tr16:
// line 28 "zparse.rl"
	{ mark = p }
	goto st5
st5:
	p++
	if p == pe { goto _test_eof5 }
	fallthrough
case 5:
// line 925 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr25
		case 78: goto st7
		case 110: goto st7
	}
	goto st0
tr25:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st6
st6:
	p++
	if p == pe { goto _test_eof6 }
	fallthrough
case 6:
// line 950 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 32: goto st6
		case 46: goto tr28
		case 92: goto tr28
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr28 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr28 }
	} else {
		goto tr28
	}
	goto st0
tr28:
// line 28 "zparse.rl"
	{ mark = p }
	goto st281
st281:
	p++
	if p == pe { goto _test_eof281 }
	fallthrough
case 281:
// line 974 "zparse.go"
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 92: goto st281
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st7:
	p++
	if p == pe { goto _test_eof7 }
	fallthrough
case 7:
	switch data[p] {
		case 89: goto st8
		case 121: goto st8
	}
	goto st0
st8:
	p++
	if p == pe { goto _test_eof8 }
	fallthrough
case 8:
	switch data[p] {
		case 9: goto tr30
		case 32: goto tr30
	}
	goto st0
tr186:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st9
tr30:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st9
st9:
	p++
	if p == pe { goto _test_eof9 }
	fallthrough
case 9:
// line 1022 "zparse.go"
	switch data[p] {
		case 9: goto st9
		case 32: goto st9
		case 65: goto tr32
		case 67: goto tr33
		case 68: goto tr18
		case 77: goto tr21
		case 78: goto tr34
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr32
		case 99: goto tr33
		case 100: goto tr18
		case 109: goto tr21
		case 110: goto tr34
		case 114: goto tr23
		case 115: goto tr24
	}
	goto st0
tr32:
// line 28 "zparse.rl"
	{ mark = p }
	goto st10
st10:
	p++
	if p == pe { goto _test_eof10 }
	fallthrough
case 10:
// line 1051 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr25
	}
	goto st0
tr33:
// line 28 "zparse.rl"
	{ mark = p }
	goto st11
st11:
	p++
	if p == pe { goto _test_eof11 }
	fallthrough
case 11:
// line 1066 "zparse.go"
	switch data[p] {
		case 78: goto st12
		case 110: goto st12
	}
	goto st0
st12:
	p++
	if p == pe { goto _test_eof12 }
	fallthrough
case 12:
	switch data[p] {
		case 65: goto st13
		case 97: goto st13
	}
	goto st0
st13:
	p++
	if p == pe { goto _test_eof13 }
	fallthrough
case 13:
	switch data[p] {
		case 77: goto st14
		case 109: goto st14
	}
	goto st0
st14:
	p++
	if p == pe { goto _test_eof14 }
	fallthrough
case 14:
	switch data[p] {
		case 69: goto st15
		case 101: goto st15
	}
	goto st0
st15:
	p++
	if p == pe { goto _test_eof15 }
	fallthrough
case 15:
	switch data[p] {
		case 9: goto tr39
		case 32: goto tr39
	}
	goto st0
tr39:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st16
st16:
	p++
	if p == pe { goto _test_eof16 }
	fallthrough
case 16:
// line 1129 "zparse.go"
	switch data[p] {
		case 9: goto st16
		case 32: goto st16
		case 46: goto tr41
		case 92: goto tr41
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr41 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr41 }
	} else {
		goto tr41
	}
	goto st0
tr41:
// line 28 "zparse.rl"
	{ mark = p }
	goto st282
st282:
	p++
	if p == pe { goto _test_eof282 }
	fallthrough
case 282:
// line 1153 "zparse.go"
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 92: goto st282
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
tr6:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st17
tr18:
// line 28 "zparse.rl"
	{ mark = p }
	goto st17
st17:
	p++
	if p == pe { goto _test_eof17 }
	fallthrough
case 17:
// line 1183 "zparse.go"
	switch data[p] {
		case 78: goto st18
		case 83: goto st279
		case 110: goto st18
		case 115: goto st279
	}
	goto st0
st18:
	p++
	if p == pe { goto _test_eof18 }
	fallthrough
case 18:
	switch data[p] {
		case 83: goto st19
		case 115: goto st19
	}
	goto st0
st19:
	p++
	if p == pe { goto _test_eof19 }
	fallthrough
case 19:
	switch data[p] {
		case 75: goto st20
		case 107: goto st20
	}
	goto st0
st20:
	p++
	if p == pe { goto _test_eof20 }
	fallthrough
case 20:
	switch data[p] {
		case 69: goto st21
		case 101: goto st21
	}
	goto st0
st21:
	p++
	if p == pe { goto _test_eof21 }
	fallthrough
case 21:
	switch data[p] {
		case 89: goto st22
		case 121: goto st22
	}
	goto st0
st22:
	p++
	if p == pe { goto _test_eof22 }
	fallthrough
case 22:
	switch data[p] {
		case 9: goto tr48
		case 32: goto tr48
	}
	goto st0
tr48:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st23
st23:
	p++
	if p == pe { goto _test_eof23 }
	fallthrough
case 23:
// line 1258 "zparse.go"
	switch data[p] {
		case 9: goto st23
		case 32: goto st23
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr50 }
	goto st0
tr50:
// line 28 "zparse.rl"
	{ mark = p }
	goto st24
st24:
	p++
	if p == pe { goto _test_eof24 }
	fallthrough
case 24:
// line 1274 "zparse.go"
	switch data[p] {
		case 9: goto tr51
		case 32: goto tr51
	}
	if 48 <= data[p] && data[p] <= 57 { goto st24 }
	goto st0
tr51:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st25
st25:
	p++
	if p == pe { goto _test_eof25 }
	fallthrough
case 25:
// line 1290 "zparse.go"
	switch data[p] {
		case 9: goto st25
		case 32: goto st25
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr54 }
	goto st0
tr54:
// line 28 "zparse.rl"
	{ mark = p }
	goto st26
st26:
	p++
	if p == pe { goto _test_eof26 }
	fallthrough
case 26:
// line 1306 "zparse.go"
	switch data[p] {
		case 9: goto tr55
		case 32: goto tr55
	}
	if 48 <= data[p] && data[p] <= 57 { goto st26 }
	goto st0
tr55:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st27
st27:
	p++
	if p == pe { goto _test_eof27 }
	fallthrough
case 27:
// line 1322 "zparse.go"
	switch data[p] {
		case 9: goto st27
		case 32: goto st27
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr58 }
	goto st0
tr58:
// line 28 "zparse.rl"
	{ mark = p }
	goto st28
st28:
	p++
	if p == pe { goto _test_eof28 }
	fallthrough
case 28:
// line 1338 "zparse.go"
	switch data[p] {
		case 9: goto tr59
		case 32: goto tr59
	}
	if 48 <= data[p] && data[p] <= 57 { goto st28 }
	goto st0
tr59:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st29
st29:
	p++
	if p == pe { goto _test_eof29 }
	fallthrough
case 29:
// line 1354 "zparse.go"
	switch data[p] {
		case 9: goto st29
		case 32: goto tr62
		case 46: goto tr63
		case 92: goto tr63
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr63 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr63 }
	} else {
		goto tr63
	}
	goto st0
tr62:
// line 28 "zparse.rl"
	{ mark = p }
	goto st283
tr763:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st283
st283:
	p++
	if p == pe { goto _test_eof283 }
	fallthrough
case 283:
// line 1382 "zparse.go"
	switch data[p] {
		case 9: goto tr609
		case 32: goto tr62
		case 46: goto tr63
		case 92: goto tr63
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr63 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr63 }
	} else {
		goto tr63
	}
	goto st0
tr609:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st30
tr1466:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st30
tr1463:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st30
tr762:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st30
tr834:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st30
tr831:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st30
tr837:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st30
tr1468:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st30
st30:
	p++
	if p == pe { goto _test_eof30 }
	fallthrough
case 30:
// line 1535 "zparse.go"
	switch data[p] {
		case 9: goto st30
		case 32: goto tr65
		case 46: goto tr63
		case 65: goto tr67
		case 67: goto tr68
		case 68: goto tr69
		case 72: goto tr70
		case 73: goto tr71
		case 77: goto tr72
		case 78: goto tr73
		case 82: goto tr74
		case 83: goto tr75
		case 92: goto tr63
		case 97: goto tr67
		case 99: goto tr68
		case 100: goto tr69
		case 104: goto tr70
		case 105: goto tr71
		case 109: goto tr72
		case 110: goto tr73
		case 114: goto tr74
		case 115: goto tr75
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr66 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr63 }
	} else {
		goto tr63
	}
	goto st0
tr65:
// line 28 "zparse.rl"
	{ mark = p }
	goto st284
st284:
	p++
	if p == pe { goto _test_eof284 }
	fallthrough
case 284:
// line 1577 "zparse.go"
	switch data[p] {
		case 9: goto tr609
		case 32: goto tr65
		case 46: goto tr63
		case 65: goto tr67
		case 67: goto tr68
		case 68: goto tr69
		case 72: goto tr70
		case 73: goto tr71
		case 77: goto tr72
		case 78: goto tr73
		case 82: goto tr74
		case 83: goto tr75
		case 92: goto tr63
		case 97: goto tr67
		case 99: goto tr68
		case 100: goto tr69
		case 104: goto tr70
		case 105: goto tr71
		case 109: goto tr72
		case 110: goto tr73
		case 114: goto tr74
		case 115: goto tr75
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr66 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr63 }
	} else {
		goto tr63
	}
	goto st0
tr63:
// line 28 "zparse.rl"
	{ mark = p }
	goto st285
st285:
	p++
	if p == pe { goto _test_eof285 }
	fallthrough
case 285:
// line 1619 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr66:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st286
st286:
	p++
	if p == pe { goto _test_eof286 }
	fallthrough
case 286:
// line 1645 "zparse.go"
	switch data[p] {
		case 9: goto tr612
		case 32: goto tr613
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st286 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr613:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st287
st287:
	p++
	if p == pe { goto _test_eof287 }
	fallthrough
case 287:
// line 1669 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st287
		case 46: goto st285
		case 65: goto tr196
		case 67: goto tr197
		case 68: goto tr198
		case 72: goto tr199
		case 73: goto tr200
		case 77: goto tr201
		case 78: goto tr202
		case 82: goto tr203
		case 83: goto tr204
		case 92: goto st285
		case 97: goto tr196
		case 99: goto tr197
		case 100: goto tr198
		case 104: goto tr199
		case 105: goto tr200
		case 109: goto tr201
		case 110: goto tr202
		case 114: goto tr203
		case 115: goto tr204
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr196:
// line 28 "zparse.rl"
	{ mark = p }
	goto st288
st288:
	p++
	if p == pe { goto _test_eof288 }
	fallthrough
case 288:
// line 1711 "zparse.go"
	switch data[p] {
		case 9: goto tr616
		case 32: goto tr617
		case 46: goto st285
		case 78: goto st866
		case 92: goto st285
		case 110: goto st866
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr714:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st31
tr616:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st31
tr621:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st31
tr632:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st31
tr662:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st31
tr659:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st31
tr777:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st31
tr774:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st31
tr859:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st31
tr884:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st31
tr1002:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st31
tr1019:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st31
tr1141:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st31
tr1200:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st31
st31:
	p++
	if p == pe { goto _test_eof31 }
	fallthrough
case 31:
// line 2059 "zparse.go"
	switch data[p] {
		case 9: goto st31
		case 32: goto st31
		case 46: goto tr28
		case 65: goto tr78
		case 67: goto tr79
		case 68: goto tr80
		case 72: goto tr81
		case 73: goto tr82
		case 77: goto tr83
		case 78: goto tr84
		case 82: goto tr85
		case 83: goto tr86
		case 92: goto tr28
		case 97: goto tr78
		case 99: goto tr79
		case 100: goto tr80
		case 104: goto tr81
		case 105: goto tr82
		case 109: goto tr83
		case 110: goto tr84
		case 114: goto tr85
		case 115: goto tr86
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr77 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr28 }
	} else {
		goto tr28
	}
	goto st0
tr77:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st289
st289:
	p++
	if p == pe { goto _test_eof289 }
	fallthrough
case 289:
// line 2103 "zparse.go"
	switch data[p] {
		case 9: goto tr619
		case 32: goto tr619
		case 46: goto st281
		case 92: goto st281
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st289 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
tr78:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st290
st290:
	p++
	if p == pe { goto _test_eof290 }
	fallthrough
case 290:
// line 2129 "zparse.go"
	switch data[p] {
		case 9: goto tr621
		case 32: goto tr621
		case 46: goto st281
		case 78: goto st291
		case 92: goto st281
		case 110: goto st291
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st291:
	p++
	if p == pe { goto _test_eof291 }
	fallthrough
case 291:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 89: goto st292
		case 92: goto st281
		case 121: goto st292
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st292:
	p++
	if p == pe { goto _test_eof292 }
	fallthrough
case 292:
	switch data[p] {
		case 9: goto tr624
		case 32: goto tr624
		case 46: goto st281
		case 92: goto st281
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
tr79:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st293
st293:
	p++
	if p == pe { goto _test_eof293 }
	fallthrough
case 293:
// line 2197 "zparse.go"
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 72: goto st292
		case 78: goto st294
		case 83: goto st292
		case 92: goto st281
		case 104: goto st292
		case 110: goto st294
		case 115: goto st292
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st294:
	p++
	if p == pe { goto _test_eof294 }
	fallthrough
case 294:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 65: goto st295
		case 92: goto st281
		case 97: goto st295
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st295:
	p++
	if p == pe { goto _test_eof295 }
	fallthrough
case 295:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 77: goto st296
		case 92: goto st281
		case 109: goto st296
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st296:
	p++
	if p == pe { goto _test_eof296 }
	fallthrough
case 296:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 69: goto st297
		case 92: goto st281
		case 101: goto st297
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st297:
	p++
	if p == pe { goto _test_eof297 }
	fallthrough
case 297:
	switch data[p] {
		case 9: goto tr629
		case 32: goto tr629
		case 46: goto st281
		case 92: goto st281
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
tr733:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st32
tr731:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st32
tr629:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st32
tr640:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st32
tr682:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st32
tr680:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st32
tr802:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st32
tr800:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st32
tr867:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st32
tr892:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st32
tr1013:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st32
tr1029:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st32
tr1151:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st32
tr1210:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st32
st32:
	p++
	if p == pe { goto _test_eof32 }
	fallthrough
case 32:
// line 2631 "zparse.go"
	switch data[p] {
		case 9: goto st32
		case 32: goto st32
		case 46: goto tr41
		case 65: goto tr89
		case 67: goto tr90
		case 68: goto tr91
		case 72: goto tr92
		case 73: goto tr93
		case 77: goto tr94
		case 78: goto tr95
		case 82: goto tr96
		case 83: goto tr97
		case 92: goto tr41
		case 97: goto tr89
		case 99: goto tr90
		case 100: goto tr91
		case 104: goto tr92
		case 105: goto tr93
		case 109: goto tr94
		case 110: goto tr95
		case 114: goto tr96
		case 115: goto tr97
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr88 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr41 }
	} else {
		goto tr41
	}
	goto st0
tr88:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st298
st298:
	p++
	if p == pe { goto _test_eof298 }
	fallthrough
case 298:
// line 2675 "zparse.go"
	switch data[p] {
		case 9: goto tr630
		case 32: goto tr630
		case 46: goto st282
		case 92: goto st282
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st298 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
tr89:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st299
st299:
	p++
	if p == pe { goto _test_eof299 }
	fallthrough
case 299:
// line 2701 "zparse.go"
	switch data[p] {
		case 9: goto tr632
		case 32: goto tr632
		case 46: goto st282
		case 78: goto st300
		case 92: goto st282
		case 110: goto st300
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st300:
	p++
	if p == pe { goto _test_eof300 }
	fallthrough
case 300:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 89: goto st301
		case 92: goto st282
		case 121: goto st301
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st301:
	p++
	if p == pe { goto _test_eof301 }
	fallthrough
case 301:
	switch data[p] {
		case 9: goto tr635
		case 32: goto tr635
		case 46: goto st282
		case 92: goto st282
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
tr90:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st302
st302:
	p++
	if p == pe { goto _test_eof302 }
	fallthrough
case 302:
// line 2769 "zparse.go"
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 72: goto st301
		case 78: goto st303
		case 83: goto st301
		case 92: goto st282
		case 104: goto st301
		case 110: goto st303
		case 115: goto st301
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st303:
	p++
	if p == pe { goto _test_eof303 }
	fallthrough
case 303:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 65: goto st304
		case 92: goto st282
		case 97: goto st304
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st304:
	p++
	if p == pe { goto _test_eof304 }
	fallthrough
case 304:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 77: goto st305
		case 92: goto st282
		case 109: goto st305
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st305:
	p++
	if p == pe { goto _test_eof305 }
	fallthrough
case 305:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 69: goto st306
		case 92: goto st282
		case 101: goto st306
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st306:
	p++
	if p == pe { goto _test_eof306 }
	fallthrough
case 306:
	switch data[p] {
		case 9: goto tr640
		case 32: goto tr640
		case 46: goto st282
		case 92: goto st282
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
tr91:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st307
st307:
	p++
	if p == pe { goto _test_eof307 }
	fallthrough
case 307:
// line 2883 "zparse.go"
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 78: goto st308
		case 83: goto st826
		case 92: goto st282
		case 110: goto st308
		case 115: goto st826
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st308:
	p++
	if p == pe { goto _test_eof308 }
	fallthrough
case 308:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 83: goto st309
		case 92: goto st282
		case 115: goto st309
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st309:
	p++
	if p == pe { goto _test_eof309 }
	fallthrough
case 309:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 75: goto st310
		case 92: goto st282
		case 107: goto st310
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st310:
	p++
	if p == pe { goto _test_eof310 }
	fallthrough
case 310:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 69: goto st311
		case 92: goto st282
		case 101: goto st311
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st311:
	p++
	if p == pe { goto _test_eof311 }
	fallthrough
case 311:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 89: goto st312
		case 92: goto st282
		case 121: goto st312
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st312:
	p++
	if p == pe { goto _test_eof312 }
	fallthrough
case 312:
	switch data[p] {
		case 9: goto tr647
		case 32: goto tr647
		case 46: goto st282
		case 92: goto st282
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
tr747:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st33
tr745:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st33
tr1493:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st33
tr647:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st33
tr695:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st33
tr693:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st33
tr816:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st33
tr814:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st33
tr874:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st33
tr899:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st33
tr1294:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st33
tr1037:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st33
tr1159:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st33
tr1218:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st33
st33:
	p++
	if p == pe { goto _test_eof33 }
	fallthrough
case 33:
// line 3336 "zparse.go"
	switch data[p] {
		case 9: goto st33
		case 32: goto st33
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr99 }
	goto st0
tr99:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st34
st34:
	p++
	if p == pe { goto _test_eof34 }
	fallthrough
case 34:
// line 3372 "zparse.go"
	switch data[p] {
		case 9: goto tr100
		case 32: goto tr100
	}
	if 48 <= data[p] && data[p] <= 57 { goto st34 }
	goto st0
tr100:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st35
st35:
	p++
	if p == pe { goto _test_eof35 }
	fallthrough
case 35:
// line 3390 "zparse.go"
	switch data[p] {
		case 9: goto st35
		case 32: goto st35
		case 65: goto tr16
		case 67: goto tr17
		case 68: goto tr18
		case 72: goto tr19
		case 73: goto tr20
		case 77: goto tr21
		case 78: goto tr22
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr16
		case 99: goto tr17
		case 100: goto tr18
		case 104: goto tr19
		case 105: goto tr20
		case 109: goto tr21
		case 110: goto tr22
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr54 }
	goto st0
tr17:
// line 28 "zparse.rl"
	{ mark = p }
	goto st36
st36:
	p++
	if p == pe { goto _test_eof36 }
	fallthrough
case 36:
// line 3424 "zparse.go"
	switch data[p] {
		case 72: goto st8
		case 78: goto st12
		case 83: goto st8
		case 104: goto st8
		case 110: goto st12
		case 115: goto st8
	}
	goto st0
tr19:
// line 28 "zparse.rl"
	{ mark = p }
	goto st37
st37:
	p++
	if p == pe { goto _test_eof37 }
	fallthrough
case 37:
// line 3443 "zparse.go"
	switch data[p] {
		case 83: goto st8
		case 115: goto st8
	}
	goto st0
tr20:
// line 28 "zparse.rl"
	{ mark = p }
	goto st38
st38:
	p++
	if p == pe { goto _test_eof38 }
	fallthrough
case 38:
// line 3458 "zparse.go"
	switch data[p] {
		case 78: goto st8
		case 110: goto st8
	}
	goto st0
tr9:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st39
tr21:
// line 28 "zparse.rl"
	{ mark = p }
	goto st39
st39:
	p++
	if p == pe { goto _test_eof39 }
	fallthrough
case 39:
// line 3479 "zparse.go"
	switch data[p] {
		case 88: goto st40
		case 120: goto st40
	}
	goto st0
st40:
	p++
	if p == pe { goto _test_eof40 }
	fallthrough
case 40:
	switch data[p] {
		case 9: goto tr104
		case 32: goto tr104
	}
	goto st0
tr104:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st41
st41:
	p++
	if p == pe { goto _test_eof41 }
	fallthrough
case 41:
// line 3512 "zparse.go"
	switch data[p] {
		case 9: goto st41
		case 32: goto st41
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr106 }
	goto st0
tr106:
// line 28 "zparse.rl"
	{ mark = p }
	goto st42
st42:
	p++
	if p == pe { goto _test_eof42 }
	fallthrough
case 42:
// line 3528 "zparse.go"
	switch data[p] {
		case 9: goto tr107
		case 32: goto tr107
	}
	if 48 <= data[p] && data[p] <= 57 { goto st42 }
	goto st0
tr107:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st43
st43:
	p++
	if p == pe { goto _test_eof43 }
	fallthrough
case 43:
// line 3544 "zparse.go"
	switch data[p] {
		case 9: goto st43
		case 32: goto st43
		case 46: goto tr110
		case 92: goto tr110
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr110 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr110 }
	} else {
		goto tr110
	}
	goto st0
tr110:
// line 28 "zparse.rl"
	{ mark = p }
	goto st313
st313:
	p++
	if p == pe { goto _test_eof313 }
	fallthrough
case 313:
// line 3568 "zparse.go"
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 92: goto st313
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
tr22:
// line 28 "zparse.rl"
	{ mark = p }
	goto st44
st44:
	p++
	if p == pe { goto _test_eof44 }
	fallthrough
case 44:
// line 3592 "zparse.go"
	switch data[p] {
		case 79: goto st45
		case 83: goto st47
		case 111: goto st45
		case 115: goto st47
	}
	goto st0
st45:
	p++
	if p == pe { goto _test_eof45 }
	fallthrough
case 45:
	switch data[p] {
		case 78: goto st46
		case 110: goto st46
	}
	goto st0
st46:
	p++
	if p == pe { goto _test_eof46 }
	fallthrough
case 46:
	switch data[p] {
		case 69: goto st8
		case 101: goto st8
	}
	goto st0
st47:
	p++
	if p == pe { goto _test_eof47 }
	fallthrough
case 47:
	switch data[p] {
		case 9: goto tr114
		case 32: goto tr114
	}
	goto st0
tr114:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st48
st48:
	p++
	if p == pe { goto _test_eof48 }
	fallthrough
case 48:
// line 3647 "zparse.go"
	switch data[p] {
		case 9: goto st48
		case 32: goto st48
		case 46: goto tr116
		case 92: goto tr116
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr116 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr116 }
	} else {
		goto tr116
	}
	goto st0
tr116:
// line 28 "zparse.rl"
	{ mark = p }
	goto st314
st314:
	p++
	if p == pe { goto _test_eof314 }
	fallthrough
case 314:
// line 3671 "zparse.go"
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 92: goto st314
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
tr11:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st49
tr23:
// line 28 "zparse.rl"
	{ mark = p }
	goto st49
st49:
	p++
	if p == pe { goto _test_eof49 }
	fallthrough
case 49:
// line 3701 "zparse.go"
	switch data[p] {
		case 82: goto st50
		case 114: goto st50
	}
	goto st0
st50:
	p++
	if p == pe { goto _test_eof50 }
	fallthrough
case 50:
	switch data[p] {
		case 83: goto st51
		case 115: goto st51
	}
	goto st0
st51:
	p++
	if p == pe { goto _test_eof51 }
	fallthrough
case 51:
	switch data[p] {
		case 73: goto st52
		case 105: goto st52
	}
	goto st0
st52:
	p++
	if p == pe { goto _test_eof52 }
	fallthrough
case 52:
	switch data[p] {
		case 71: goto st53
		case 103: goto st53
	}
	goto st0
st53:
	p++
	if p == pe { goto _test_eof53 }
	fallthrough
case 53:
	switch data[p] {
		case 9: goto tr121
		case 32: goto tr121
	}
	goto st0
tr121:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st54
st54:
	p++
	if p == pe { goto _test_eof54 }
	fallthrough
case 54:
// line 3764 "zparse.go"
	switch data[p] {
		case 9: goto st54
		case 32: goto st54
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr123 }
	goto st0
tr123:
// line 28 "zparse.rl"
	{ mark = p }
	goto st55
st55:
	p++
	if p == pe { goto _test_eof55 }
	fallthrough
case 55:
// line 3780 "zparse.go"
	switch data[p] {
		case 9: goto tr124
		case 32: goto tr124
	}
	if 48 <= data[p] && data[p] <= 57 { goto st55 }
	goto st0
tr124:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st56
st56:
	p++
	if p == pe { goto _test_eof56 }
	fallthrough
case 56:
// line 3796 "zparse.go"
	switch data[p] {
		case 9: goto st56
		case 32: goto st56
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr127 }
	goto st0
tr127:
// line 28 "zparse.rl"
	{ mark = p }
	goto st57
st57:
	p++
	if p == pe { goto _test_eof57 }
	fallthrough
case 57:
// line 3812 "zparse.go"
	switch data[p] {
		case 9: goto tr128
		case 32: goto tr128
	}
	if 48 <= data[p] && data[p] <= 57 { goto st57 }
	goto st0
tr128:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st58
st58:
	p++
	if p == pe { goto _test_eof58 }
	fallthrough
case 58:
// line 3828 "zparse.go"
	switch data[p] {
		case 9: goto st58
		case 32: goto st58
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr131 }
	goto st0
tr131:
// line 28 "zparse.rl"
	{ mark = p }
	goto st59
st59:
	p++
	if p == pe { goto _test_eof59 }
	fallthrough
case 59:
// line 3844 "zparse.go"
	switch data[p] {
		case 9: goto tr132
		case 32: goto tr132
	}
	if 48 <= data[p] && data[p] <= 57 { goto st59 }
	goto st0
tr132:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st60
st60:
	p++
	if p == pe { goto _test_eof60 }
	fallthrough
case 60:
// line 3860 "zparse.go"
	switch data[p] {
		case 9: goto st60
		case 32: goto st60
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr135 }
	goto st0
tr135:
// line 28 "zparse.rl"
	{ mark = p }
	goto st61
st61:
	p++
	if p == pe { goto _test_eof61 }
	fallthrough
case 61:
// line 3876 "zparse.go"
	switch data[p] {
		case 9: goto tr136
		case 32: goto tr136
	}
	if 48 <= data[p] && data[p] <= 57 { goto st61 }
	goto st0
tr136:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st62
st62:
	p++
	if p == pe { goto _test_eof62 }
	fallthrough
case 62:
// line 3892 "zparse.go"
	switch data[p] {
		case 9: goto st62
		case 32: goto st62
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr139 }
	goto st0
tr139:
// line 28 "zparse.rl"
	{ mark = p }
	goto st63
st63:
	p++
	if p == pe { goto _test_eof63 }
	fallthrough
case 63:
// line 3908 "zparse.go"
	switch data[p] {
		case 9: goto tr140
		case 32: goto tr140
	}
	if 48 <= data[p] && data[p] <= 57 { goto st63 }
	goto st0
tr140:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st64
st64:
	p++
	if p == pe { goto _test_eof64 }
	fallthrough
case 64:
// line 3924 "zparse.go"
	switch data[p] {
		case 9: goto st64
		case 32: goto st64
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr143 }
	goto st0
tr143:
// line 28 "zparse.rl"
	{ mark = p }
	goto st65
st65:
	p++
	if p == pe { goto _test_eof65 }
	fallthrough
case 65:
// line 3940 "zparse.go"
	switch data[p] {
		case 9: goto tr144
		case 32: goto tr144
	}
	if 48 <= data[p] && data[p] <= 57 { goto st65 }
	goto st0
tr144:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st66
st66:
	p++
	if p == pe { goto _test_eof66 }
	fallthrough
case 66:
// line 3956 "zparse.go"
	switch data[p] {
		case 9: goto st66
		case 32: goto st66
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr147 }
	goto st0
tr147:
// line 28 "zparse.rl"
	{ mark = p }
	goto st67
st67:
	p++
	if p == pe { goto _test_eof67 }
	fallthrough
case 67:
// line 3972 "zparse.go"
	switch data[p] {
		case 9: goto tr148
		case 32: goto tr148
	}
	if 48 <= data[p] && data[p] <= 57 { goto st67 }
	goto st0
tr148:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st68
st68:
	p++
	if p == pe { goto _test_eof68 }
	fallthrough
case 68:
// line 3988 "zparse.go"
	switch data[p] {
		case 9: goto st68
		case 32: goto st68
		case 46: goto tr151
		case 92: goto tr151
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr151 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr151 }
	} else {
		goto tr151
	}
	goto st0
tr151:
// line 28 "zparse.rl"
	{ mark = p }
	goto st69
st69:
	p++
	if p == pe { goto _test_eof69 }
	fallthrough
case 69:
// line 4012 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 92: goto st69
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr152:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st70
tr597:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st70
st70:
	p++
	if p == pe { goto _test_eof70 }
	fallthrough
case 70:
// line 4050 "zparse.go"
	switch data[p] {
		case 9: goto st70
		case 32: goto tr155
		case 46: goto tr156
		case 92: goto tr156
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr156 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr155:
// line 28 "zparse.rl"
	{ mark = p }
	goto st315
tr1284:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st315
st315:
	p++
	if p == pe { goto _test_eof315 }
	fallthrough
case 315:
// line 4078 "zparse.go"
	switch data[p] {
		case 9: goto tr652
		case 32: goto tr155
		case 46: goto tr156
		case 92: goto tr156
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr156 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr1444:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st71
tr652:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st71
tr1328:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st71
tr1330:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st71
tr1283:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st71
tr1325:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st71
tr1441:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st71
tr1447:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st71
st71:
	p++
	if p == pe { goto _test_eof71 }
	fallthrough
case 71:
// line 4236 "zparse.go"
	switch data[p] {
		case 9: goto st71
		case 32: goto tr158
		case 46: goto tr156
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto tr156
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr159 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr158:
// line 28 "zparse.rl"
	{ mark = p }
	goto st316
st316:
	p++
	if p == pe { goto _test_eof316 }
	fallthrough
case 316:
// line 4278 "zparse.go"
	switch data[p] {
		case 9: goto tr652
		case 32: goto tr158
		case 46: goto tr156
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto tr156
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr159 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr156:
// line 28 "zparse.rl"
	{ mark = p }
	goto st317
st317:
	p++
	if p == pe { goto _test_eof317 }
	fallthrough
case 317:
// line 4320 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr159:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st318
st318:
	p++
	if p == pe { goto _test_eof318 }
	fallthrough
case 318:
// line 4346 "zparse.go"
	switch data[p] {
		case 9: goto tr655
		case 32: goto tr656
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st318 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr656:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st319
st319:
	p++
	if p == pe { goto _test_eof319 }
	fallthrough
case 319:
// line 4370 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st319
		case 46: goto st317
		case 65: goto tr499
		case 67: goto tr500
		case 68: goto tr501
		case 72: goto tr502
		case 73: goto tr503
		case 77: goto tr504
		case 78: goto tr505
		case 82: goto tr506
		case 83: goto tr507
		case 92: goto st317
		case 97: goto tr499
		case 99: goto tr500
		case 100: goto tr501
		case 104: goto tr502
		case 105: goto tr503
		case 109: goto tr504
		case 110: goto tr505
		case 114: goto tr506
		case 115: goto tr507
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr499:
// line 28 "zparse.rl"
	{ mark = p }
	goto st320
st320:
	p++
	if p == pe { goto _test_eof320 }
	fallthrough
case 320:
// line 4412 "zparse.go"
	switch data[p] {
		case 9: goto tr659
		case 32: goto tr660
		case 46: goto st317
		case 78: goto st825
		case 92: goto st317
		case 110: goto st825
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr660:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st321
st321:
	p++
	if p == pe { goto _test_eof321 }
	fallthrough
case 321:
// line 4446 "zparse.go"
	switch data[p] {
		case 9: goto tr662
		case 32: goto st321
		case 46: goto tr471
		case 92: goto tr471
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr471 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr471 }
	} else {
		goto tr471
	}
	goto st0
tr471:
// line 28 "zparse.rl"
	{ mark = p }
	goto st322
st322:
	p++
	if p == pe { goto _test_eof322 }
	fallthrough
case 322:
// line 4470 "zparse.go"
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 92: goto st322
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
tr665:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st323
tr685:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st323
tr1000:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st323
tr1009:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st323
tr1017:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st323
tr1024:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st323
tr1058:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st323
tr1068:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st323
tr1146:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st323
tr1198:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st323
tr1205:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st323
st323:
	p++
	if p == pe { goto _test_eof323 }
	fallthrough
case 323:
// line 4605 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st323
		case 46: goto st317
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto st317
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr159 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr160:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st324
st324:
	p++
	if p == pe { goto _test_eof324 }
	fallthrough
case 324:
// line 4649 "zparse.go"
	switch data[p] {
		case 9: goto tr659
		case 32: goto tr660
		case 46: goto st317
		case 78: goto st325
		case 92: goto st317
		case 110: goto st325
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st325:
	p++
	if p == pe { goto _test_eof325 }
	fallthrough
case 325:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 89: goto st326
		case 92: goto st317
		case 121: goto st326
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st326:
	p++
	if p == pe { goto _test_eof326 }
	fallthrough
case 326:
	switch data[p] {
		case 9: goto tr670
		case 32: goto tr671
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr671:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st327
st327:
	p++
	if p == pe { goto _test_eof327 }
	fallthrough
case 327:
// line 4715 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st327
		case 46: goto st317
		case 65: goto tr514
		case 67: goto tr515
		case 68: goto tr501
		case 77: goto tr504
		case 78: goto tr516
		case 82: goto tr506
		case 83: goto tr507
		case 92: goto st317
		case 97: goto tr514
		case 99: goto tr515
		case 100: goto tr501
		case 109: goto tr504
		case 110: goto tr516
		case 114: goto tr506
		case 115: goto tr507
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr513 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr513:
// line 28 "zparse.rl"
	{ mark = p }
	goto st328
st328:
	p++
	if p == pe { goto _test_eof328 }
	fallthrough
case 328:
// line 4753 "zparse.go"
	switch data[p] {
		case 9: goto tr655
		case 32: goto tr673
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st328 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr673:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st329
tr1045:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st329
st329:
	p++
	if p == pe { goto _test_eof329 }
	fallthrough
case 329:
// line 4781 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st329
		case 46: goto st317
		case 65: goto tr514
		case 67: goto tr515
		case 68: goto tr501
		case 77: goto tr504
		case 78: goto tr516
		case 82: goto tr506
		case 83: goto tr507
		case 92: goto st317
		case 97: goto tr514
		case 99: goto tr515
		case 100: goto tr501
		case 109: goto tr504
		case 110: goto tr516
		case 114: goto tr506
		case 115: goto tr507
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr514:
// line 28 "zparse.rl"
	{ mark = p }
	goto st330
st330:
	p++
	if p == pe { goto _test_eof330 }
	fallthrough
case 330:
// line 4819 "zparse.go"
	switch data[p] {
		case 9: goto tr659
		case 32: goto tr660
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr515:
// line 28 "zparse.rl"
	{ mark = p }
	goto st331
st331:
	p++
	if p == pe { goto _test_eof331 }
	fallthrough
case 331:
// line 4843 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 78: goto st332
		case 92: goto st317
		case 110: goto st332
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st332:
	p++
	if p == pe { goto _test_eof332 }
	fallthrough
case 332:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 65: goto st333
		case 92: goto st317
		case 97: goto st333
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st333:
	p++
	if p == pe { goto _test_eof333 }
	fallthrough
case 333:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 77: goto st334
		case 92: goto st317
		case 109: goto st334
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st334:
	p++
	if p == pe { goto _test_eof334 }
	fallthrough
case 334:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 69: goto st335
		case 92: goto st317
		case 101: goto st335
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st335:
	p++
	if p == pe { goto _test_eof335 }
	fallthrough
case 335:
	switch data[p] {
		case 9: goto tr680
		case 32: goto tr681
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr681:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st336
st336:
	p++
	if p == pe { goto _test_eof336 }
	fallthrough
case 336:
// line 4959 "zparse.go"
	switch data[p] {
		case 9: goto tr682
		case 32: goto st336
		case 46: goto tr524
		case 92: goto tr524
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr524 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr524 }
	} else {
		goto tr524
	}
	goto st0
tr524:
// line 28 "zparse.rl"
	{ mark = p }
	goto st337
st337:
	p++
	if p == pe { goto _test_eof337 }
	fallthrough
case 337:
// line 4983 "zparse.go"
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 92: goto st337
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
tr162:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st338
tr501:
// line 28 "zparse.rl"
	{ mark = p }
	goto st338
st338:
	p++
	if p == pe { goto _test_eof338 }
	fallthrough
case 338:
// line 5013 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 78: goto st339
		case 83: goto st823
		case 92: goto st317
		case 110: goto st339
		case 115: goto st823
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st339:
	p++
	if p == pe { goto _test_eof339 }
	fallthrough
case 339:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 83: goto st340
		case 92: goto st317
		case 115: goto st340
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st340:
	p++
	if p == pe { goto _test_eof340 }
	fallthrough
case 340:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 75: goto st341
		case 92: goto st317
		case 107: goto st341
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st341:
	p++
	if p == pe { goto _test_eof341 }
	fallthrough
case 341:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 69: goto st342
		case 92: goto st317
		case 101: goto st342
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st342:
	p++
	if p == pe { goto _test_eof342 }
	fallthrough
case 342:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 89: goto st343
		case 92: goto st317
		case 121: goto st343
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st343:
	p++
	if p == pe { goto _test_eof343 }
	fallthrough
case 343:
	switch data[p] {
		case 9: goto tr693
		case 32: goto tr694
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr694:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st344
st344:
	p++
	if p == pe { goto _test_eof344 }
	fallthrough
case 344:
// line 5152 "zparse.go"
	switch data[p] {
		case 9: goto tr695
		case 32: goto st344
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr546 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr546:
// line 28 "zparse.rl"
	{ mark = p }
	goto st345
st345:
	p++
	if p == pe { goto _test_eof345 }
	fallthrough
case 345:
// line 5176 "zparse.go"
	switch data[p] {
		case 9: goto tr697
		case 32: goto tr698
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st345 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr753:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st72
tr700:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st72
tr697:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st72
tr750:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st72
tr822:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st72
tr819:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st72
tr1040:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st72
st72:
	p++
	if p == pe { goto _test_eof72 }
	fallthrough
case 72:
// line 5305 "zparse.go"
	switch data[p] {
		case 9: goto st72
		case 32: goto st72
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr170 }
	goto st0
tr170:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st73
st73:
	p++
	if p == pe { goto _test_eof73 }
	fallthrough
case 73:
// line 5341 "zparse.go"
	switch data[p] {
		case 9: goto tr171
		case 32: goto tr171
	}
	if 48 <= data[p] && data[p] <= 57 { goto st73 }
	goto st0
tr171:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st74
st74:
	p++
	if p == pe { goto _test_eof74 }
	fallthrough
case 74:
// line 5359 "zparse.go"
	switch data[p] {
		case 9: goto st74
		case 32: goto st74
		case 65: goto tr16
		case 67: goto tr17
		case 68: goto tr18
		case 72: goto tr19
		case 73: goto tr20
		case 77: goto tr21
		case 78: goto tr22
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr16
		case 99: goto tr17
		case 100: goto tr18
		case 104: goto tr19
		case 105: goto tr20
		case 109: goto tr21
		case 110: goto tr22
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr58 }
	goto st0
tr12:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st75
tr24:
// line 28 "zparse.rl"
	{ mark = p }
	goto st75
st75:
	p++
	if p == pe { goto _test_eof75 }
	fallthrough
case 75:
// line 5399 "zparse.go"
	switch data[p] {
		case 79: goto st76
		case 111: goto st76
	}
	goto st0
st76:
	p++
	if p == pe { goto _test_eof76 }
	fallthrough
case 76:
	switch data[p] {
		case 65: goto st77
		case 97: goto st77
	}
	goto st0
st77:
	p++
	if p == pe { goto _test_eof77 }
	fallthrough
case 77:
	switch data[p] {
		case 9: goto tr176
		case 32: goto tr176
	}
	goto st0
tr178:
// line 28 "zparse.rl"
	{ mark = p }
	goto st78
tr176:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st78
st78:
	p++
	if p == pe { goto _test_eof78 }
	fallthrough
case 78:
// line 5446 "zparse.go"
	switch data[p] {
		case 9: goto st78
		case 32: goto tr178
		case 46: goto tr179
		case 92: goto tr179
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr179 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr179 }
	} else {
		goto tr179
	}
	goto st0
tr179:
// line 28 "zparse.rl"
	{ mark = p }
	goto st79
st79:
	p++
	if p == pe { goto _test_eof79 }
	fallthrough
case 79:
// line 5470 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr4:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st80
st80:
	p++
	if p == pe { goto _test_eof80 }
	fallthrough
case 80:
// line 5495 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr25
		case 78: goto st81
		case 110: goto st81
	}
	goto st0
st81:
	p++
	if p == pe { goto _test_eof81 }
	fallthrough
case 81:
	switch data[p] {
		case 89: goto st82
		case 121: goto st82
	}
	goto st0
st82:
	p++
	if p == pe { goto _test_eof82 }
	fallthrough
case 82:
	switch data[p] {
		case 9: goto tr183
		case 32: goto tr183
	}
	goto st0
tr183:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st83
st83:
	p++
	if p == pe { goto _test_eof83 }
	fallthrough
case 83:
// line 5532 "zparse.go"
	switch data[p] {
		case 9: goto st83
		case 32: goto st83
		case 65: goto tr32
		case 67: goto tr33
		case 68: goto tr18
		case 77: goto tr21
		case 78: goto tr34
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr32
		case 99: goto tr33
		case 100: goto tr18
		case 109: goto tr21
		case 110: goto tr34
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr185 }
	goto st0
tr185:
// line 28 "zparse.rl"
	{ mark = p }
	goto st84
st84:
	p++
	if p == pe { goto _test_eof84 }
	fallthrough
case 84:
// line 5562 "zparse.go"
	switch data[p] {
		case 9: goto tr186
		case 32: goto tr186
	}
	if 48 <= data[p] && data[p] <= 57 { goto st84 }
	goto st0
tr34:
// line 28 "zparse.rl"
	{ mark = p }
	goto st85
st85:
	p++
	if p == pe { goto _test_eof85 }
	fallthrough
case 85:
// line 5578 "zparse.go"
	switch data[p] {
		case 83: goto st47
		case 115: goto st47
	}
	goto st0
tr5:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st86
st86:
	p++
	if p == pe { goto _test_eof86 }
	fallthrough
case 86:
// line 5595 "zparse.go"
	switch data[p] {
		case 72: goto st82
		case 78: goto st12
		case 83: goto st82
		case 104: goto st82
		case 110: goto st12
		case 115: goto st82
	}
	goto st0
tr7:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st87
st87:
	p++
	if p == pe { goto _test_eof87 }
	fallthrough
case 87:
// line 5616 "zparse.go"
	switch data[p] {
		case 83: goto st82
		case 115: goto st82
	}
	goto st0
tr8:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st88
st88:
	p++
	if p == pe { goto _test_eof88 }
	fallthrough
case 88:
// line 5633 "zparse.go"
	switch data[p] {
		case 78: goto st82
		case 110: goto st82
	}
	goto st0
tr10:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st89
st89:
	p++
	if p == pe { goto _test_eof89 }
	fallthrough
case 89:
// line 5650 "zparse.go"
	switch data[p] {
		case 79: goto st90
		case 83: goto st47
		case 111: goto st90
		case 115: goto st47
	}
	goto st0
st90:
	p++
	if p == pe { goto _test_eof90 }
	fallthrough
case 90:
	switch data[p] {
		case 78: goto st91
		case 110: goto st91
	}
	goto st0
st91:
	p++
	if p == pe { goto _test_eof91 }
	fallthrough
case 91:
	switch data[p] {
		case 69: goto st82
		case 101: goto st82
	}
	goto st0
tr698:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st346
st346:
	p++
	if p == pe { goto _test_eof346 }
	fallthrough
case 346:
// line 5687 "zparse.go"
	switch data[p] {
		case 9: goto tr700
		case 32: goto st346
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr702 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr702:
// line 28 "zparse.rl"
	{ mark = p }
	goto st347
st347:
	p++
	if p == pe { goto _test_eof347 }
	fallthrough
case 347:
// line 5711 "zparse.go"
	switch data[p] {
		case 9: goto tr703
		case 32: goto tr704
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st347 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr759:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st92
tr1460:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st92
tr703:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st92
tr756:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st92
tr828:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st92
tr825:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st92
st92:
	p++
	if p == pe { goto _test_eof92 }
	fallthrough
case 92:
// line 5819 "zparse.go"
	switch data[p] {
		case 9: goto st92
		case 32: goto st92
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr191 }
	goto st0
tr191:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st93
st93:
	p++
	if p == pe { goto _test_eof93 }
	fallthrough
case 93:
// line 5855 "zparse.go"
	switch data[p] {
		case 9: goto tr192
		case 32: goto tr192
	}
	if 48 <= data[p] && data[p] <= 57 { goto st93 }
	goto st0
tr192:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st94
st94:
	p++
	if p == pe { goto _test_eof94 }
	fallthrough
case 94:
// line 5873 "zparse.go"
	switch data[p] {
		case 9: goto st94
		case 32: goto tr195
		case 46: goto tr63
		case 65: goto tr196
		case 67: goto tr197
		case 68: goto tr198
		case 72: goto tr199
		case 73: goto tr200
		case 77: goto tr201
		case 78: goto tr202
		case 82: goto tr203
		case 83: goto tr204
		case 92: goto tr63
		case 97: goto tr196
		case 99: goto tr197
		case 100: goto tr198
		case 104: goto tr199
		case 105: goto tr200
		case 109: goto tr201
		case 110: goto tr202
		case 114: goto tr203
		case 115: goto tr204
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr63 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr63 }
	} else {
		goto tr63
	}
	goto st0
tr195:
// line 28 "zparse.rl"
	{ mark = p }
	goto st348
st348:
	p++
	if p == pe { goto _test_eof348 }
	fallthrough
case 348:
// line 5915 "zparse.go"
	switch data[p] {
		case 9: goto tr609
		case 32: goto tr195
		case 46: goto tr63
		case 65: goto tr196
		case 67: goto tr197
		case 68: goto tr198
		case 72: goto tr199
		case 73: goto tr200
		case 77: goto tr201
		case 78: goto tr202
		case 82: goto tr203
		case 83: goto tr204
		case 92: goto tr63
		case 97: goto tr196
		case 99: goto tr197
		case 100: goto tr198
		case 104: goto tr199
		case 105: goto tr200
		case 109: goto tr201
		case 110: goto tr202
		case 114: goto tr203
		case 115: goto tr204
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr63 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr63 }
	} else {
		goto tr63
	}
	goto st0
tr197:
// line 28 "zparse.rl"
	{ mark = p }
	goto st349
st349:
	p++
	if p == pe { goto _test_eof349 }
	fallthrough
case 349:
// line 5957 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 72: goto st350
		case 78: goto st362
		case 83: goto st350
		case 92: goto st285
		case 104: goto st350
		case 110: goto st362
		case 115: goto st350
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st350:
	p++
	if p == pe { goto _test_eof350 }
	fallthrough
case 350:
	switch data[p] {
		case 9: goto tr708
		case 32: goto tr709
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr726:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st351
tr709:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st351
st351:
	p++
	if p == pe { goto _test_eof351 }
	fallthrough
case 351:
// line 6010 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st351
		case 46: goto st285
		case 65: goto tr711
		case 67: goto tr712
		case 68: goto tr198
		case 77: goto tr201
		case 78: goto tr713
		case 82: goto tr203
		case 83: goto tr204
		case 92: goto st285
		case 97: goto tr711
		case 99: goto tr712
		case 100: goto tr198
		case 109: goto tr201
		case 110: goto tr713
		case 114: goto tr203
		case 115: goto tr204
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr711:
// line 28 "zparse.rl"
	{ mark = p }
	goto st352
st352:
	p++
	if p == pe { goto _test_eof352 }
	fallthrough
case 352:
// line 6048 "zparse.go"
	switch data[p] {
		case 9: goto tr616
		case 32: goto tr617
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr617:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st353
st353:
	p++
	if p == pe { goto _test_eof353 }
	fallthrough
case 353:
// line 6080 "zparse.go"
	switch data[p] {
		case 9: goto tr714
		case 32: goto st353
		case 46: goto tr716
		case 92: goto tr716
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr716 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr716 }
	} else {
		goto tr716
	}
	goto st0
tr716:
// line 28 "zparse.rl"
	{ mark = p }
	goto st354
st354:
	p++
	if p == pe { goto _test_eof354 }
	fallthrough
case 354:
// line 6104 "zparse.go"
	switch data[p] {
		case 9: goto tr717
		case 32: goto tr718
		case 46: goto st354
		case 92: goto st354
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st354 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st354 }
	} else {
		goto st354
	}
	goto st0
tr718:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st355
tr737:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st355
tr1379:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st355
tr1388:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st355
st355:
	p++
	if p == pe { goto _test_eof355 }
	fallthrough
case 355:
// line 6161 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st355
		case 46: goto st285
		case 65: goto tr67
		case 67: goto tr68
		case 68: goto tr69
		case 72: goto tr70
		case 73: goto tr71
		case 77: goto tr72
		case 78: goto tr73
		case 82: goto tr74
		case 83: goto tr75
		case 92: goto st285
		case 97: goto tr67
		case 99: goto tr68
		case 100: goto tr69
		case 104: goto tr70
		case 105: goto tr71
		case 109: goto tr72
		case 110: goto tr73
		case 114: goto tr74
		case 115: goto tr75
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr66 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr67:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st356
st356:
	p++
	if p == pe { goto _test_eof356 }
	fallthrough
case 356:
// line 6205 "zparse.go"
	switch data[p] {
		case 9: goto tr616
		case 32: goto tr617
		case 46: goto st285
		case 78: goto st357
		case 92: goto st285
		case 110: goto st357
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st357:
	p++
	if p == pe { goto _test_eof357 }
	fallthrough
case 357:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 89: goto st358
		case 92: goto st285
		case 121: goto st358
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st358:
	p++
	if p == pe { goto _test_eof358 }
	fallthrough
case 358:
	switch data[p] {
		case 9: goto tr708
		case 32: goto tr723
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr723:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st359
st359:
	p++
	if p == pe { goto _test_eof359 }
	fallthrough
case 359:
// line 6271 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st359
		case 46: goto st285
		case 65: goto tr711
		case 67: goto tr712
		case 68: goto tr198
		case 77: goto tr201
		case 78: goto tr713
		case 82: goto tr203
		case 83: goto tr204
		case 92: goto st285
		case 97: goto tr711
		case 99: goto tr712
		case 100: goto tr198
		case 109: goto tr201
		case 110: goto tr713
		case 114: goto tr203
		case 115: goto tr204
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr725 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr725:
// line 28 "zparse.rl"
	{ mark = p }
	goto st360
st360:
	p++
	if p == pe { goto _test_eof360 }
	fallthrough
case 360:
// line 6309 "zparse.go"
	switch data[p] {
		case 9: goto tr612
		case 32: goto tr726
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st360 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr712:
// line 28 "zparse.rl"
	{ mark = p }
	goto st361
st361:
	p++
	if p == pe { goto _test_eof361 }
	fallthrough
case 361:
// line 6333 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 78: goto st362
		case 92: goto st285
		case 110: goto st362
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st362:
	p++
	if p == pe { goto _test_eof362 }
	fallthrough
case 362:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 65: goto st363
		case 92: goto st285
		case 97: goto st363
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st363:
	p++
	if p == pe { goto _test_eof363 }
	fallthrough
case 363:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 77: goto st364
		case 92: goto st285
		case 109: goto st364
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st364:
	p++
	if p == pe { goto _test_eof364 }
	fallthrough
case 364:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 69: goto st365
		case 92: goto st285
		case 101: goto st365
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st365:
	p++
	if p == pe { goto _test_eof365 }
	fallthrough
case 365:
	switch data[p] {
		case 9: goto tr731
		case 32: goto tr732
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr732:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st366
st366:
	p++
	if p == pe { goto _test_eof366 }
	fallthrough
case 366:
// line 6449 "zparse.go"
	switch data[p] {
		case 9: goto tr733
		case 32: goto st366
		case 46: goto tr735
		case 92: goto tr735
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr735 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr735 }
	} else {
		goto tr735
	}
	goto st0
tr735:
// line 28 "zparse.rl"
	{ mark = p }
	goto st367
st367:
	p++
	if p == pe { goto _test_eof367 }
	fallthrough
case 367:
// line 6473 "zparse.go"
	switch data[p] {
		case 9: goto tr736
		case 32: goto tr737
		case 46: goto st367
		case 92: goto st367
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st367 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st367 }
	} else {
		goto st367
	}
	goto st0
tr69:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st368
tr198:
// line 28 "zparse.rl"
	{ mark = p }
	goto st368
st368:
	p++
	if p == pe { goto _test_eof368 }
	fallthrough
case 368:
// line 6503 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 78: goto st369
		case 83: goto st380
		case 92: goto st285
		case 110: goto st369
		case 115: goto st380
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st369:
	p++
	if p == pe { goto _test_eof369 }
	fallthrough
case 369:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 83: goto st370
		case 92: goto st285
		case 115: goto st370
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st370:
	p++
	if p == pe { goto _test_eof370 }
	fallthrough
case 370:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 75: goto st371
		case 92: goto st285
		case 107: goto st371
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st371:
	p++
	if p == pe { goto _test_eof371 }
	fallthrough
case 371:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 69: goto st372
		case 92: goto st285
		case 101: goto st372
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st372:
	p++
	if p == pe { goto _test_eof372 }
	fallthrough
case 372:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 89: goto st373
		case 92: goto st285
		case 121: goto st373
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st373:
	p++
	if p == pe { goto _test_eof373 }
	fallthrough
case 373:
	switch data[p] {
		case 9: goto tr745
		case 32: goto tr746
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr746:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st374
st374:
	p++
	if p == pe { goto _test_eof374 }
	fallthrough
case 374:
// line 6642 "zparse.go"
	switch data[p] {
		case 9: goto tr747
		case 32: goto st374
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr749 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr749:
// line 28 "zparse.rl"
	{ mark = p }
	goto st375
st375:
	p++
	if p == pe { goto _test_eof375 }
	fallthrough
case 375:
// line 6666 "zparse.go"
	switch data[p] {
		case 9: goto tr750
		case 32: goto tr751
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st375 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr751:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st376
st376:
	p++
	if p == pe { goto _test_eof376 }
	fallthrough
case 376:
// line 6690 "zparse.go"
	switch data[p] {
		case 9: goto tr753
		case 32: goto st376
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr755 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr755:
// line 28 "zparse.rl"
	{ mark = p }
	goto st377
st377:
	p++
	if p == pe { goto _test_eof377 }
	fallthrough
case 377:
// line 6714 "zparse.go"
	switch data[p] {
		case 9: goto tr756
		case 32: goto tr757
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st377 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr757:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st378
st378:
	p++
	if p == pe { goto _test_eof378 }
	fallthrough
case 378:
// line 6738 "zparse.go"
	switch data[p] {
		case 9: goto tr759
		case 32: goto st378
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr761 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr761:
// line 28 "zparse.rl"
	{ mark = p }
	goto st379
st379:
	p++
	if p == pe { goto _test_eof379 }
	fallthrough
case 379:
// line 6762 "zparse.go"
	switch data[p] {
		case 9: goto tr762
		case 32: goto tr763
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st379 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st380:
	p++
	if p == pe { goto _test_eof380 }
	fallthrough
case 380:
	switch data[p] {
		case 9: goto tr765
		case 32: goto tr766
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1345:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st95
tr765:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st95
tr1494:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st95
tr1472:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st95
tr1163:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st95
tr1469:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st95
tr842:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st95
tr840:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st95
tr875:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st95
tr900:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st95
tr1296:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st95
tr1286:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st95
tr1161:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st95
tr1220:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st95
st95:
	p++
	if p == pe { goto _test_eof95 }
	fallthrough
case 95:
// line 7127 "zparse.go"
	switch data[p] {
		case 9: goto st95
		case 32: goto st95
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr206 }
	goto st0
tr206:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st96
st96:
	p++
	if p == pe { goto _test_eof96 }
	fallthrough
case 96:
// line 7163 "zparse.go"
	switch data[p] {
		case 9: goto tr207
		case 32: goto tr207
	}
	if 48 <= data[p] && data[p] <= 57 { goto st96 }
	goto st0
tr207:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st97
st97:
	p++
	if p == pe { goto _test_eof97 }
	fallthrough
case 97:
// line 7181 "zparse.go"
	switch data[p] {
		case 9: goto st97
		case 32: goto st97
		case 65: goto tr16
		case 67: goto tr17
		case 68: goto tr18
		case 72: goto tr19
		case 73: goto tr20
		case 77: goto tr21
		case 78: goto tr22
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr16
		case 99: goto tr17
		case 100: goto tr18
		case 104: goto tr19
		case 105: goto tr20
		case 109: goto tr21
		case 110: goto tr22
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr210 }
	goto st0
tr210:
// line 28 "zparse.rl"
	{ mark = p }
	goto st98
st98:
	p++
	if p == pe { goto _test_eof98 }
	fallthrough
case 98:
// line 7215 "zparse.go"
	switch data[p] {
		case 9: goto tr211
		case 32: goto tr211
	}
	if 48 <= data[p] && data[p] <= 57 { goto st98 }
	goto st0
tr211:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st99
st99:
	p++
	if p == pe { goto _test_eof99 }
	fallthrough
case 99:
// line 7231 "zparse.go"
	switch data[p] {
		case 9: goto st99
		case 32: goto st99
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr214 }
	goto st0
tr214:
// line 28 "zparse.rl"
	{ mark = p }
	goto st100
st100:
	p++
	if p == pe { goto _test_eof100 }
	fallthrough
case 100:
// line 7247 "zparse.go"
	switch data[p] {
		case 9: goto tr215
		case 32: goto tr215
	}
	if 48 <= data[p] && data[p] <= 57 { goto st100 }
	goto st0
tr215:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st101
st101:
	p++
	if p == pe { goto _test_eof101 }
	fallthrough
case 101:
// line 7263 "zparse.go"
	switch data[p] {
		case 9: goto st101
		case 32: goto tr218
		case 46: goto tr219
		case 92: goto tr219
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr219 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr219 }
	} else {
		goto tr219
	}
	goto st0
tr218:
// line 28 "zparse.rl"
	{ mark = p }
	goto st381
tr1341:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st381
st381:
	p++
	if p == pe { goto _test_eof381 }
	fallthrough
case 381:
// line 7291 "zparse.go"
	switch data[p] {
		case 9: goto tr767
		case 32: goto tr218
		case 46: goto tr219
		case 92: goto tr219
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr219 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr219 }
	} else {
		goto tr219
	}
	goto st0
tr1363:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st102
tr1180:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st102
tr1177:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st102
tr1360:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st102
tr767:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st102
tr1365:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st102
tr1340:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st102
tr1183:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st102
st102:
	p++
	if p == pe { goto _test_eof102 }
	fallthrough
case 102:
// line 7444 "zparse.go"
	switch data[p] {
		case 9: goto st102
		case 32: goto tr221
		case 46: goto tr219
		case 65: goto tr223
		case 67: goto tr224
		case 68: goto tr225
		case 72: goto tr226
		case 73: goto tr227
		case 77: goto tr228
		case 78: goto tr229
		case 82: goto tr230
		case 83: goto tr231
		case 92: goto tr219
		case 97: goto tr223
		case 99: goto tr224
		case 100: goto tr225
		case 104: goto tr226
		case 105: goto tr227
		case 109: goto tr228
		case 110: goto tr229
		case 114: goto tr230
		case 115: goto tr231
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr222 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr219 }
	} else {
		goto tr219
	}
	goto st0
tr221:
// line 28 "zparse.rl"
	{ mark = p }
	goto st382
st382:
	p++
	if p == pe { goto _test_eof382 }
	fallthrough
case 382:
// line 7486 "zparse.go"
	switch data[p] {
		case 9: goto tr767
		case 32: goto tr221
		case 46: goto tr219
		case 65: goto tr223
		case 67: goto tr224
		case 68: goto tr225
		case 72: goto tr226
		case 73: goto tr227
		case 77: goto tr228
		case 78: goto tr229
		case 82: goto tr230
		case 83: goto tr231
		case 92: goto tr219
		case 97: goto tr223
		case 99: goto tr224
		case 100: goto tr225
		case 104: goto tr226
		case 105: goto tr227
		case 109: goto tr228
		case 110: goto tr229
		case 114: goto tr230
		case 115: goto tr231
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr222 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr219 }
	} else {
		goto tr219
	}
	goto st0
tr219:
// line 28 "zparse.rl"
	{ mark = p }
	goto st383
st383:
	p++
	if p == pe { goto _test_eof383 }
	fallthrough
case 383:
// line 7528 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr222:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st384
st384:
	p++
	if p == pe { goto _test_eof384 }
	fallthrough
case 384:
// line 7554 "zparse.go"
	switch data[p] {
		case 9: goto tr770
		case 32: goto tr771
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st384 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr771:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st385
st385:
	p++
	if p == pe { goto _test_eof385 }
	fallthrough
case 385:
// line 7578 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st385
		case 46: goto st383
		case 65: goto tr243
		case 67: goto tr244
		case 68: goto tr245
		case 72: goto tr246
		case 73: goto tr247
		case 77: goto tr248
		case 78: goto tr249
		case 82: goto tr250
		case 83: goto tr251
		case 92: goto st383
		case 97: goto tr243
		case 99: goto tr244
		case 100: goto tr245
		case 104: goto tr246
		case 105: goto tr247
		case 109: goto tr248
		case 110: goto tr249
		case 114: goto tr250
		case 115: goto tr251
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr243:
// line 28 "zparse.rl"
	{ mark = p }
	goto st386
st386:
	p++
	if p == pe { goto _test_eof386 }
	fallthrough
case 386:
// line 7620 "zparse.go"
	switch data[p] {
		case 9: goto tr774
		case 32: goto tr775
		case 46: goto st383
		case 78: goto st761
		case 92: goto st383
		case 110: goto st761
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr775:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st387
st387:
	p++
	if p == pe { goto _test_eof387 }
	fallthrough
case 387:
// line 7654 "zparse.go"
	switch data[p] {
		case 9: goto tr777
		case 32: goto st387
		case 46: goto tr779
		case 92: goto tr779
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr779 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr779 }
	} else {
		goto tr779
	}
	goto st0
tr779:
// line 28 "zparse.rl"
	{ mark = p }
	goto st388
st388:
	p++
	if p == pe { goto _test_eof388 }
	fallthrough
case 388:
// line 7678 "zparse.go"
	switch data[p] {
		case 9: goto tr780
		case 32: goto tr781
		case 46: goto st388
		case 92: goto st388
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st388 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st388 }
	} else {
		goto st388
	}
	goto st0
tr781:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st389
tr806:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st389
tr943:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st389
tr954:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st389
st389:
	p++
	if p == pe { goto _test_eof389 }
	fallthrough
case 389:
// line 7735 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st389
		case 46: goto st383
		case 65: goto tr223
		case 67: goto tr224
		case 68: goto tr225
		case 72: goto tr226
		case 73: goto tr227
		case 77: goto tr228
		case 78: goto tr229
		case 82: goto tr230
		case 83: goto tr231
		case 92: goto st383
		case 97: goto tr223
		case 99: goto tr224
		case 100: goto tr225
		case 104: goto tr226
		case 105: goto tr227
		case 109: goto tr228
		case 110: goto tr229
		case 114: goto tr230
		case 115: goto tr231
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr222 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr223:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st390
st390:
	p++
	if p == pe { goto _test_eof390 }
	fallthrough
case 390:
// line 7779 "zparse.go"
	switch data[p] {
		case 9: goto tr774
		case 32: goto tr775
		case 46: goto st383
		case 78: goto st391
		case 92: goto st383
		case 110: goto st391
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st391:
	p++
	if p == pe { goto _test_eof391 }
	fallthrough
case 391:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 89: goto st392
		case 92: goto st383
		case 121: goto st392
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st392:
	p++
	if p == pe { goto _test_eof392 }
	fallthrough
case 392:
	switch data[p] {
		case 9: goto tr786
		case 32: goto tr787
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr787:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st393
st393:
	p++
	if p == pe { goto _test_eof393 }
	fallthrough
case 393:
// line 7845 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st393
		case 46: goto st383
		case 65: goto tr790
		case 67: goto tr791
		case 68: goto tr245
		case 77: goto tr248
		case 78: goto tr792
		case 82: goto tr250
		case 83: goto tr251
		case 92: goto st383
		case 97: goto tr790
		case 99: goto tr791
		case 100: goto tr245
		case 109: goto tr248
		case 110: goto tr792
		case 114: goto tr250
		case 115: goto tr251
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr789 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr789:
// line 28 "zparse.rl"
	{ mark = p }
	goto st394
st394:
	p++
	if p == pe { goto _test_eof394 }
	fallthrough
case 394:
// line 7883 "zparse.go"
	switch data[p] {
		case 9: goto tr770
		case 32: goto tr793
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st394 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr793:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st395
tr855:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st395
st395:
	p++
	if p == pe { goto _test_eof395 }
	fallthrough
case 395:
// line 7911 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st395
		case 46: goto st383
		case 65: goto tr790
		case 67: goto tr791
		case 68: goto tr245
		case 77: goto tr248
		case 78: goto tr792
		case 82: goto tr250
		case 83: goto tr251
		case 92: goto st383
		case 97: goto tr790
		case 99: goto tr791
		case 100: goto tr245
		case 109: goto tr248
		case 110: goto tr792
		case 114: goto tr250
		case 115: goto tr251
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr790:
// line 28 "zparse.rl"
	{ mark = p }
	goto st396
st396:
	p++
	if p == pe { goto _test_eof396 }
	fallthrough
case 396:
// line 7949 "zparse.go"
	switch data[p] {
		case 9: goto tr774
		case 32: goto tr775
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr791:
// line 28 "zparse.rl"
	{ mark = p }
	goto st397
st397:
	p++
	if p == pe { goto _test_eof397 }
	fallthrough
case 397:
// line 7973 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 78: goto st398
		case 92: goto st383
		case 110: goto st398
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st398:
	p++
	if p == pe { goto _test_eof398 }
	fallthrough
case 398:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 65: goto st399
		case 92: goto st383
		case 97: goto st399
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st399:
	p++
	if p == pe { goto _test_eof399 }
	fallthrough
case 399:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 77: goto st400
		case 92: goto st383
		case 109: goto st400
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st400:
	p++
	if p == pe { goto _test_eof400 }
	fallthrough
case 400:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 69: goto st401
		case 92: goto st383
		case 101: goto st401
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st401:
	p++
	if p == pe { goto _test_eof401 }
	fallthrough
case 401:
	switch data[p] {
		case 9: goto tr800
		case 32: goto tr801
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr801:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st402
st402:
	p++
	if p == pe { goto _test_eof402 }
	fallthrough
case 402:
// line 8089 "zparse.go"
	switch data[p] {
		case 9: goto tr802
		case 32: goto st402
		case 46: goto tr804
		case 92: goto tr804
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr804 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr804 }
	} else {
		goto tr804
	}
	goto st0
tr804:
// line 28 "zparse.rl"
	{ mark = p }
	goto st403
st403:
	p++
	if p == pe { goto _test_eof403 }
	fallthrough
case 403:
// line 8113 "zparse.go"
	switch data[p] {
		case 9: goto tr805
		case 32: goto tr806
		case 46: goto st403
		case 92: goto st403
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st403 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st403 }
	} else {
		goto st403
	}
	goto st0
tr225:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st404
tr245:
// line 28 "zparse.rl"
	{ mark = p }
	goto st404
st404:
	p++
	if p == pe { goto _test_eof404 }
	fallthrough
case 404:
// line 8143 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 78: goto st405
		case 83: goto st419
		case 92: goto st383
		case 110: goto st405
		case 115: goto st419
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st405:
	p++
	if p == pe { goto _test_eof405 }
	fallthrough
case 405:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 83: goto st406
		case 92: goto st383
		case 115: goto st406
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st406:
	p++
	if p == pe { goto _test_eof406 }
	fallthrough
case 406:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 75: goto st407
		case 92: goto st383
		case 107: goto st407
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st407:
	p++
	if p == pe { goto _test_eof407 }
	fallthrough
case 407:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 69: goto st408
		case 92: goto st383
		case 101: goto st408
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st408:
	p++
	if p == pe { goto _test_eof408 }
	fallthrough
case 408:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 89: goto st409
		case 92: goto st383
		case 121: goto st409
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st409:
	p++
	if p == pe { goto _test_eof409 }
	fallthrough
case 409:
	switch data[p] {
		case 9: goto tr814
		case 32: goto tr815
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr815:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st410
st410:
	p++
	if p == pe { goto _test_eof410 }
	fallthrough
case 410:
// line 8282 "zparse.go"
	switch data[p] {
		case 9: goto tr816
		case 32: goto st410
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr818 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr818:
// line 28 "zparse.rl"
	{ mark = p }
	goto st411
st411:
	p++
	if p == pe { goto _test_eof411 }
	fallthrough
case 411:
// line 8306 "zparse.go"
	switch data[p] {
		case 9: goto tr819
		case 32: goto tr820
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st411 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr820:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st412
st412:
	p++
	if p == pe { goto _test_eof412 }
	fallthrough
case 412:
// line 8330 "zparse.go"
	switch data[p] {
		case 9: goto tr822
		case 32: goto st412
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr824 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr824:
// line 28 "zparse.rl"
	{ mark = p }
	goto st413
st413:
	p++
	if p == pe { goto _test_eof413 }
	fallthrough
case 413:
// line 8354 "zparse.go"
	switch data[p] {
		case 9: goto tr825
		case 32: goto tr826
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st413 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr826:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st414
st414:
	p++
	if p == pe { goto _test_eof414 }
	fallthrough
case 414:
// line 8378 "zparse.go"
	switch data[p] {
		case 9: goto tr828
		case 32: goto st414
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr830 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr830:
// line 28 "zparse.rl"
	{ mark = p }
	goto st415
st415:
	p++
	if p == pe { goto _test_eof415 }
	fallthrough
case 415:
// line 8402 "zparse.go"
	switch data[p] {
		case 9: goto tr831
		case 32: goto tr832
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st415 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr832:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st416
st416:
	p++
	if p == pe { goto _test_eof416 }
	fallthrough
case 416:
// line 8426 "zparse.go"
	switch data[p] {
		case 9: goto tr834
		case 32: goto tr835
		case 46: goto tr836
		case 92: goto tr836
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr836 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr836 }
	} else {
		goto tr836
	}
	goto st0
tr835:
// line 28 "zparse.rl"
	{ mark = p }
	goto st417
st417:
	p++
	if p == pe { goto _test_eof417 }
	fallthrough
case 417:
// line 8450 "zparse.go"
	switch data[p] {
		case 9: goto tr837
		case 32: goto tr835
		case 46: goto tr836
		case 92: goto tr836
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr836 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr836 }
	} else {
		goto tr836
	}
	goto st0
tr836:
// line 28 "zparse.rl"
	{ mark = p }
	goto st418
st418:
	p++
	if p == pe { goto _test_eof418 }
	fallthrough
case 418:
// line 8474 "zparse.go"
	switch data[p] {
		case 9: goto tr838
		case 32: goto st418
		case 46: goto st418
		case 92: goto st418
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st418 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st418 }
	} else {
		goto st418
	}
	goto st0
st419:
	p++
	if p == pe { goto _test_eof419 }
	fallthrough
case 419:
	switch data[p] {
		case 9: goto tr840
		case 32: goto tr841
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr841:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st420
st420:
	p++
	if p == pe { goto _test_eof420 }
	fallthrough
case 420:
// line 8525 "zparse.go"
	switch data[p] {
		case 9: goto tr842
		case 32: goto st420
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr844 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr844:
// line 28 "zparse.rl"
	{ mark = p }
	goto st421
st421:
	p++
	if p == pe { goto _test_eof421 }
	fallthrough
case 421:
// line 8549 "zparse.go"
	switch data[p] {
		case 9: goto tr845
		case 32: goto tr846
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st421 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1351:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st103
tr1168:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st103
tr1273:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st103
tr1348:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st103
tr848:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st103
tr845:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st103
tr1165:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st103
st103:
	p++
	if p == pe { goto _test_eof103 }
	fallthrough
case 103:
// line 8678 "zparse.go"
	switch data[p] {
		case 9: goto st103
		case 32: goto st103
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr233 }
	goto st0
tr233:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st104
st104:
	p++
	if p == pe { goto _test_eof104 }
	fallthrough
case 104:
// line 8714 "zparse.go"
	switch data[p] {
		case 9: goto tr234
		case 32: goto tr234
	}
	if 48 <= data[p] && data[p] <= 57 { goto st104 }
	goto st0
tr234:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st105
st105:
	p++
	if p == pe { goto _test_eof105 }
	fallthrough
case 105:
// line 8732 "zparse.go"
	switch data[p] {
		case 9: goto st105
		case 32: goto st105
		case 65: goto tr16
		case 67: goto tr17
		case 68: goto tr18
		case 72: goto tr19
		case 73: goto tr20
		case 77: goto tr21
		case 78: goto tr22
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr16
		case 99: goto tr17
		case 100: goto tr18
		case 104: goto tr19
		case 105: goto tr20
		case 109: goto tr21
		case 110: goto tr22
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr214 }
	goto st0
tr846:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st422
st422:
	p++
	if p == pe { goto _test_eof422 }
	fallthrough
case 422:
// line 8766 "zparse.go"
	switch data[p] {
		case 9: goto tr848
		case 32: goto st422
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr850 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr850:
// line 28 "zparse.rl"
	{ mark = p }
	goto st423
st423:
	p++
	if p == pe { goto _test_eof423 }
	fallthrough
case 423:
// line 8790 "zparse.go"
	switch data[p] {
		case 9: goto tr851
		case 32: goto tr852
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st423 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1357:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st106
tr1174:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st106
tr1171:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st106
tr1354:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st106
tr1337:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st106
tr851:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st106
st106:
	p++
	if p == pe { goto _test_eof106 }
	fallthrough
case 106:
// line 8898 "zparse.go"
	switch data[p] {
		case 9: goto st106
		case 32: goto st106
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr238 }
	goto st0
tr238:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st107
st107:
	p++
	if p == pe { goto _test_eof107 }
	fallthrough
case 107:
// line 8934 "zparse.go"
	switch data[p] {
		case 9: goto tr239
		case 32: goto tr239
	}
	if 48 <= data[p] && data[p] <= 57 { goto st107 }
	goto st0
tr239:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st108
st108:
	p++
	if p == pe { goto _test_eof108 }
	fallthrough
case 108:
// line 8952 "zparse.go"
	switch data[p] {
		case 9: goto st108
		case 32: goto tr242
		case 46: goto tr219
		case 65: goto tr243
		case 67: goto tr244
		case 68: goto tr245
		case 72: goto tr246
		case 73: goto tr247
		case 77: goto tr248
		case 78: goto tr249
		case 82: goto tr250
		case 83: goto tr251
		case 92: goto tr219
		case 97: goto tr243
		case 99: goto tr244
		case 100: goto tr245
		case 104: goto tr246
		case 105: goto tr247
		case 109: goto tr248
		case 110: goto tr249
		case 114: goto tr250
		case 115: goto tr251
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr219 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr219 }
	} else {
		goto tr219
	}
	goto st0
tr242:
// line 28 "zparse.rl"
	{ mark = p }
	goto st424
st424:
	p++
	if p == pe { goto _test_eof424 }
	fallthrough
case 424:
// line 8994 "zparse.go"
	switch data[p] {
		case 9: goto tr767
		case 32: goto tr242
		case 46: goto tr219
		case 65: goto tr243
		case 67: goto tr244
		case 68: goto tr245
		case 72: goto tr246
		case 73: goto tr247
		case 77: goto tr248
		case 78: goto tr249
		case 82: goto tr250
		case 83: goto tr251
		case 92: goto tr219
		case 97: goto tr243
		case 99: goto tr244
		case 100: goto tr245
		case 104: goto tr246
		case 105: goto tr247
		case 109: goto tr248
		case 110: goto tr249
		case 114: goto tr250
		case 115: goto tr251
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr219 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr219 }
	} else {
		goto tr219
	}
	goto st0
tr244:
// line 28 "zparse.rl"
	{ mark = p }
	goto st425
st425:
	p++
	if p == pe { goto _test_eof425 }
	fallthrough
case 425:
// line 9036 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 72: goto st426
		case 78: goto st398
		case 83: goto st426
		case 92: goto st383
		case 104: goto st426
		case 110: goto st398
		case 115: goto st426
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st426:
	p++
	if p == pe { goto _test_eof426 }
	fallthrough
case 426:
	switch data[p] {
		case 9: goto tr786
		case 32: goto tr855
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr246:
// line 28 "zparse.rl"
	{ mark = p }
	goto st427
st427:
	p++
	if p == pe { goto _test_eof427 }
	fallthrough
case 427:
// line 9085 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 83: goto st426
		case 92: goto st383
		case 115: goto st426
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr247:
// line 28 "zparse.rl"
	{ mark = p }
	goto st428
st428:
	p++
	if p == pe { goto _test_eof428 }
	fallthrough
case 428:
// line 9111 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 78: goto st426
		case 92: goto st383
		case 110: goto st426
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr228:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st429
tr248:
// line 28 "zparse.rl"
	{ mark = p }
	goto st429
st429:
	p++
	if p == pe { goto _test_eof429 }
	fallthrough
case 429:
// line 9143 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 88: goto st430
		case 92: goto st383
		case 120: goto st430
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st430:
	p++
	if p == pe { goto _test_eof430 }
	fallthrough
case 430:
	switch data[p] {
		case 9: goto tr857
		case 32: goto tr858
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1369:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st109
tr1367:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st109
tr1496:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st109
tr1474:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st109
tr1049:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st109
tr1047:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st109
tr931:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st109
tr857:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st109
tr877:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st109
tr902:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st109
tr1299:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st109
tr1125:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st109
tr1189:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st109
tr1223:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st109
st109:
	p++
	if p == pe { goto _test_eof109 }
	fallthrough
case 109:
// line 9510 "zparse.go"
	switch data[p] {
		case 9: goto st109
		case 32: goto st109
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr253 }
	goto st0
tr253:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st110
st110:
	p++
	if p == pe { goto _test_eof110 }
	fallthrough
case 110:
// line 9546 "zparse.go"
	switch data[p] {
		case 9: goto tr254
		case 32: goto tr254
	}
	if 48 <= data[p] && data[p] <= 57 { goto st110 }
	goto st0
tr254:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st111
st111:
	p++
	if p == pe { goto _test_eof111 }
	fallthrough
case 111:
// line 9564 "zparse.go"
	switch data[p] {
		case 9: goto st111
		case 32: goto st111
		case 46: goto tr110
		case 65: goto tr257
		case 67: goto tr258
		case 68: goto tr259
		case 72: goto tr260
		case 73: goto tr261
		case 77: goto tr262
		case 78: goto tr263
		case 82: goto tr264
		case 83: goto tr265
		case 92: goto tr110
		case 97: goto tr257
		case 99: goto tr258
		case 100: goto tr259
		case 104: goto tr260
		case 105: goto tr261
		case 109: goto tr262
		case 110: goto tr263
		case 114: goto tr264
		case 115: goto tr265
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr110 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr110 }
	} else {
		goto tr110
	}
	goto st0
tr419:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st431
tr257:
// line 28 "zparse.rl"
	{ mark = p }
	goto st431
st431:
	p++
	if p == pe { goto _test_eof431 }
	fallthrough
case 431:
// line 9612 "zparse.go"
	switch data[p] {
		case 9: goto tr859
		case 32: goto tr859
		case 46: goto st313
		case 78: goto st432
		case 92: goto st313
		case 110: goto st432
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st432:
	p++
	if p == pe { goto _test_eof432 }
	fallthrough
case 432:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 89: goto st433
		case 92: goto st313
		case 121: goto st433
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st433:
	p++
	if p == pe { goto _test_eof433 }
	fallthrough
case 433:
	switch data[p] {
		case 9: goto tr862
		case 32: goto tr862
		case 46: goto st313
		case 92: goto st313
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
tr420:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st434
tr258:
// line 28 "zparse.rl"
	{ mark = p }
	goto st434
st434:
	p++
	if p == pe { goto _test_eof434 }
	fallthrough
case 434:
// line 9684 "zparse.go"
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 72: goto st433
		case 78: goto st435
		case 83: goto st433
		case 92: goto st313
		case 104: goto st433
		case 110: goto st435
		case 115: goto st433
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st435:
	p++
	if p == pe { goto _test_eof435 }
	fallthrough
case 435:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 65: goto st436
		case 92: goto st313
		case 97: goto st436
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st436:
	p++
	if p == pe { goto _test_eof436 }
	fallthrough
case 436:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 77: goto st437
		case 92: goto st313
		case 109: goto st437
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st437:
	p++
	if p == pe { goto _test_eof437 }
	fallthrough
case 437:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 69: goto st438
		case 92: goto st313
		case 101: goto st438
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st438:
	p++
	if p == pe { goto _test_eof438 }
	fallthrough
case 438:
	switch data[p] {
		case 9: goto tr867
		case 32: goto tr867
		case 46: goto st313
		case 92: goto st313
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
tr421:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st439
tr259:
// line 28 "zparse.rl"
	{ mark = p }
	goto st439
st439:
	p++
	if p == pe { goto _test_eof439 }
	fallthrough
case 439:
// line 9802 "zparse.go"
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 78: goto st440
		case 83: goto st445
		case 92: goto st313
		case 110: goto st440
		case 115: goto st445
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st440:
	p++
	if p == pe { goto _test_eof440 }
	fallthrough
case 440:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 83: goto st441
		case 92: goto st313
		case 115: goto st441
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st441:
	p++
	if p == pe { goto _test_eof441 }
	fallthrough
case 441:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 75: goto st442
		case 92: goto st313
		case 107: goto st442
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st442:
	p++
	if p == pe { goto _test_eof442 }
	fallthrough
case 442:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 69: goto st443
		case 92: goto st313
		case 101: goto st443
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st443:
	p++
	if p == pe { goto _test_eof443 }
	fallthrough
case 443:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 89: goto st444
		case 92: goto st313
		case 121: goto st444
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st444:
	p++
	if p == pe { goto _test_eof444 }
	fallthrough
case 444:
	switch data[p] {
		case 9: goto tr874
		case 32: goto tr874
		case 46: goto st313
		case 92: goto st313
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st445:
	p++
	if p == pe { goto _test_eof445 }
	fallthrough
case 445:
	switch data[p] {
		case 9: goto tr875
		case 32: goto tr875
		case 46: goto st313
		case 92: goto st313
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
tr422:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st446
tr260:
// line 28 "zparse.rl"
	{ mark = p }
	goto st446
st446:
	p++
	if p == pe { goto _test_eof446 }
	fallthrough
case 446:
// line 9958 "zparse.go"
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 83: goto st433
		case 92: goto st313
		case 115: goto st433
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
tr423:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st447
tr261:
// line 28 "zparse.rl"
	{ mark = p }
	goto st447
st447:
	p++
	if p == pe { goto _test_eof447 }
	fallthrough
case 447:
// line 9990 "zparse.go"
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 78: goto st433
		case 92: goto st313
		case 110: goto st433
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
tr424:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st448
tr262:
// line 28 "zparse.rl"
	{ mark = p }
	goto st448
st448:
	p++
	if p == pe { goto _test_eof448 }
	fallthrough
case 448:
// line 10022 "zparse.go"
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 88: goto st449
		case 92: goto st313
		case 120: goto st449
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st449:
	p++
	if p == pe { goto _test_eof449 }
	fallthrough
case 449:
	switch data[p] {
		case 9: goto tr877
		case 32: goto tr877
		case 46: goto st313
		case 92: goto st313
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
tr425:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st450
tr263:
// line 28 "zparse.rl"
	{ mark = p }
	goto st450
st450:
	p++
	if p == pe { goto _test_eof450 }
	fallthrough
case 450:
// line 10073 "zparse.go"
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 79: goto st451
		case 83: goto st453
		case 92: goto st313
		case 111: goto st451
		case 115: goto st453
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st451:
	p++
	if p == pe { goto _test_eof451 }
	fallthrough
case 451:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 78: goto st452
		case 92: goto st313
		case 110: goto st452
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st452:
	p++
	if p == pe { goto _test_eof452 }
	fallthrough
case 452:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 69: goto st433
		case 92: goto st313
		case 101: goto st433
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st453:
	p++
	if p == pe { goto _test_eof453 }
	fallthrough
case 453:
	switch data[p] {
		case 9: goto tr881
		case 32: goto tr881
		case 46: goto st313
		case 92: goto st313
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
tr1384:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st112
tr1382:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st112
tr1500:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st112
tr1478:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st112
tr1065:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st112
tr1063:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st112
tr950:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st112
tr948:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st112
tr881:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st112
tr906:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st112
tr1304:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st112
tr1259:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st112
tr1194:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st112
tr1228:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st112
st112:
	p++
	if p == pe { goto _test_eof112 }
	fallthrough
case 112:
// line 10484 "zparse.go"
	switch data[p] {
		case 9: goto st112
		case 32: goto st112
		case 46: goto tr116
		case 65: goto tr268
		case 67: goto tr269
		case 68: goto tr270
		case 72: goto tr271
		case 73: goto tr272
		case 77: goto tr273
		case 78: goto tr274
		case 82: goto tr275
		case 83: goto tr276
		case 92: goto tr116
		case 97: goto tr268
		case 99: goto tr269
		case 100: goto tr270
		case 104: goto tr271
		case 105: goto tr272
		case 109: goto tr273
		case 110: goto tr274
		case 114: goto tr275
		case 115: goto tr276
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr267 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr116 }
	} else {
		goto tr116
	}
	goto st0
tr267:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st454
st454:
	p++
	if p == pe { goto _test_eof454 }
	fallthrough
case 454:
// line 10528 "zparse.go"
	switch data[p] {
		case 9: goto tr882
		case 32: goto tr882
		case 46: goto st314
		case 92: goto st314
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st454 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
tr268:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st455
st455:
	p++
	if p == pe { goto _test_eof455 }
	fallthrough
case 455:
// line 10554 "zparse.go"
	switch data[p] {
		case 9: goto tr884
		case 32: goto tr884
		case 46: goto st314
		case 78: goto st456
		case 92: goto st314
		case 110: goto st456
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st456:
	p++
	if p == pe { goto _test_eof456 }
	fallthrough
case 456:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 89: goto st457
		case 92: goto st314
		case 121: goto st457
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st457:
	p++
	if p == pe { goto _test_eof457 }
	fallthrough
case 457:
	switch data[p] {
		case 9: goto tr887
		case 32: goto tr887
		case 46: goto st314
		case 92: goto st314
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
tr269:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st458
st458:
	p++
	if p == pe { goto _test_eof458 }
	fallthrough
case 458:
// line 10622 "zparse.go"
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 72: goto st457
		case 78: goto st459
		case 83: goto st457
		case 92: goto st314
		case 104: goto st457
		case 110: goto st459
		case 115: goto st457
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st459:
	p++
	if p == pe { goto _test_eof459 }
	fallthrough
case 459:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 65: goto st460
		case 92: goto st314
		case 97: goto st460
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st460:
	p++
	if p == pe { goto _test_eof460 }
	fallthrough
case 460:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 77: goto st461
		case 92: goto st314
		case 109: goto st461
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st461:
	p++
	if p == pe { goto _test_eof461 }
	fallthrough
case 461:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 69: goto st462
		case 92: goto st314
		case 101: goto st462
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st462:
	p++
	if p == pe { goto _test_eof462 }
	fallthrough
case 462:
	switch data[p] {
		case 9: goto tr892
		case 32: goto tr892
		case 46: goto st314
		case 92: goto st314
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
tr270:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st463
st463:
	p++
	if p == pe { goto _test_eof463 }
	fallthrough
case 463:
// line 10736 "zparse.go"
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 78: goto st464
		case 83: goto st469
		case 92: goto st314
		case 110: goto st464
		case 115: goto st469
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st464:
	p++
	if p == pe { goto _test_eof464 }
	fallthrough
case 464:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 83: goto st465
		case 92: goto st314
		case 115: goto st465
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st465:
	p++
	if p == pe { goto _test_eof465 }
	fallthrough
case 465:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 75: goto st466
		case 92: goto st314
		case 107: goto st466
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st466:
	p++
	if p == pe { goto _test_eof466 }
	fallthrough
case 466:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 69: goto st467
		case 92: goto st314
		case 101: goto st467
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st467:
	p++
	if p == pe { goto _test_eof467 }
	fallthrough
case 467:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 89: goto st468
		case 92: goto st314
		case 121: goto st468
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st468:
	p++
	if p == pe { goto _test_eof468 }
	fallthrough
case 468:
	switch data[p] {
		case 9: goto tr899
		case 32: goto tr899
		case 46: goto st314
		case 92: goto st314
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st469:
	p++
	if p == pe { goto _test_eof469 }
	fallthrough
case 469:
	switch data[p] {
		case 9: goto tr900
		case 32: goto tr900
		case 46: goto st314
		case 92: goto st314
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
tr271:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st470
st470:
	p++
	if p == pe { goto _test_eof470 }
	fallthrough
case 470:
// line 10888 "zparse.go"
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 83: goto st457
		case 92: goto st314
		case 115: goto st457
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
tr272:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st471
st471:
	p++
	if p == pe { goto _test_eof471 }
	fallthrough
case 471:
// line 10916 "zparse.go"
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 78: goto st457
		case 92: goto st314
		case 110: goto st457
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
tr273:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st472
st472:
	p++
	if p == pe { goto _test_eof472 }
	fallthrough
case 472:
// line 10944 "zparse.go"
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 88: goto st473
		case 92: goto st314
		case 120: goto st473
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st473:
	p++
	if p == pe { goto _test_eof473 }
	fallthrough
case 473:
	switch data[p] {
		case 9: goto tr902
		case 32: goto tr902
		case 46: goto st314
		case 92: goto st314
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
tr274:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st474
st474:
	p++
	if p == pe { goto _test_eof474 }
	fallthrough
case 474:
// line 10991 "zparse.go"
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 79: goto st475
		case 83: goto st477
		case 92: goto st314
		case 111: goto st475
		case 115: goto st477
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st475:
	p++
	if p == pe { goto _test_eof475 }
	fallthrough
case 475:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 78: goto st476
		case 92: goto st314
		case 110: goto st476
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st476:
	p++
	if p == pe { goto _test_eof476 }
	fallthrough
case 476:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 69: goto st457
		case 92: goto st314
		case 101: goto st457
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st477:
	p++
	if p == pe { goto _test_eof477 }
	fallthrough
case 477:
	switch data[p] {
		case 9: goto tr906
		case 32: goto tr906
		case 46: goto st314
		case 92: goto st314
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
tr275:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st478
st478:
	p++
	if p == pe { goto _test_eof478 }
	fallthrough
case 478:
// line 11082 "zparse.go"
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 82: goto st479
		case 92: goto st314
		case 114: goto st479
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st479:
	p++
	if p == pe { goto _test_eof479 }
	fallthrough
case 479:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 83: goto st480
		case 92: goto st314
		case 115: goto st480
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st480:
	p++
	if p == pe { goto _test_eof480 }
	fallthrough
case 480:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 73: goto st481
		case 92: goto st314
		case 105: goto st481
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st481:
	p++
	if p == pe { goto _test_eof481 }
	fallthrough
case 481:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 71: goto st482
		case 92: goto st314
		case 103: goto st482
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st482:
	p++
	if p == pe { goto _test_eof482 }
	fallthrough
case 482:
	switch data[p] {
		case 9: goto tr911
		case 32: goto tr911
		case 46: goto st314
		case 92: goto st314
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
tr1396:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st113
tr1505:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st113
tr1483:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st113
tr1076:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st113
tr1074:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st113
tr962:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st113
tr960:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st113
tr927:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st113
tr911:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st113
tr1310:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st113
tr1265:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st113
tr1250:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st113
tr1234:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st113
tr1394:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st113
st113:
	p++
	if p == pe { goto _test_eof113 }
	fallthrough
case 113:
// line 11512 "zparse.go"
	switch data[p] {
		case 9: goto st113
		case 32: goto st113
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr278 }
	goto st0
tr278:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st114
st114:
	p++
	if p == pe { goto _test_eof114 }
	fallthrough
case 114:
// line 11548 "zparse.go"
	switch data[p] {
		case 9: goto tr279
		case 32: goto tr279
	}
	if 48 <= data[p] && data[p] <= 57 { goto st114 }
	goto st0
tr279:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st115
st115:
	p++
	if p == pe { goto _test_eof115 }
	fallthrough
case 115:
// line 11566 "zparse.go"
	switch data[p] {
		case 9: goto st115
		case 32: goto st115
		case 65: goto tr16
		case 67: goto tr17
		case 68: goto tr18
		case 72: goto tr19
		case 73: goto tr20
		case 77: goto tr21
		case 78: goto tr22
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr16
		case 99: goto tr17
		case 100: goto tr18
		case 104: goto tr19
		case 105: goto tr20
		case 109: goto tr21
		case 110: goto tr22
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr127 }
	goto st0
tr276:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st483
st483:
	p++
	if p == pe { goto _test_eof483 }
	fallthrough
case 483:
// line 11602 "zparse.go"
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 79: goto st484
		case 92: goto st314
		case 111: goto st484
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st484:
	p++
	if p == pe { goto _test_eof484 }
	fallthrough
case 484:
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr650
		case 46: goto st314
		case 65: goto st485
		case 92: goto st314
		case 97: goto st485
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
st485:
	p++
	if p == pe { goto _test_eof485 }
	fallthrough
case 485:
	switch data[p] {
		case 9: goto tr914
		case 32: goto tr914
		case 46: goto st314
		case 92: goto st314
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st314 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st314 }
	} else {
		goto st314
	}
	goto st0
tr283:
// line 28 "zparse.rl"
	{ mark = p }
	goto st116
tr1454:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st116
tr1452:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st116
tr1508:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st116
tr1486:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st116
tr1121:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st116
tr1119:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st116
tr1335:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st116
tr1333:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st116
tr930:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st116
tr914:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st116
tr1314:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st116
tr1269:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st116
tr1254:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st116
tr1243:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st116
st116:
	p++
	if p == pe { goto _test_eof116 }
	fallthrough
case 116:
// line 11994 "zparse.go"
	switch data[p] {
		case 9: goto st116
		case 32: goto tr283
		case 46: goto tr179
		case 65: goto tr285
		case 67: goto tr286
		case 68: goto tr287
		case 72: goto tr288
		case 73: goto tr289
		case 77: goto tr290
		case 78: goto tr291
		case 82: goto tr292
		case 83: goto tr293
		case 92: goto tr179
		case 97: goto tr285
		case 99: goto tr286
		case 100: goto tr287
		case 104: goto tr288
		case 105: goto tr289
		case 109: goto tr290
		case 110: goto tr291
		case 114: goto tr292
		case 115: goto tr293
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr284 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr179 }
	} else {
		goto tr179
	}
	goto st0
tr284:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st117
st117:
	p++
	if p == pe { goto _test_eof117 }
	fallthrough
case 117:
// line 12038 "zparse.go"
	switch data[p] {
		case 9: goto tr13
		case 32: goto tr294
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st117 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr294:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st118
st118:
	p++
	if p == pe { goto _test_eof118 }
	fallthrough
case 118:
// line 12062 "zparse.go"
	switch data[p] {
		case 9: goto st4
		case 32: goto st118
		case 46: goto st79
		case 65: goto tr297
		case 67: goto tr298
		case 68: goto tr299
		case 72: goto tr300
		case 73: goto tr301
		case 77: goto tr302
		case 78: goto tr303
		case 82: goto tr304
		case 83: goto tr305
		case 92: goto st79
		case 97: goto tr297
		case 99: goto tr298
		case 100: goto tr299
		case 104: goto tr300
		case 105: goto tr301
		case 109: goto tr302
		case 110: goto tr303
		case 114: goto tr304
		case 115: goto tr305
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr297:
// line 28 "zparse.rl"
	{ mark = p }
	goto st119
st119:
	p++
	if p == pe { goto _test_eof119 }
	fallthrough
case 119:
// line 12104 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr306
		case 46: goto st79
		case 78: goto st193
		case 92: goto st79
		case 110: goto st193
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr306:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st120
st120:
	p++
	if p == pe { goto _test_eof120 }
	fallthrough
case 120:
// line 12138 "zparse.go"
	switch data[p] {
		case 9: goto st6
		case 32: goto st120
		case 46: goto tr309
		case 92: goto tr309
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr309 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr309 }
	} else {
		goto tr309
	}
	goto st0
tr309:
// line 28 "zparse.rl"
	{ mark = p }
	goto st486
st486:
	p++
	if p == pe { goto _test_eof486 }
	fallthrough
case 486:
// line 12162 "zparse.go"
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr915
		case 46: goto st486
		case 92: goto st486
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st486 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st486 }
	} else {
		goto st486
	}
	goto st0
tr915:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st121
tr917:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st121
tr919:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st121
tr921:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st121
st121:
	p++
	if p == pe { goto _test_eof121 }
	fallthrough
case 121:
// line 12219 "zparse.go"
	switch data[p] {
		case 9: goto st2
		case 32: goto st121
		case 46: goto st79
		case 65: goto tr285
		case 67: goto tr286
		case 68: goto tr287
		case 72: goto tr288
		case 73: goto tr289
		case 77: goto tr290
		case 78: goto tr291
		case 82: goto tr292
		case 83: goto tr293
		case 92: goto st79
		case 97: goto tr285
		case 99: goto tr286
		case 100: goto tr287
		case 104: goto tr288
		case 105: goto tr289
		case 109: goto tr290
		case 110: goto tr291
		case 114: goto tr292
		case 115: goto tr293
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr284 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr285:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st122
st122:
	p++
	if p == pe { goto _test_eof122 }
	fallthrough
case 122:
// line 12263 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr306
		case 46: goto st79
		case 78: goto st123
		case 92: goto st79
		case 110: goto st123
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st123:
	p++
	if p == pe { goto _test_eof123 }
	fallthrough
case 123:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 89: goto st124
		case 92: goto st79
		case 121: goto st124
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st124:
	p++
	if p == pe { goto _test_eof124 }
	fallthrough
case 124:
	switch data[p] {
		case 9: goto tr183
		case 32: goto tr313
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr313:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st125
st125:
	p++
	if p == pe { goto _test_eof125 }
	fallthrough
case 125:
// line 12328 "zparse.go"
	switch data[p] {
		case 9: goto st83
		case 32: goto st125
		case 46: goto st79
		case 65: goto tr316
		case 67: goto tr317
		case 68: goto tr299
		case 77: goto tr302
		case 78: goto tr318
		case 82: goto tr304
		case 83: goto tr305
		case 92: goto st79
		case 97: goto tr316
		case 99: goto tr317
		case 100: goto tr299
		case 109: goto tr302
		case 110: goto tr318
		case 114: goto tr304
		case 115: goto tr305
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr315 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr315:
// line 28 "zparse.rl"
	{ mark = p }
	goto st126
st126:
	p++
	if p == pe { goto _test_eof126 }
	fallthrough
case 126:
// line 12366 "zparse.go"
	switch data[p] {
		case 9: goto tr186
		case 32: goto tr319
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st126 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr319:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
	goto st127
tr414:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
	goto st127
st127:
	p++
	if p == pe { goto _test_eof127 }
	fallthrough
case 127:
// line 12394 "zparse.go"
	switch data[p] {
		case 9: goto st9
		case 32: goto st127
		case 46: goto st79
		case 65: goto tr316
		case 67: goto tr317
		case 68: goto tr299
		case 77: goto tr302
		case 78: goto tr318
		case 82: goto tr304
		case 83: goto tr305
		case 92: goto st79
		case 97: goto tr316
		case 99: goto tr317
		case 100: goto tr299
		case 109: goto tr302
		case 110: goto tr318
		case 114: goto tr304
		case 115: goto tr305
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr316:
// line 28 "zparse.rl"
	{ mark = p }
	goto st128
st128:
	p++
	if p == pe { goto _test_eof128 }
	fallthrough
case 128:
// line 12432 "zparse.go"
	switch data[p] {
		case 9: goto tr25
		case 32: goto tr306
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr317:
// line 28 "zparse.rl"
	{ mark = p }
	goto st129
st129:
	p++
	if p == pe { goto _test_eof129 }
	fallthrough
case 129:
// line 12456 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 78: goto st130
		case 92: goto st79
		case 110: goto st130
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st130:
	p++
	if p == pe { goto _test_eof130 }
	fallthrough
case 130:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 65: goto st131
		case 92: goto st79
		case 97: goto st131
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st131:
	p++
	if p == pe { goto _test_eof131 }
	fallthrough
case 131:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 77: goto st132
		case 92: goto st79
		case 109: goto st132
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st132:
	p++
	if p == pe { goto _test_eof132 }
	fallthrough
case 132:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 69: goto st133
		case 92: goto st79
		case 101: goto st133
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st133:
	p++
	if p == pe { goto _test_eof133 }
	fallthrough
case 133:
	switch data[p] {
		case 9: goto tr39
		case 32: goto tr326
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr326:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st134
st134:
	p++
	if p == pe { goto _test_eof134 }
	fallthrough
case 134:
// line 12568 "zparse.go"
	switch data[p] {
		case 9: goto st16
		case 32: goto st134
		case 46: goto tr328
		case 92: goto tr328
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr328 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr328 }
	} else {
		goto tr328
	}
	goto st0
tr328:
// line 28 "zparse.rl"
	{ mark = p }
	goto st487
st487:
	p++
	if p == pe { goto _test_eof487 }
	fallthrough
case 487:
// line 12592 "zparse.go"
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr917
		case 46: goto st487
		case 92: goto st487
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st487 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st487 }
	} else {
		goto st487
	}
	goto st0
tr287:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st135
tr299:
// line 28 "zparse.rl"
	{ mark = p }
	goto st135
st135:
	p++
	if p == pe { goto _test_eof135 }
	fallthrough
case 135:
// line 12622 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 78: goto st136
		case 83: goto st147
		case 92: goto st79
		case 110: goto st136
		case 115: goto st147
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st136:
	p++
	if p == pe { goto _test_eof136 }
	fallthrough
case 136:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 83: goto st137
		case 92: goto st79
		case 115: goto st137
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st137:
	p++
	if p == pe { goto _test_eof137 }
	fallthrough
case 137:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 75: goto st138
		case 92: goto st79
		case 107: goto st138
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st138:
	p++
	if p == pe { goto _test_eof138 }
	fallthrough
case 138:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 69: goto st139
		case 92: goto st79
		case 101: goto st139
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st139:
	p++
	if p == pe { goto _test_eof139 }
	fallthrough
case 139:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 89: goto st140
		case 92: goto st79
		case 121: goto st140
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st140:
	p++
	if p == pe { goto _test_eof140 }
	fallthrough
case 140:
	switch data[p] {
		case 9: goto tr48
		case 32: goto tr335
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr335:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st141
st141:
	p++
	if p == pe { goto _test_eof141 }
	fallthrough
case 141:
// line 12756 "zparse.go"
	switch data[p] {
		case 9: goto st23
		case 32: goto st141
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr337:
// line 28 "zparse.rl"
	{ mark = p }
	goto st142
st142:
	p++
	if p == pe { goto _test_eof142 }
	fallthrough
case 142:
// line 12780 "zparse.go"
	switch data[p] {
		case 9: goto tr51
		case 32: goto tr338
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st142 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr338:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st143
st143:
	p++
	if p == pe { goto _test_eof143 }
	fallthrough
case 143:
// line 12804 "zparse.go"
	switch data[p] {
		case 9: goto st25
		case 32: goto st143
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr341 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr341:
// line 28 "zparse.rl"
	{ mark = p }
	goto st144
st144:
	p++
	if p == pe { goto _test_eof144 }
	fallthrough
case 144:
// line 12828 "zparse.go"
	switch data[p] {
		case 9: goto tr55
		case 32: goto tr342
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st144 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr342:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st145
st145:
	p++
	if p == pe { goto _test_eof145 }
	fallthrough
case 145:
// line 12852 "zparse.go"
	switch data[p] {
		case 9: goto st27
		case 32: goto st145
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr345 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr345:
// line 28 "zparse.rl"
	{ mark = p }
	goto st146
st146:
	p++
	if p == pe { goto _test_eof146 }
	fallthrough
case 146:
// line 12876 "zparse.go"
	switch data[p] {
		case 9: goto tr59
		case 32: goto tr59
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st146 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st147:
	p++
	if p == pe { goto _test_eof147 }
	fallthrough
case 147:
	switch data[p] {
		case 9: goto tr347
		case 32: goto tr348
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr347:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st148
st148:
	p++
	if p == pe { goto _test_eof148 }
	fallthrough
case 148:
// line 12927 "zparse.go"
	switch data[p] {
		case 9: goto st148
		case 32: goto st148
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr350 }
	goto st0
tr350:
// line 28 "zparse.rl"
	{ mark = p }
	goto st149
st149:
	p++
	if p == pe { goto _test_eof149 }
	fallthrough
case 149:
// line 12943 "zparse.go"
	switch data[p] {
		case 9: goto tr351
		case 32: goto tr351
	}
	if 48 <= data[p] && data[p] <= 57 { goto st149 }
	goto st0
tr351:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st150
st150:
	p++
	if p == pe { goto _test_eof150 }
	fallthrough
case 150:
// line 12959 "zparse.go"
	switch data[p] {
		case 9: goto st150
		case 32: goto st150
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr210 }
	goto st0
tr348:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st151
st151:
	p++
	if p == pe { goto _test_eof151 }
	fallthrough
case 151:
// line 12983 "zparse.go"
	switch data[p] {
		case 9: goto st148
		case 32: goto st151
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr355 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr355:
// line 28 "zparse.rl"
	{ mark = p }
	goto st152
st152:
	p++
	if p == pe { goto _test_eof152 }
	fallthrough
case 152:
// line 13007 "zparse.go"
	switch data[p] {
		case 9: goto tr351
		case 32: goto tr356
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st152 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr356:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st153
st153:
	p++
	if p == pe { goto _test_eof153 }
	fallthrough
case 153:
// line 13031 "zparse.go"
	switch data[p] {
		case 9: goto st150
		case 32: goto st153
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr359 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr359:
// line 28 "zparse.rl"
	{ mark = p }
	goto st154
st154:
	p++
	if p == pe { goto _test_eof154 }
	fallthrough
case 154:
// line 13055 "zparse.go"
	switch data[p] {
		case 9: goto tr211
		case 32: goto tr360
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st154 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr360:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st155
st155:
	p++
	if p == pe { goto _test_eof155 }
	fallthrough
case 155:
// line 13079 "zparse.go"
	switch data[p] {
		case 9: goto st99
		case 32: goto st155
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr363 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr363:
// line 28 "zparse.rl"
	{ mark = p }
	goto st156
st156:
	p++
	if p == pe { goto _test_eof156 }
	fallthrough
case 156:
// line 13103 "zparse.go"
	switch data[p] {
		case 9: goto tr215
		case 32: goto tr215
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st156 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr290:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st157
tr302:
// line 28 "zparse.rl"
	{ mark = p }
	goto st157
st157:
	p++
	if p == pe { goto _test_eof157 }
	fallthrough
case 157:
// line 13133 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 88: goto st158
		case 92: goto st79
		case 120: goto st158
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st158:
	p++
	if p == pe { goto _test_eof158 }
	fallthrough
case 158:
	switch data[p] {
		case 9: goto tr104
		case 32: goto tr366
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr366:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st159
st159:
	p++
	if p == pe { goto _test_eof159 }
	fallthrough
case 159:
// line 13185 "zparse.go"
	switch data[p] {
		case 9: goto st41
		case 32: goto st159
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr368 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr368:
// line 28 "zparse.rl"
	{ mark = p }
	goto st160
st160:
	p++
	if p == pe { goto _test_eof160 }
	fallthrough
case 160:
// line 13209 "zparse.go"
	switch data[p] {
		case 9: goto tr107
		case 32: goto tr369
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st160 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr369:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st161
st161:
	p++
	if p == pe { goto _test_eof161 }
	fallthrough
case 161:
// line 13233 "zparse.go"
	switch data[p] {
		case 9: goto st43
		case 32: goto st161
		case 46: goto tr372
		case 92: goto tr372
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr372 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr372 }
	} else {
		goto tr372
	}
	goto st0
tr372:
// line 28 "zparse.rl"
	{ mark = p }
	goto st488
st488:
	p++
	if p == pe { goto _test_eof488 }
	fallthrough
case 488:
// line 13257 "zparse.go"
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr919
		case 46: goto st488
		case 92: goto st488
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st488 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st488 }
	} else {
		goto st488
	}
	goto st0
tr318:
// line 28 "zparse.rl"
	{ mark = p }
	goto st162
st162:
	p++
	if p == pe { goto _test_eof162 }
	fallthrough
case 162:
// line 13281 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 83: goto st163
		case 92: goto st79
		case 115: goto st163
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st163:
	p++
	if p == pe { goto _test_eof163 }
	fallthrough
case 163:
	switch data[p] {
		case 9: goto tr114
		case 32: goto tr374
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr374:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st164
st164:
	p++
	if p == pe { goto _test_eof164 }
	fallthrough
case 164:
// line 13333 "zparse.go"
	switch data[p] {
		case 9: goto st48
		case 32: goto st164
		case 46: goto tr376
		case 92: goto tr376
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr376 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr376 }
	} else {
		goto tr376
	}
	goto st0
tr376:
// line 28 "zparse.rl"
	{ mark = p }
	goto st489
st489:
	p++
	if p == pe { goto _test_eof489 }
	fallthrough
case 489:
// line 13357 "zparse.go"
	switch data[p] {
		case 9: goto tr650
		case 32: goto tr921
		case 46: goto st489
		case 92: goto st489
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st489 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st489 }
	} else {
		goto st489
	}
	goto st0
tr292:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st165
tr304:
// line 28 "zparse.rl"
	{ mark = p }
	goto st165
st165:
	p++
	if p == pe { goto _test_eof165 }
	fallthrough
case 165:
// line 13387 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 82: goto st166
		case 92: goto st79
		case 114: goto st166
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st166:
	p++
	if p == pe { goto _test_eof166 }
	fallthrough
case 166:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 83: goto st167
		case 92: goto st79
		case 115: goto st167
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st167:
	p++
	if p == pe { goto _test_eof167 }
	fallthrough
case 167:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 73: goto st168
		case 92: goto st79
		case 105: goto st168
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st168:
	p++
	if p == pe { goto _test_eof168 }
	fallthrough
case 168:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 71: goto st169
		case 92: goto st79
		case 103: goto st169
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st169:
	p++
	if p == pe { goto _test_eof169 }
	fallthrough
case 169:
	switch data[p] {
		case 9: goto tr121
		case 32: goto tr381
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr381:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st170
st170:
	p++
	if p == pe { goto _test_eof170 }
	fallthrough
case 170:
// line 13499 "zparse.go"
	switch data[p] {
		case 9: goto st54
		case 32: goto st170
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr383:
// line 28 "zparse.rl"
	{ mark = p }
	goto st171
st171:
	p++
	if p == pe { goto _test_eof171 }
	fallthrough
case 171:
// line 13523 "zparse.go"
	switch data[p] {
		case 9: goto tr124
		case 32: goto tr384
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st171 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr384:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st172
st172:
	p++
	if p == pe { goto _test_eof172 }
	fallthrough
case 172:
// line 13547 "zparse.go"
	switch data[p] {
		case 9: goto st56
		case 32: goto st172
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr387 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr387:
// line 28 "zparse.rl"
	{ mark = p }
	goto st173
st173:
	p++
	if p == pe { goto _test_eof173 }
	fallthrough
case 173:
// line 13571 "zparse.go"
	switch data[p] {
		case 9: goto tr128
		case 32: goto tr388
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st173 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr388:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st174
st174:
	p++
	if p == pe { goto _test_eof174 }
	fallthrough
case 174:
// line 13595 "zparse.go"
	switch data[p] {
		case 9: goto st58
		case 32: goto st174
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr391 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr391:
// line 28 "zparse.rl"
	{ mark = p }
	goto st175
st175:
	p++
	if p == pe { goto _test_eof175 }
	fallthrough
case 175:
// line 13619 "zparse.go"
	switch data[p] {
		case 9: goto tr132
		case 32: goto tr392
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st175 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr392:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st176
st176:
	p++
	if p == pe { goto _test_eof176 }
	fallthrough
case 176:
// line 13643 "zparse.go"
	switch data[p] {
		case 9: goto st60
		case 32: goto st176
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr395 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr395:
// line 28 "zparse.rl"
	{ mark = p }
	goto st177
st177:
	p++
	if p == pe { goto _test_eof177 }
	fallthrough
case 177:
// line 13667 "zparse.go"
	switch data[p] {
		case 9: goto tr136
		case 32: goto tr396
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st177 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr396:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st178
st178:
	p++
	if p == pe { goto _test_eof178 }
	fallthrough
case 178:
// line 13691 "zparse.go"
	switch data[p] {
		case 9: goto st62
		case 32: goto st178
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr399 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr399:
// line 28 "zparse.rl"
	{ mark = p }
	goto st179
st179:
	p++
	if p == pe { goto _test_eof179 }
	fallthrough
case 179:
// line 13715 "zparse.go"
	switch data[p] {
		case 9: goto tr140
		case 32: goto tr400
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st179 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr400:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st180
st180:
	p++
	if p == pe { goto _test_eof180 }
	fallthrough
case 180:
// line 13739 "zparse.go"
	switch data[p] {
		case 9: goto st64
		case 32: goto st180
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr403 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr403:
// line 28 "zparse.rl"
	{ mark = p }
	goto st181
st181:
	p++
	if p == pe { goto _test_eof181 }
	fallthrough
case 181:
// line 13763 "zparse.go"
	switch data[p] {
		case 9: goto tr144
		case 32: goto tr404
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st181 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr404:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st182
st182:
	p++
	if p == pe { goto _test_eof182 }
	fallthrough
case 182:
// line 13787 "zparse.go"
	switch data[p] {
		case 9: goto st66
		case 32: goto st182
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr407 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr407:
// line 28 "zparse.rl"
	{ mark = p }
	goto st183
st183:
	p++
	if p == pe { goto _test_eof183 }
	fallthrough
case 183:
// line 13811 "zparse.go"
	switch data[p] {
		case 9: goto tr148
		case 32: goto tr148
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st183 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr293:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st184
tr305:
// line 28 "zparse.rl"
	{ mark = p }
	goto st184
st184:
	p++
	if p == pe { goto _test_eof184 }
	fallthrough
case 184:
// line 13841 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 79: goto st185
		case 92: goto st79
		case 111: goto st185
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st185:
	p++
	if p == pe { goto _test_eof185 }
	fallthrough
case 185:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 65: goto st186
		case 92: goto st79
		case 97: goto st186
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st186:
	p++
	if p == pe { goto _test_eof186 }
	fallthrough
case 186:
	switch data[p] {
		case 9: goto tr176
		case 32: goto tr176
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr286:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st187
st187:
	p++
	if p == pe { goto _test_eof187 }
	fallthrough
case 187:
// line 13907 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 72: goto st124
		case 78: goto st130
		case 83: goto st124
		case 92: goto st79
		case 104: goto st124
		case 110: goto st130
		case 115: goto st124
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr288:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st188
st188:
	p++
	if p == pe { goto _test_eof188 }
	fallthrough
case 188:
// line 13938 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 83: goto st124
		case 92: goto st79
		case 115: goto st124
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr289:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st189
st189:
	p++
	if p == pe { goto _test_eof189 }
	fallthrough
case 189:
// line 13965 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 78: goto st124
		case 92: goto st79
		case 110: goto st124
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr291:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st190
st190:
	p++
	if p == pe { goto _test_eof190 }
	fallthrough
case 190:
// line 13992 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 79: goto st191
		case 83: goto st163
		case 92: goto st79
		case 111: goto st191
		case 115: goto st163
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st191:
	p++
	if p == pe { goto _test_eof191 }
	fallthrough
case 191:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 78: goto st192
		case 92: goto st79
		case 110: goto st192
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st192:
	p++
	if p == pe { goto _test_eof192 }
	fallthrough
case 192:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 69: goto st124
		case 92: goto st79
		case 101: goto st124
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st193:
	p++
	if p == pe { goto _test_eof193 }
	fallthrough
case 193:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 89: goto st194
		case 92: goto st79
		case 121: goto st194
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st194:
	p++
	if p == pe { goto _test_eof194 }
	fallthrough
case 194:
	switch data[p] {
		case 9: goto tr30
		case 32: goto tr414
		case 46: goto st79
		case 92: goto st79
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr298:
// line 28 "zparse.rl"
	{ mark = p }
	goto st195
st195:
	p++
	if p == pe { goto _test_eof195 }
	fallthrough
case 195:
// line 14098 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 72: goto st194
		case 78: goto st130
		case 83: goto st194
		case 92: goto st79
		case 104: goto st194
		case 110: goto st130
		case 115: goto st194
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr300:
// line 28 "zparse.rl"
	{ mark = p }
	goto st196
st196:
	p++
	if p == pe { goto _test_eof196 }
	fallthrough
case 196:
// line 14127 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 83: goto st194
		case 92: goto st79
		case 115: goto st194
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr301:
// line 28 "zparse.rl"
	{ mark = p }
	goto st197
st197:
	p++
	if p == pe { goto _test_eof197 }
	fallthrough
case 197:
// line 14152 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 78: goto st194
		case 92: goto st79
		case 110: goto st194
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr303:
// line 28 "zparse.rl"
	{ mark = p }
	goto st198
st198:
	p++
	if p == pe { goto _test_eof198 }
	fallthrough
case 198:
// line 14177 "zparse.go"
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 79: goto st199
		case 83: goto st163
		case 92: goto st79
		case 111: goto st199
		case 115: goto st163
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st199:
	p++
	if p == pe { goto _test_eof199 }
	fallthrough
case 199:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 78: goto st200
		case 92: goto st79
		case 110: goto st200
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
st200:
	p++
	if p == pe { goto _test_eof200 }
	fallthrough
case 200:
	switch data[p] {
		case 32: goto st79
		case 46: goto st79
		case 69: goto st194
		case 92: goto st79
		case 101: goto st194
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st79 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st79 }
	} else {
		goto st79
	}
	goto st0
tr426:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st490
tr264:
// line 28 "zparse.rl"
	{ mark = p }
	goto st490
st490:
	p++
	if p == pe { goto _test_eof490 }
	fallthrough
case 490:
// line 14250 "zparse.go"
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 82: goto st491
		case 92: goto st313
		case 114: goto st491
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st491:
	p++
	if p == pe { goto _test_eof491 }
	fallthrough
case 491:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 83: goto st492
		case 92: goto st313
		case 115: goto st492
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st492:
	p++
	if p == pe { goto _test_eof492 }
	fallthrough
case 492:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 73: goto st493
		case 92: goto st313
		case 105: goto st493
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st493:
	p++
	if p == pe { goto _test_eof493 }
	fallthrough
case 493:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 71: goto st494
		case 92: goto st313
		case 103: goto st494
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st494:
	p++
	if p == pe { goto _test_eof494 }
	fallthrough
case 494:
	switch data[p] {
		case 9: goto tr927
		case 32: goto tr927
		case 46: goto st313
		case 92: goto st313
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
tr427:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st495
tr265:
// line 28 "zparse.rl"
	{ mark = p }
	goto st495
st495:
	p++
	if p == pe { goto _test_eof495 }
	fallthrough
case 495:
// line 14364 "zparse.go"
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 79: goto st496
		case 92: goto st313
		case 111: goto st496
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st496:
	p++
	if p == pe { goto _test_eof496 }
	fallthrough
case 496:
	switch data[p] {
		case 9: goto tr648
		case 32: goto tr648
		case 46: goto st313
		case 65: goto st497
		case 92: goto st313
		case 97: goto st497
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
st497:
	p++
	if p == pe { goto _test_eof497 }
	fallthrough
case 497:
	switch data[p] {
		case 9: goto tr930
		case 32: goto tr930
		case 46: goto st313
		case 92: goto st313
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st313 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
tr858:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st498
st498:
	p++
	if p == pe { goto _test_eof498 }
	fallthrough
case 498:
// line 14438 "zparse.go"
	switch data[p] {
		case 9: goto tr931
		case 32: goto st498
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr933 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr933:
// line 28 "zparse.rl"
	{ mark = p }
	goto st499
st499:
	p++
	if p == pe { goto _test_eof499 }
	fallthrough
case 499:
// line 14462 "zparse.go"
	switch data[p] {
		case 9: goto tr934
		case 32: goto tr935
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st499 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1375:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st201
tr1054:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st201
tr1051:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st201
tr1372:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st201
tr939:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st201
tr934:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st201
tr1128:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st201
st201:
	p++
	if p == pe { goto _test_eof201 }
	fallthrough
case 201:
// line 14591 "zparse.go"
	switch data[p] {
		case 9: goto st201
		case 32: goto st201
		case 46: goto tr110
		case 65: goto tr419
		case 67: goto tr420
		case 68: goto tr421
		case 72: goto tr422
		case 73: goto tr423
		case 77: goto tr424
		case 78: goto tr425
		case 82: goto tr426
		case 83: goto tr427
		case 92: goto tr110
		case 97: goto tr419
		case 99: goto tr420
		case 100: goto tr421
		case 104: goto tr422
		case 105: goto tr423
		case 109: goto tr424
		case 110: goto tr425
		case 114: goto tr426
		case 115: goto tr427
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr418 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr110 }
	} else {
		goto tr110
	}
	goto st0
tr418:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st500
st500:
	p++
	if p == pe { goto _test_eof500 }
	fallthrough
case 500:
// line 14635 "zparse.go"
	switch data[p] {
		case 9: goto tr937
		case 32: goto tr937
		case 46: goto st313
		case 92: goto st313
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st500 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st313 }
	} else {
		goto st313
	}
	goto st0
tr935:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st501
st501:
	p++
	if p == pe { goto _test_eof501 }
	fallthrough
case 501:
// line 14659 "zparse.go"
	switch data[p] {
		case 9: goto tr939
		case 32: goto st501
		case 46: goto tr941
		case 92: goto tr941
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr941 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr941 }
	} else {
		goto tr941
	}
	goto st0
tr941:
// line 28 "zparse.rl"
	{ mark = p }
	goto st502
st502:
	p++
	if p == pe { goto _test_eof502 }
	fallthrough
case 502:
// line 14683 "zparse.go"
	switch data[p] {
		case 9: goto tr942
		case 32: goto tr943
		case 46: goto st502
		case 92: goto st502
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st502 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st502 }
	} else {
		goto st502
	}
	goto st0
tr249:
// line 28 "zparse.rl"
	{ mark = p }
	goto st503
st503:
	p++
	if p == pe { goto _test_eof503 }
	fallthrough
case 503:
// line 14707 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 79: goto st504
		case 83: goto st506
		case 92: goto st383
		case 111: goto st504
		case 115: goto st506
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st504:
	p++
	if p == pe { goto _test_eof504 }
	fallthrough
case 504:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 78: goto st505
		case 92: goto st383
		case 110: goto st505
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st505:
	p++
	if p == pe { goto _test_eof505 }
	fallthrough
case 505:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 69: goto st426
		case 92: goto st383
		case 101: goto st426
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st506:
	p++
	if p == pe { goto _test_eof506 }
	fallthrough
case 506:
	switch data[p] {
		case 9: goto tr948
		case 32: goto tr949
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr949:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st507
st507:
	p++
	if p == pe { goto _test_eof507 }
	fallthrough
case 507:
// line 14804 "zparse.go"
	switch data[p] {
		case 9: goto tr950
		case 32: goto st507
		case 46: goto tr952
		case 92: goto tr952
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr952 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr952 }
	} else {
		goto tr952
	}
	goto st0
tr952:
// line 28 "zparse.rl"
	{ mark = p }
	goto st508
st508:
	p++
	if p == pe { goto _test_eof508 }
	fallthrough
case 508:
// line 14828 "zparse.go"
	switch data[p] {
		case 9: goto tr953
		case 32: goto tr954
		case 46: goto st508
		case 92: goto st508
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st508 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st508 }
	} else {
		goto st508
	}
	goto st0
tr230:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st509
tr250:
// line 28 "zparse.rl"
	{ mark = p }
	goto st509
st509:
	p++
	if p == pe { goto _test_eof509 }
	fallthrough
case 509:
// line 14858 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 82: goto st510
		case 92: goto st383
		case 114: goto st510
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st510:
	p++
	if p == pe { goto _test_eof510 }
	fallthrough
case 510:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 83: goto st511
		case 92: goto st383
		case 115: goto st511
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st511:
	p++
	if p == pe { goto _test_eof511 }
	fallthrough
case 511:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 73: goto st512
		case 92: goto st383
		case 105: goto st512
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st512:
	p++
	if p == pe { goto _test_eof512 }
	fallthrough
case 512:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 71: goto st513
		case 92: goto st383
		case 103: goto st513
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st513:
	p++
	if p == pe { goto _test_eof513 }
	fallthrough
case 513:
	switch data[p] {
		case 9: goto tr960
		case 32: goto tr961
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr961:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st514
st514:
	p++
	if p == pe { goto _test_eof514 }
	fallthrough
case 514:
// line 14974 "zparse.go"
	switch data[p] {
		case 9: goto tr962
		case 32: goto st514
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr964 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr964:
// line 28 "zparse.rl"
	{ mark = p }
	goto st515
st515:
	p++
	if p == pe { goto _test_eof515 }
	fallthrough
case 515:
// line 14998 "zparse.go"
	switch data[p] {
		case 9: goto tr965
		case 32: goto tr966
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st515 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1402:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st202
tr1081:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st202
tr1078:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st202
tr968:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st202
tr965:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st202
tr1237:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st202
tr1399:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st202
st202:
	p++
	if p == pe { goto _test_eof202 }
	fallthrough
case 202:
// line 15127 "zparse.go"
	switch data[p] {
		case 9: goto st202
		case 32: goto st202
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr429 }
	goto st0
tr429:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st203
st203:
	p++
	if p == pe { goto _test_eof203 }
	fallthrough
case 203:
// line 15163 "zparse.go"
	switch data[p] {
		case 9: goto tr430
		case 32: goto tr430
	}
	if 48 <= data[p] && data[p] <= 57 { goto st203 }
	goto st0
tr430:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st204
st204:
	p++
	if p == pe { goto _test_eof204 }
	fallthrough
case 204:
// line 15181 "zparse.go"
	switch data[p] {
		case 9: goto st204
		case 32: goto st204
		case 65: goto tr16
		case 67: goto tr17
		case 68: goto tr18
		case 72: goto tr19
		case 73: goto tr20
		case 77: goto tr21
		case 78: goto tr22
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr16
		case 99: goto tr17
		case 100: goto tr18
		case 104: goto tr19
		case 105: goto tr20
		case 109: goto tr21
		case 110: goto tr22
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr131 }
	goto st0
tr966:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st516
st516:
	p++
	if p == pe { goto _test_eof516 }
	fallthrough
case 516:
// line 15215 "zparse.go"
	switch data[p] {
		case 9: goto tr968
		case 32: goto st516
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr970 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr970:
// line 28 "zparse.rl"
	{ mark = p }
	goto st517
st517:
	p++
	if p == pe { goto _test_eof517 }
	fallthrough
case 517:
// line 15239 "zparse.go"
	switch data[p] {
		case 9: goto tr971
		case 32: goto tr972
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st517 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1408:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st205
tr1087:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st205
tr1084:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st205
tr974:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st205
tr971:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st205
tr1405:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st205
st205:
	p++
	if p == pe { goto _test_eof205 }
	fallthrough
case 205:
// line 15347 "zparse.go"
	switch data[p] {
		case 9: goto st205
		case 32: goto st205
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr434 }
	goto st0
tr434:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st206
st206:
	p++
	if p == pe { goto _test_eof206 }
	fallthrough
case 206:
// line 15383 "zparse.go"
	switch data[p] {
		case 9: goto tr435
		case 32: goto tr435
	}
	if 48 <= data[p] && data[p] <= 57 { goto st206 }
	goto st0
tr435:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st207
st207:
	p++
	if p == pe { goto _test_eof207 }
	fallthrough
case 207:
// line 15401 "zparse.go"
	switch data[p] {
		case 9: goto st207
		case 32: goto st207
		case 65: goto tr16
		case 67: goto tr17
		case 68: goto tr18
		case 72: goto tr19
		case 73: goto tr20
		case 77: goto tr21
		case 78: goto tr22
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr16
		case 99: goto tr17
		case 100: goto tr18
		case 104: goto tr19
		case 105: goto tr20
		case 109: goto tr21
		case 110: goto tr22
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr135 }
	goto st0
tr972:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st518
st518:
	p++
	if p == pe { goto _test_eof518 }
	fallthrough
case 518:
// line 15435 "zparse.go"
	switch data[p] {
		case 9: goto tr974
		case 32: goto st518
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr976 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr976:
// line 28 "zparse.rl"
	{ mark = p }
	goto st519
st519:
	p++
	if p == pe { goto _test_eof519 }
	fallthrough
case 519:
// line 15459 "zparse.go"
	switch data[p] {
		case 9: goto tr977
		case 32: goto tr978
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st519 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1414:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st208
tr1093:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st208
tr1090:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st208
tr980:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st208
tr977:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st208
tr1411:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st208
st208:
	p++
	if p == pe { goto _test_eof208 }
	fallthrough
case 208:
// line 15567 "zparse.go"
	switch data[p] {
		case 9: goto st208
		case 32: goto st208
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr439 }
	goto st0
tr439:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st209
st209:
	p++
	if p == pe { goto _test_eof209 }
	fallthrough
case 209:
// line 15603 "zparse.go"
	switch data[p] {
		case 9: goto tr440
		case 32: goto tr440
	}
	if 48 <= data[p] && data[p] <= 57 { goto st209 }
	goto st0
tr440:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st210
st210:
	p++
	if p == pe { goto _test_eof210 }
	fallthrough
case 210:
// line 15621 "zparse.go"
	switch data[p] {
		case 9: goto st210
		case 32: goto st210
		case 65: goto tr16
		case 67: goto tr17
		case 68: goto tr18
		case 72: goto tr19
		case 73: goto tr20
		case 77: goto tr21
		case 78: goto tr22
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr16
		case 99: goto tr17
		case 100: goto tr18
		case 104: goto tr19
		case 105: goto tr20
		case 109: goto tr21
		case 110: goto tr22
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr139 }
	goto st0
tr978:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st520
st520:
	p++
	if p == pe { goto _test_eof520 }
	fallthrough
case 520:
// line 15655 "zparse.go"
	switch data[p] {
		case 9: goto tr980
		case 32: goto st520
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr982 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr982:
// line 28 "zparse.rl"
	{ mark = p }
	goto st521
st521:
	p++
	if p == pe { goto _test_eof521 }
	fallthrough
case 521:
// line 15679 "zparse.go"
	switch data[p] {
		case 9: goto tr983
		case 32: goto tr984
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st521 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1420:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st211
tr1099:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st211
tr1096:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st211
tr986:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st211
tr983:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st211
tr1417:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st211
st211:
	p++
	if p == pe { goto _test_eof211 }
	fallthrough
case 211:
// line 15787 "zparse.go"
	switch data[p] {
		case 9: goto st211
		case 32: goto st211
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr444 }
	goto st0
tr444:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st212
st212:
	p++
	if p == pe { goto _test_eof212 }
	fallthrough
case 212:
// line 15823 "zparse.go"
	switch data[p] {
		case 9: goto tr445
		case 32: goto tr445
	}
	if 48 <= data[p] && data[p] <= 57 { goto st212 }
	goto st0
tr445:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st213
st213:
	p++
	if p == pe { goto _test_eof213 }
	fallthrough
case 213:
// line 15841 "zparse.go"
	switch data[p] {
		case 9: goto st213
		case 32: goto st213
		case 65: goto tr16
		case 67: goto tr17
		case 68: goto tr18
		case 72: goto tr19
		case 73: goto tr20
		case 77: goto tr21
		case 78: goto tr22
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr16
		case 99: goto tr17
		case 100: goto tr18
		case 104: goto tr19
		case 105: goto tr20
		case 109: goto tr21
		case 110: goto tr22
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr143 }
	goto st0
tr984:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st522
st522:
	p++
	if p == pe { goto _test_eof522 }
	fallthrough
case 522:
// line 15875 "zparse.go"
	switch data[p] {
		case 9: goto tr986
		case 32: goto st522
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr988 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr988:
// line 28 "zparse.rl"
	{ mark = p }
	goto st523
st523:
	p++
	if p == pe { goto _test_eof523 }
	fallthrough
case 523:
// line 15899 "zparse.go"
	switch data[p] {
		case 9: goto tr989
		case 32: goto tr990
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st523 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1426:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st214
tr1105:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st214
tr1102:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st214
tr992:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st214
tr989:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st214
tr1423:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st214
st214:
	p++
	if p == pe { goto _test_eof214 }
	fallthrough
case 214:
// line 16007 "zparse.go"
	switch data[p] {
		case 9: goto st214
		case 32: goto st214
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr449 }
	goto st0
tr449:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st215
st215:
	p++
	if p == pe { goto _test_eof215 }
	fallthrough
case 215:
// line 16043 "zparse.go"
	switch data[p] {
		case 9: goto tr450
		case 32: goto tr450
	}
	if 48 <= data[p] && data[p] <= 57 { goto st215 }
	goto st0
tr450:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st216
st216:
	p++
	if p == pe { goto _test_eof216 }
	fallthrough
case 216:
// line 16061 "zparse.go"
	switch data[p] {
		case 9: goto st216
		case 32: goto st216
		case 65: goto tr16
		case 67: goto tr17
		case 68: goto tr18
		case 72: goto tr19
		case 73: goto tr20
		case 77: goto tr21
		case 78: goto tr22
		case 82: goto tr23
		case 83: goto tr24
		case 97: goto tr16
		case 99: goto tr17
		case 100: goto tr18
		case 104: goto tr19
		case 105: goto tr20
		case 109: goto tr21
		case 110: goto tr22
		case 114: goto tr23
		case 115: goto tr24
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr147 }
	goto st0
tr990:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st524
st524:
	p++
	if p == pe { goto _test_eof524 }
	fallthrough
case 524:
// line 16095 "zparse.go"
	switch data[p] {
		case 9: goto tr992
		case 32: goto st524
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr994 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr994:
// line 28 "zparse.rl"
	{ mark = p }
	goto st525
st525:
	p++
	if p == pe { goto _test_eof525 }
	fallthrough
case 525:
// line 16119 "zparse.go"
	switch data[p] {
		case 9: goto tr995
		case 32: goto tr996
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st525 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1432:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st217
tr1111:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st217
tr1108:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st217
tr1316:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st217
tr995:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st217
tr1429:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st217
st217:
	p++
	if p == pe { goto _test_eof217 }
	fallthrough
case 217:
// line 16227 "zparse.go"
	switch data[p] {
		case 9: goto st217
		case 32: goto st217
		case 65: goto tr4
		case 67: goto tr5
		case 68: goto tr6
		case 72: goto tr7
		case 73: goto tr8
		case 77: goto tr9
		case 78: goto tr10
		case 82: goto tr11
		case 83: goto tr12
		case 97: goto tr4
		case 99: goto tr5
		case 100: goto tr6
		case 104: goto tr7
		case 105: goto tr8
		case 109: goto tr9
		case 110: goto tr10
		case 114: goto tr11
		case 115: goto tr12
	}
	if 48 <= data[p] && data[p] <= 57 { goto tr454 }
	goto st0
tr454:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st218
st218:
	p++
	if p == pe { goto _test_eof218 }
	fallthrough
case 218:
// line 16263 "zparse.go"
	switch data[p] {
		case 9: goto tr455
		case 32: goto tr455
	}
	if 48 <= data[p] && data[p] <= 57 { goto st218 }
	goto st0
tr455:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st219
st219:
	p++
	if p == pe { goto _test_eof219 }
	fallthrough
case 219:
// line 16281 "zparse.go"
	switch data[p] {
		case 9: goto st219
		case 32: goto st219
		case 46: goto tr151
		case 65: goto tr458
		case 67: goto tr459
		case 68: goto tr460
		case 72: goto tr461
		case 73: goto tr462
		case 77: goto tr463
		case 78: goto tr464
		case 82: goto tr465
		case 83: goto tr466
		case 92: goto tr151
		case 97: goto tr458
		case 99: goto tr459
		case 100: goto tr460
		case 104: goto tr461
		case 105: goto tr462
		case 109: goto tr463
		case 110: goto tr464
		case 114: goto tr465
		case 115: goto tr466
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr151 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr151 }
	} else {
		goto tr151
	}
	goto st0
tr458:
// line 28 "zparse.rl"
	{ mark = p }
	goto st220
st220:
	p++
	if p == pe { goto _test_eof220 }
	fallthrough
case 220:
// line 16323 "zparse.go"
	switch data[p] {
		case 9: goto tr467
		case 32: goto tr467
		case 46: goto st69
		case 78: goto st270
		case 92: goto st69
		case 110: goto st270
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr467:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st221
st221:
	p++
	if p == pe { goto _test_eof221 }
	fallthrough
case 221:
// line 16359 "zparse.go"
	switch data[p] {
		case 9: goto st221
		case 32: goto tr470
		case 46: goto tr471
		case 92: goto tr471
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr471 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr471 }
	} else {
		goto tr471
	}
	goto st0
tr470:
// line 28 "zparse.rl"
	{ mark = p }
	goto st526
st526:
	p++
	if p == pe { goto _test_eof526 }
	fallthrough
case 526:
// line 16383 "zparse.go"
	switch data[p] {
		case 9: goto tr998
		case 32: goto tr470
		case 46: goto tr471
		case 92: goto tr471
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr471 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr471 }
	} else {
		goto tr471
	}
	goto st0
tr998:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st222
st222:
	p++
	if p == pe { goto _test_eof222 }
	fallthrough
case 222:
// line 16420 "zparse.go"
	switch data[p] {
		case 9: goto st222
		case 32: goto tr473
		case 46: goto tr471
		case 65: goto tr475
		case 67: goto tr476
		case 68: goto tr477
		case 72: goto tr478
		case 73: goto tr479
		case 77: goto tr480
		case 78: goto tr481
		case 82: goto tr482
		case 83: goto tr483
		case 92: goto tr471
		case 97: goto tr475
		case 99: goto tr476
		case 100: goto tr477
		case 104: goto tr478
		case 105: goto tr479
		case 109: goto tr480
		case 110: goto tr481
		case 114: goto tr482
		case 115: goto tr483
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr474 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr471 }
	} else {
		goto tr471
	}
	goto st0
tr473:
// line 28 "zparse.rl"
	{ mark = p }
	goto st527
st527:
	p++
	if p == pe { goto _test_eof527 }
	fallthrough
case 527:
// line 16462 "zparse.go"
	switch data[p] {
		case 9: goto tr998
		case 32: goto tr473
		case 46: goto tr471
		case 65: goto tr475
		case 67: goto tr476
		case 68: goto tr477
		case 72: goto tr478
		case 73: goto tr479
		case 77: goto tr480
		case 78: goto tr481
		case 82: goto tr482
		case 83: goto tr483
		case 92: goto tr471
		case 97: goto tr475
		case 99: goto tr476
		case 100: goto tr477
		case 104: goto tr478
		case 105: goto tr479
		case 109: goto tr480
		case 110: goto tr481
		case 114: goto tr482
		case 115: goto tr483
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr474 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr471 }
	} else {
		goto tr471
	}
	goto st0
tr474:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st528
st528:
	p++
	if p == pe { goto _test_eof528 }
	fallthrough
case 528:
// line 16506 "zparse.go"
	switch data[p] {
		case 9: goto tr999
		case 32: goto tr1000
		case 46: goto st322
		case 92: goto st322
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st528 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
tr475:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st529
st529:
	p++
	if p == pe { goto _test_eof529 }
	fallthrough
case 529:
// line 16532 "zparse.go"
	switch data[p] {
		case 9: goto tr1002
		case 32: goto tr1003
		case 46: goto st322
		case 78: goto st740
		case 92: goto st322
		case 110: goto st740
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
tr1003:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	goto st530
tr1020:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st530
tr1142:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st530
tr1201:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st530
st530:
	p++
	if p == pe { goto _test_eof530 }
	fallthrough
case 530:
// line 16631 "zparse.go"
	switch data[p] {
		case 9: goto tr662
		case 32: goto st530
		case 46: goto tr471
		case 65: goto tr475
		case 67: goto tr476
		case 68: goto tr477
		case 72: goto tr478
		case 73: goto tr479
		case 77: goto tr480
		case 78: goto tr481
		case 82: goto tr482
		case 83: goto tr483
		case 92: goto tr471
		case 97: goto tr475
		case 99: goto tr476
		case 100: goto tr477
		case 104: goto tr478
		case 105: goto tr479
		case 109: goto tr480
		case 110: goto tr481
		case 114: goto tr482
		case 115: goto tr483
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr474 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr471 }
	} else {
		goto tr471
	}
	goto st0
tr476:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st531
st531:
	p++
	if p == pe { goto _test_eof531 }
	fallthrough
case 531:
// line 16675 "zparse.go"
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 72: goto st532
		case 78: goto st533
		case 83: goto st532
		case 92: goto st322
		case 104: goto st532
		case 110: goto st533
		case 115: goto st532
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st532:
	p++
	if p == pe { goto _test_eof532 }
	fallthrough
case 532:
	switch data[p] {
		case 9: goto tr1008
		case 32: goto tr1009
		case 46: goto st322
		case 92: goto st322
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st533:
	p++
	if p == pe { goto _test_eof533 }
	fallthrough
case 533:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 65: goto st534
		case 92: goto st322
		case 97: goto st534
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st534:
	p++
	if p == pe { goto _test_eof534 }
	fallthrough
case 534:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 77: goto st535
		case 92: goto st322
		case 109: goto st535
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st535:
	p++
	if p == pe { goto _test_eof535 }
	fallthrough
case 535:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 69: goto st536
		case 92: goto st322
		case 101: goto st536
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st536:
	p++
	if p == pe { goto _test_eof536 }
	fallthrough
case 536:
	switch data[p] {
		case 9: goto tr1013
		case 32: goto tr1014
		case 46: goto st322
		case 92: goto st322
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
tr1014:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st537
tr1030:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st537
tr1152:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st537
tr1211:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st537
st537:
	p++
	if p == pe { goto _test_eof537 }
	fallthrough
case 537:
// line 16879 "zparse.go"
	switch data[p] {
		case 9: goto tr682
		case 32: goto st537
		case 46: goto tr524
		case 65: goto tr528
		case 67: goto tr529
		case 68: goto tr530
		case 72: goto tr531
		case 73: goto tr532
		case 77: goto tr533
		case 78: goto tr534
		case 82: goto tr535
		case 83: goto tr536
		case 92: goto tr524
		case 97: goto tr528
		case 99: goto tr529
		case 100: goto tr530
		case 104: goto tr531
		case 105: goto tr532
		case 109: goto tr533
		case 110: goto tr534
		case 114: goto tr535
		case 115: goto tr536
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr527 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr524 }
	} else {
		goto tr524
	}
	goto st0
tr527:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st538
st538:
	p++
	if p == pe { goto _test_eof538 }
	fallthrough
case 538:
// line 16923 "zparse.go"
	switch data[p] {
		case 9: goto tr1016
		case 32: goto tr1017
		case 46: goto st337
		case 92: goto st337
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st538 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
tr528:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st539
st539:
	p++
	if p == pe { goto _test_eof539 }
	fallthrough
case 539:
// line 16949 "zparse.go"
	switch data[p] {
		case 9: goto tr1019
		case 32: goto tr1020
		case 46: goto st337
		case 78: goto st540
		case 92: goto st337
		case 110: goto st540
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st540:
	p++
	if p == pe { goto _test_eof540 }
	fallthrough
case 540:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 89: goto st541
		case 92: goto st337
		case 121: goto st541
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st541:
	p++
	if p == pe { goto _test_eof541 }
	fallthrough
case 541:
	switch data[p] {
		case 9: goto tr1023
		case 32: goto tr1024
		case 46: goto st337
		case 92: goto st337
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
tr529:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st542
st542:
	p++
	if p == pe { goto _test_eof542 }
	fallthrough
case 542:
// line 17017 "zparse.go"
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 72: goto st541
		case 78: goto st543
		case 83: goto st541
		case 92: goto st337
		case 104: goto st541
		case 110: goto st543
		case 115: goto st541
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st543:
	p++
	if p == pe { goto _test_eof543 }
	fallthrough
case 543:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 65: goto st544
		case 92: goto st337
		case 97: goto st544
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st544:
	p++
	if p == pe { goto _test_eof544 }
	fallthrough
case 544:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 77: goto st545
		case 92: goto st337
		case 109: goto st545
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st545:
	p++
	if p == pe { goto _test_eof545 }
	fallthrough
case 545:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 69: goto st546
		case 92: goto st337
		case 101: goto st546
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st546:
	p++
	if p == pe { goto _test_eof546 }
	fallthrough
case 546:
	switch data[p] {
		case 9: goto tr1029
		case 32: goto tr1030
		case 46: goto st337
		case 92: goto st337
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
tr530:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st547
st547:
	p++
	if p == pe { goto _test_eof547 }
	fallthrough
case 547:
// line 17131 "zparse.go"
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 78: goto st548
		case 83: goto st716
		case 92: goto st337
		case 110: goto st548
		case 115: goto st716
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st548:
	p++
	if p == pe { goto _test_eof548 }
	fallthrough
case 548:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 83: goto st549
		case 92: goto st337
		case 115: goto st549
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st549:
	p++
	if p == pe { goto _test_eof549 }
	fallthrough
case 549:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 75: goto st550
		case 92: goto st337
		case 107: goto st550
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st550:
	p++
	if p == pe { goto _test_eof550 }
	fallthrough
case 550:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 69: goto st551
		case 92: goto st337
		case 101: goto st551
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st551:
	p++
	if p == pe { goto _test_eof551 }
	fallthrough
case 551:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 89: goto st552
		case 92: goto st337
		case 121: goto st552
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st552:
	p++
	if p == pe { goto _test_eof552 }
	fallthrough
case 552:
	switch data[p] {
		case 9: goto tr1037
		case 32: goto tr1038
		case 46: goto st337
		case 92: goto st337
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
tr1295:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st553
tr1038:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st553
tr1160:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st553
tr1219:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st553
st553:
	p++
	if p == pe { goto _test_eof553 }
	fallthrough
case 553:
// line 17335 "zparse.go"
	switch data[p] {
		case 9: goto tr695
		case 32: goto st553
		case 46: goto st317
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto st317
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr549 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr549:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st554
st554:
	p++
	if p == pe { goto _test_eof554 }
	fallthrough
case 554:
// line 17379 "zparse.go"
	switch data[p] {
		case 9: goto tr1040
		case 32: goto tr1041
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st554 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1041:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st555
st555:
	p++
	if p == pe { goto _test_eof555 }
	fallthrough
case 555:
// line 17405 "zparse.go"
	switch data[p] {
		case 9: goto tr700
		case 32: goto st555
		case 46: goto st317
		case 65: goto tr499
		case 67: goto tr500
		case 68: goto tr501
		case 72: goto tr502
		case 73: goto tr503
		case 77: goto tr504
		case 78: goto tr505
		case 82: goto tr506
		case 83: goto tr507
		case 92: goto st317
		case 97: goto tr499
		case 99: goto tr500
		case 100: goto tr501
		case 104: goto tr502
		case 105: goto tr503
		case 109: goto tr504
		case 110: goto tr505
		case 114: goto tr506
		case 115: goto tr507
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr702 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr500:
// line 28 "zparse.rl"
	{ mark = p }
	goto st556
st556:
	p++
	if p == pe { goto _test_eof556 }
	fallthrough
case 556:
// line 17447 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 72: goto st557
		case 78: goto st332
		case 83: goto st557
		case 92: goto st317
		case 104: goto st557
		case 110: goto st332
		case 115: goto st557
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st557:
	p++
	if p == pe { goto _test_eof557 }
	fallthrough
case 557:
	switch data[p] {
		case 9: goto tr670
		case 32: goto tr1045
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr502:
// line 28 "zparse.rl"
	{ mark = p }
	goto st558
st558:
	p++
	if p == pe { goto _test_eof558 }
	fallthrough
case 558:
// line 17496 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 83: goto st557
		case 92: goto st317
		case 115: goto st557
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr503:
// line 28 "zparse.rl"
	{ mark = p }
	goto st559
st559:
	p++
	if p == pe { goto _test_eof559 }
	fallthrough
case 559:
// line 17522 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 78: goto st557
		case 92: goto st317
		case 110: goto st557
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr165:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st560
tr504:
// line 28 "zparse.rl"
	{ mark = p }
	goto st560
st560:
	p++
	if p == pe { goto _test_eof560 }
	fallthrough
case 560:
// line 17554 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 88: goto st561
		case 92: goto st317
		case 120: goto st561
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st561:
	p++
	if p == pe { goto _test_eof561 }
	fallthrough
case 561:
	switch data[p] {
		case 9: goto tr1047
		case 32: goto tr1048
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1048:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st562
st562:
	p++
	if p == pe { goto _test_eof562 }
	fallthrough
case 562:
// line 17607 "zparse.go"
	switch data[p] {
		case 9: goto tr1049
		case 32: goto st562
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr561 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr561:
// line 28 "zparse.rl"
	{ mark = p }
	goto st563
st563:
	p++
	if p == pe { goto _test_eof563 }
	fallthrough
case 563:
// line 17631 "zparse.go"
	switch data[p] {
		case 9: goto tr1051
		case 32: goto tr1052
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st563 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1052:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st564
st564:
	p++
	if p == pe { goto _test_eof564 }
	fallthrough
case 564:
// line 17655 "zparse.go"
	switch data[p] {
		case 9: goto tr1054
		case 32: goto st564
		case 46: goto tr1056
		case 92: goto tr1056
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1056 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1056 }
	} else {
		goto tr1056
	}
	goto st0
tr1056:
// line 28 "zparse.rl"
	{ mark = p }
	goto st565
st565:
	p++
	if p == pe { goto _test_eof565 }
	fallthrough
case 565:
// line 17679 "zparse.go"
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 92: goto st565
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
tr505:
// line 28 "zparse.rl"
	{ mark = p }
	goto st566
st566:
	p++
	if p == pe { goto _test_eof566 }
	fallthrough
case 566:
// line 17703 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 79: goto st567
		case 83: goto st569
		case 92: goto st317
		case 111: goto st567
		case 115: goto st569
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st567:
	p++
	if p == pe { goto _test_eof567 }
	fallthrough
case 567:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 78: goto st568
		case 92: goto st317
		case 110: goto st568
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st568:
	p++
	if p == pe { goto _test_eof568 }
	fallthrough
case 568:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 69: goto st557
		case 92: goto st317
		case 101: goto st557
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st569:
	p++
	if p == pe { goto _test_eof569 }
	fallthrough
case 569:
	switch data[p] {
		case 9: goto tr1063
		case 32: goto tr1064
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1064:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st570
st570:
	p++
	if p == pe { goto _test_eof570 }
	fallthrough
case 570:
// line 17800 "zparse.go"
	switch data[p] {
		case 9: goto tr1065
		case 32: goto st570
		case 46: goto tr571
		case 92: goto tr571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr571 }
	} else {
		goto tr571
	}
	goto st0
tr571:
// line 28 "zparse.rl"
	{ mark = p }
	goto st571
st571:
	p++
	if p == pe { goto _test_eof571 }
	fallthrough
case 571:
// line 17824 "zparse.go"
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 92: goto st571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
tr167:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st572
tr506:
// line 28 "zparse.rl"
	{ mark = p }
	goto st572
st572:
	p++
	if p == pe { goto _test_eof572 }
	fallthrough
case 572:
// line 17854 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 82: goto st573
		case 92: goto st317
		case 114: goto st573
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st573:
	p++
	if p == pe { goto _test_eof573 }
	fallthrough
case 573:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 83: goto st574
		case 92: goto st317
		case 115: goto st574
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st574:
	p++
	if p == pe { goto _test_eof574 }
	fallthrough
case 574:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 73: goto st575
		case 92: goto st317
		case 105: goto st575
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st575:
	p++
	if p == pe { goto _test_eof575 }
	fallthrough
case 575:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 71: goto st576
		case 92: goto st317
		case 103: goto st576
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st576:
	p++
	if p == pe { goto _test_eof576 }
	fallthrough
case 576:
	switch data[p] {
		case 9: goto tr1074
		case 32: goto tr1075
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1075:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st577
st577:
	p++
	if p == pe { goto _test_eof577 }
	fallthrough
case 577:
// line 17970 "zparse.go"
	switch data[p] {
		case 9: goto tr1076
		case 32: goto st577
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr591 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr591:
// line 28 "zparse.rl"
	{ mark = p }
	goto st578
st578:
	p++
	if p == pe { goto _test_eof578 }
	fallthrough
case 578:
// line 17994 "zparse.go"
	switch data[p] {
		case 9: goto tr1078
		case 32: goto tr1079
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st578 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1079:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st579
st579:
	p++
	if p == pe { goto _test_eof579 }
	fallthrough
case 579:
// line 18018 "zparse.go"
	switch data[p] {
		case 9: goto tr1081
		case 32: goto st579
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1083 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1083:
// line 28 "zparse.rl"
	{ mark = p }
	goto st580
st580:
	p++
	if p == pe { goto _test_eof580 }
	fallthrough
case 580:
// line 18042 "zparse.go"
	switch data[p] {
		case 9: goto tr1084
		case 32: goto tr1085
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st580 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1085:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st581
st581:
	p++
	if p == pe { goto _test_eof581 }
	fallthrough
case 581:
// line 18066 "zparse.go"
	switch data[p] {
		case 9: goto tr1087
		case 32: goto st581
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1089 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1089:
// line 28 "zparse.rl"
	{ mark = p }
	goto st582
st582:
	p++
	if p == pe { goto _test_eof582 }
	fallthrough
case 582:
// line 18090 "zparse.go"
	switch data[p] {
		case 9: goto tr1090
		case 32: goto tr1091
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st582 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1091:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st583
st583:
	p++
	if p == pe { goto _test_eof583 }
	fallthrough
case 583:
// line 18114 "zparse.go"
	switch data[p] {
		case 9: goto tr1093
		case 32: goto st583
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1095 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1095:
// line 28 "zparse.rl"
	{ mark = p }
	goto st584
st584:
	p++
	if p == pe { goto _test_eof584 }
	fallthrough
case 584:
// line 18138 "zparse.go"
	switch data[p] {
		case 9: goto tr1096
		case 32: goto tr1097
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st584 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1097:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st585
st585:
	p++
	if p == pe { goto _test_eof585 }
	fallthrough
case 585:
// line 18162 "zparse.go"
	switch data[p] {
		case 9: goto tr1099
		case 32: goto st585
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1101 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1101:
// line 28 "zparse.rl"
	{ mark = p }
	goto st586
st586:
	p++
	if p == pe { goto _test_eof586 }
	fallthrough
case 586:
// line 18186 "zparse.go"
	switch data[p] {
		case 9: goto tr1102
		case 32: goto tr1103
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st586 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1103:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st587
st587:
	p++
	if p == pe { goto _test_eof587 }
	fallthrough
case 587:
// line 18210 "zparse.go"
	switch data[p] {
		case 9: goto tr1105
		case 32: goto st587
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1107 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1107:
// line 28 "zparse.rl"
	{ mark = p }
	goto st588
st588:
	p++
	if p == pe { goto _test_eof588 }
	fallthrough
case 588:
// line 18234 "zparse.go"
	switch data[p] {
		case 9: goto tr1108
		case 32: goto tr1109
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st588 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1109:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st589
st589:
	p++
	if p == pe { goto _test_eof589 }
	fallthrough
case 589:
// line 18258 "zparse.go"
	switch data[p] {
		case 9: goto tr1111
		case 32: goto st589
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1113 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1113:
// line 28 "zparse.rl"
	{ mark = p }
	goto st590
st590:
	p++
	if p == pe { goto _test_eof590 }
	fallthrough
case 590:
// line 18282 "zparse.go"
	switch data[p] {
		case 9: goto tr1114
		case 32: goto tr1115
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st590 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1438:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	goto st223
tr1280:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st223
tr1114:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st223
tr1322:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	goto st223
tr1319:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st223
tr1435:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st223
st223:
	p++
	if p == pe { goto _test_eof223 }
	fallthrough
case 223:
// line 18390 "zparse.go"
	switch data[p] {
		case 9: goto st223
		case 32: goto st223
		case 46: goto tr151
		case 65: goto tr486
		case 67: goto tr487
		case 68: goto tr488
		case 72: goto tr489
		case 73: goto tr490
		case 77: goto tr491
		case 78: goto tr492
		case 82: goto tr493
		case 83: goto tr494
		case 92: goto tr151
		case 97: goto tr486
		case 99: goto tr487
		case 100: goto tr488
		case 104: goto tr489
		case 105: goto tr490
		case 109: goto tr491
		case 110: goto tr492
		case 114: goto tr493
		case 115: goto tr494
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr485 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr151 }
	} else {
		goto tr151
	}
	goto st0
tr485:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st224
st224:
	p++
	if p == pe { goto _test_eof224 }
	fallthrough
case 224:
// line 18434 "zparse.go"
	switch data[p] {
		case 9: goto tr495
		case 32: goto tr495
		case 46: goto st69
		case 92: goto st69
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st224 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr495:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st225
st225:
	p++
	if p == pe { goto _test_eof225 }
	fallthrough
case 225:
// line 18460 "zparse.go"
	switch data[p] {
		case 9: goto st225
		case 32: goto tr498
		case 46: goto tr156
		case 65: goto tr499
		case 67: goto tr500
		case 68: goto tr501
		case 72: goto tr502
		case 73: goto tr503
		case 77: goto tr504
		case 78: goto tr505
		case 82: goto tr506
		case 83: goto tr507
		case 92: goto tr156
		case 97: goto tr499
		case 99: goto tr500
		case 100: goto tr501
		case 104: goto tr502
		case 105: goto tr503
		case 109: goto tr504
		case 110: goto tr505
		case 114: goto tr506
		case 115: goto tr507
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr156 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr498:
// line 28 "zparse.rl"
	{ mark = p }
	goto st591
st591:
	p++
	if p == pe { goto _test_eof591 }
	fallthrough
case 591:
// line 18502 "zparse.go"
	switch data[p] {
		case 9: goto tr652
		case 32: goto tr498
		case 46: goto tr156
		case 65: goto tr499
		case 67: goto tr500
		case 68: goto tr501
		case 72: goto tr502
		case 73: goto tr503
		case 77: goto tr504
		case 78: goto tr505
		case 82: goto tr506
		case 83: goto tr507
		case 92: goto tr156
		case 97: goto tr499
		case 99: goto tr500
		case 100: goto tr501
		case 104: goto tr502
		case 105: goto tr503
		case 109: goto tr504
		case 110: goto tr505
		case 114: goto tr506
		case 115: goto tr507
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr156 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr168:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st592
tr507:
// line 28 "zparse.rl"
	{ mark = p }
	goto st592
st592:
	p++
	if p == pe { goto _test_eof592 }
	fallthrough
case 592:
// line 18550 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 79: goto st593
		case 92: goto st317
		case 111: goto st593
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st593:
	p++
	if p == pe { goto _test_eof593 }
	fallthrough
case 593:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 65: goto st594
		case 92: goto st317
		case 97: goto st594
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st594:
	p++
	if p == pe { goto _test_eof594 }
	fallthrough
case 594:
	switch data[p] {
		case 9: goto tr1119
		case 32: goto tr1120
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1122:
// line 28 "zparse.rl"
	{ mark = p }
	goto st595
tr1120:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st595
st595:
	p++
	if p == pe { goto _test_eof595 }
	fallthrough
case 595:
// line 18628 "zparse.go"
	switch data[p] {
		case 9: goto tr1121
		case 32: goto tr1122
		case 46: goto tr156
		case 92: goto tr156
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr156 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr486:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st226
st226:
	p++
	if p == pe { goto _test_eof226 }
	fallthrough
case 226:
// line 18654 "zparse.go"
	switch data[p] {
		case 9: goto tr467
		case 32: goto tr467
		case 46: goto st69
		case 78: goto st227
		case 92: goto st69
		case 110: goto st227
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st227:
	p++
	if p == pe { goto _test_eof227 }
	fallthrough
case 227:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 89: goto st228
		case 92: goto st69
		case 121: goto st228
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st228:
	p++
	if p == pe { goto _test_eof228 }
	fallthrough
case 228:
	switch data[p] {
		case 9: goto tr510
		case 32: goto tr510
		case 46: goto st69
		case 92: goto st69
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr510:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st229
st229:
	p++
	if p == pe { goto _test_eof229 }
	fallthrough
case 229:
// line 18722 "zparse.go"
	switch data[p] {
		case 9: goto st229
		case 32: goto tr512
		case 46: goto tr156
		case 65: goto tr514
		case 67: goto tr515
		case 68: goto tr501
		case 77: goto tr504
		case 78: goto tr516
		case 82: goto tr506
		case 83: goto tr507
		case 92: goto tr156
		case 97: goto tr514
		case 99: goto tr515
		case 100: goto tr501
		case 109: goto tr504
		case 110: goto tr516
		case 114: goto tr506
		case 115: goto tr507
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr513 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr512:
// line 28 "zparse.rl"
	{ mark = p }
	goto st596
st596:
	p++
	if p == pe { goto _test_eof596 }
	fallthrough
case 596:
// line 18760 "zparse.go"
	switch data[p] {
		case 9: goto tr652
		case 32: goto tr512
		case 46: goto tr156
		case 65: goto tr514
		case 67: goto tr515
		case 68: goto tr501
		case 77: goto tr504
		case 78: goto tr516
		case 82: goto tr506
		case 83: goto tr507
		case 92: goto tr156
		case 97: goto tr514
		case 99: goto tr515
		case 100: goto tr501
		case 109: goto tr504
		case 110: goto tr516
		case 114: goto tr506
		case 115: goto tr507
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr513 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr516:
// line 28 "zparse.rl"
	{ mark = p }
	goto st597
st597:
	p++
	if p == pe { goto _test_eof597 }
	fallthrough
case 597:
// line 18798 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 83: goto st569
		case 92: goto st317
		case 115: goto st569
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr487:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st230
st230:
	p++
	if p == pe { goto _test_eof230 }
	fallthrough
case 230:
// line 18826 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 72: goto st228
		case 78: goto st231
		case 83: goto st228
		case 92: goto st69
		case 104: goto st228
		case 110: goto st231
		case 115: goto st228
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st231:
	p++
	if p == pe { goto _test_eof231 }
	fallthrough
case 231:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 65: goto st232
		case 92: goto st69
		case 97: goto st232
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st232:
	p++
	if p == pe { goto _test_eof232 }
	fallthrough
case 232:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 77: goto st233
		case 92: goto st69
		case 109: goto st233
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st233:
	p++
	if p == pe { goto _test_eof233 }
	fallthrough
case 233:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 69: goto st234
		case 92: goto st69
		case 101: goto st234
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st234:
	p++
	if p == pe { goto _test_eof234 }
	fallthrough
case 234:
	switch data[p] {
		case 9: goto tr521
		case 32: goto tr521
		case 46: goto st69
		case 92: goto st69
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr521:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st235
st235:
	p++
	if p == pe { goto _test_eof235 }
	fallthrough
case 235:
// line 18948 "zparse.go"
	switch data[p] {
		case 9: goto st235
		case 32: goto tr523
		case 46: goto tr524
		case 92: goto tr524
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr524 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr524 }
	} else {
		goto tr524
	}
	goto st0
tr523:
// line 28 "zparse.rl"
	{ mark = p }
	goto st598
st598:
	p++
	if p == pe { goto _test_eof598 }
	fallthrough
case 598:
// line 18972 "zparse.go"
	switch data[p] {
		case 9: goto tr1123
		case 32: goto tr523
		case 46: goto tr524
		case 92: goto tr524
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr524 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr524 }
	} else {
		goto tr524
	}
	goto st0
tr1123:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st236
st236:
	p++
	if p == pe { goto _test_eof236 }
	fallthrough
case 236:
// line 19009 "zparse.go"
	switch data[p] {
		case 9: goto st236
		case 32: goto tr526
		case 46: goto tr524
		case 65: goto tr528
		case 67: goto tr529
		case 68: goto tr530
		case 72: goto tr531
		case 73: goto tr532
		case 77: goto tr533
		case 78: goto tr534
		case 82: goto tr535
		case 83: goto tr536
		case 92: goto tr524
		case 97: goto tr528
		case 99: goto tr529
		case 100: goto tr530
		case 104: goto tr531
		case 105: goto tr532
		case 109: goto tr533
		case 110: goto tr534
		case 114: goto tr535
		case 115: goto tr536
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr527 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr524 }
	} else {
		goto tr524
	}
	goto st0
tr526:
// line 28 "zparse.rl"
	{ mark = p }
	goto st599
st599:
	p++
	if p == pe { goto _test_eof599 }
	fallthrough
case 599:
// line 19051 "zparse.go"
	switch data[p] {
		case 9: goto tr1123
		case 32: goto tr526
		case 46: goto tr524
		case 65: goto tr528
		case 67: goto tr529
		case 68: goto tr530
		case 72: goto tr531
		case 73: goto tr532
		case 77: goto tr533
		case 78: goto tr534
		case 82: goto tr535
		case 83: goto tr536
		case 92: goto tr524
		case 97: goto tr528
		case 99: goto tr529
		case 100: goto tr530
		case 104: goto tr531
		case 105: goto tr532
		case 109: goto tr533
		case 110: goto tr534
		case 114: goto tr535
		case 115: goto tr536
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr527 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr524 }
	} else {
		goto tr524
	}
	goto st0
tr531:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st600
st600:
	p++
	if p == pe { goto _test_eof600 }
	fallthrough
case 600:
// line 19095 "zparse.go"
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 83: goto st541
		case 92: goto st337
		case 115: goto st541
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
tr532:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st601
st601:
	p++
	if p == pe { goto _test_eof601 }
	fallthrough
case 601:
// line 19123 "zparse.go"
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 78: goto st541
		case 92: goto st337
		case 110: goto st541
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
tr533:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st602
st602:
	p++
	if p == pe { goto _test_eof602 }
	fallthrough
case 602:
// line 19151 "zparse.go"
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 88: goto st603
		case 92: goto st337
		case 120: goto st603
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st603:
	p++
	if p == pe { goto _test_eof603 }
	fallthrough
case 603:
	switch data[p] {
		case 9: goto tr1125
		case 32: goto tr1126
		case 46: goto st337
		case 92: goto st337
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
tr1300:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st604
tr1126:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st604
tr1190:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st604
tr1224:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st604
st604:
	p++
	if p == pe { goto _test_eof604 }
	fallthrough
case 604:
// line 19269 "zparse.go"
	switch data[p] {
		case 9: goto tr1049
		case 32: goto st604
		case 46: goto st317
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto st317
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr564 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr564:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st605
st605:
	p++
	if p == pe { goto _test_eof605 }
	fallthrough
case 605:
// line 19313 "zparse.go"
	switch data[p] {
		case 9: goto tr1128
		case 32: goto tr1129
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st605 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1129:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st606
st606:
	p++
	if p == pe { goto _test_eof606 }
	fallthrough
case 606:
// line 19339 "zparse.go"
	switch data[p] {
		case 9: goto tr1054
		case 32: goto st606
		case 46: goto tr1056
		case 65: goto tr1132
		case 67: goto tr1133
		case 68: goto tr1134
		case 72: goto tr1135
		case 73: goto tr1136
		case 77: goto tr1137
		case 78: goto tr1138
		case 82: goto tr1139
		case 83: goto tr1140
		case 92: goto tr1056
		case 97: goto tr1132
		case 99: goto tr1133
		case 100: goto tr1134
		case 104: goto tr1135
		case 105: goto tr1136
		case 109: goto tr1137
		case 110: goto tr1138
		case 114: goto tr1139
		case 115: goto tr1140
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1056 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr1056 }
	} else {
		goto tr1056
	}
	goto st0
tr1132:
// line 28 "zparse.rl"
	{ mark = p }
	goto st607
st607:
	p++
	if p == pe { goto _test_eof607 }
	fallthrough
case 607:
// line 19381 "zparse.go"
	switch data[p] {
		case 9: goto tr1141
		case 32: goto tr1142
		case 46: goto st565
		case 78: goto st608
		case 92: goto st565
		case 110: goto st608
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st608:
	p++
	if p == pe { goto _test_eof608 }
	fallthrough
case 608:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 89: goto st609
		case 92: goto st565
		case 121: goto st609
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st609:
	p++
	if p == pe { goto _test_eof609 }
	fallthrough
case 609:
	switch data[p] {
		case 9: goto tr1145
		case 32: goto tr1146
		case 46: goto st565
		case 92: goto st565
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
tr1133:
// line 28 "zparse.rl"
	{ mark = p }
	goto st610
st610:
	p++
	if p == pe { goto _test_eof610 }
	fallthrough
case 610:
// line 19447 "zparse.go"
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 72: goto st609
		case 78: goto st611
		case 83: goto st609
		case 92: goto st565
		case 104: goto st609
		case 110: goto st611
		case 115: goto st609
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st611:
	p++
	if p == pe { goto _test_eof611 }
	fallthrough
case 611:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 65: goto st612
		case 92: goto st565
		case 97: goto st612
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st612:
	p++
	if p == pe { goto _test_eof612 }
	fallthrough
case 612:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 77: goto st613
		case 92: goto st565
		case 109: goto st613
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st613:
	p++
	if p == pe { goto _test_eof613 }
	fallthrough
case 613:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 69: goto st614
		case 92: goto st565
		case 101: goto st614
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st614:
	p++
	if p == pe { goto _test_eof614 }
	fallthrough
case 614:
	switch data[p] {
		case 9: goto tr1151
		case 32: goto tr1152
		case 46: goto st565
		case 92: goto st565
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
tr1134:
// line 28 "zparse.rl"
	{ mark = p }
	goto st615
st615:
	p++
	if p == pe { goto _test_eof615 }
	fallthrough
case 615:
// line 19559 "zparse.go"
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 78: goto st616
		case 83: goto st621
		case 92: goto st565
		case 110: goto st616
		case 115: goto st621
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st616:
	p++
	if p == pe { goto _test_eof616 }
	fallthrough
case 616:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 83: goto st617
		case 92: goto st565
		case 115: goto st617
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st617:
	p++
	if p == pe { goto _test_eof617 }
	fallthrough
case 617:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 75: goto st618
		case 92: goto st565
		case 107: goto st618
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st618:
	p++
	if p == pe { goto _test_eof618 }
	fallthrough
case 618:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 69: goto st619
		case 92: goto st565
		case 101: goto st619
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st619:
	p++
	if p == pe { goto _test_eof619 }
	fallthrough
case 619:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 89: goto st620
		case 92: goto st565
		case 121: goto st620
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st620:
	p++
	if p == pe { goto _test_eof620 }
	fallthrough
case 620:
	switch data[p] {
		case 9: goto tr1159
		case 32: goto tr1160
		case 46: goto st565
		case 92: goto st565
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st621:
	p++
	if p == pe { goto _test_eof621 }
	fallthrough
case 621:
	switch data[p] {
		case 9: goto tr1161
		case 32: goto tr1162
		case 46: goto st565
		case 92: goto st565
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
tr1297:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st622
tr1287:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st622
tr1162:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st622
tr1221:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st622
st622:
	p++
	if p == pe { goto _test_eof622 }
	fallthrough
case 622:
// line 19782 "zparse.go"
	switch data[p] {
		case 9: goto tr1163
		case 32: goto st622
		case 46: goto st317
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto st317
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr556 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr556:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st623
st623:
	p++
	if p == pe { goto _test_eof623 }
	fallthrough
case 623:
// line 19826 "zparse.go"
	switch data[p] {
		case 9: goto tr1165
		case 32: goto tr1166
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st623 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1166:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st624
st624:
	p++
	if p == pe { goto _test_eof624 }
	fallthrough
case 624:
// line 19852 "zparse.go"
	switch data[p] {
		case 9: goto tr1168
		case 32: goto st624
		case 46: goto st317
		case 65: goto tr499
		case 67: goto tr500
		case 68: goto tr501
		case 72: goto tr502
		case 73: goto tr503
		case 77: goto tr504
		case 78: goto tr505
		case 82: goto tr506
		case 83: goto tr507
		case 92: goto st317
		case 97: goto tr499
		case 99: goto tr500
		case 100: goto tr501
		case 104: goto tr502
		case 105: goto tr503
		case 109: goto tr504
		case 110: goto tr505
		case 114: goto tr506
		case 115: goto tr507
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1170 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1170:
// line 28 "zparse.rl"
	{ mark = p }
	goto st625
st625:
	p++
	if p == pe { goto _test_eof625 }
	fallthrough
case 625:
// line 19894 "zparse.go"
	switch data[p] {
		case 9: goto tr1171
		case 32: goto tr1172
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st625 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1172:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st626
st626:
	p++
	if p == pe { goto _test_eof626 }
	fallthrough
case 626:
// line 19918 "zparse.go"
	switch data[p] {
		case 9: goto tr1174
		case 32: goto st626
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1176 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1176:
// line 28 "zparse.rl"
	{ mark = p }
	goto st627
st627:
	p++
	if p == pe { goto _test_eof627 }
	fallthrough
case 627:
// line 19942 "zparse.go"
	switch data[p] {
		case 9: goto tr1177
		case 32: goto tr1178
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st627 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1178:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st628
st628:
	p++
	if p == pe { goto _test_eof628 }
	fallthrough
case 628:
// line 19966 "zparse.go"
	switch data[p] {
		case 9: goto tr1180
		case 32: goto tr1181
		case 46: goto tr1182
		case 92: goto tr1182
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1182 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1182 }
	} else {
		goto tr1182
	}
	goto st0
tr1181:
// line 28 "zparse.rl"
	{ mark = p }
	goto st629
st629:
	p++
	if p == pe { goto _test_eof629 }
	fallthrough
case 629:
// line 19990 "zparse.go"
	switch data[p] {
		case 9: goto tr1183
		case 32: goto tr1181
		case 46: goto tr1182
		case 92: goto tr1182
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1182 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1182 }
	} else {
		goto tr1182
	}
	goto st0
tr1182:
// line 28 "zparse.rl"
	{ mark = p }
	goto st630
st630:
	p++
	if p == pe { goto _test_eof630 }
	fallthrough
case 630:
// line 20014 "zparse.go"
	switch data[p] {
		case 9: goto tr1184
		case 32: goto st630
		case 46: goto st630
		case 92: goto st630
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st630 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st630 }
	} else {
		goto st630
	}
	goto st0
tr161:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st631
st631:
	p++
	if p == pe { goto _test_eof631 }
	fallthrough
case 631:
// line 20040 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 72: goto st326
		case 78: goto st332
		case 83: goto st326
		case 92: goto st317
		case 104: goto st326
		case 110: goto st332
		case 115: goto st326
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr163:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st632
st632:
	p++
	if p == pe { goto _test_eof632 }
	fallthrough
case 632:
// line 20072 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 83: goto st326
		case 92: goto st317
		case 115: goto st326
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr164:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st633
st633:
	p++
	if p == pe { goto _test_eof633 }
	fallthrough
case 633:
// line 20100 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 78: goto st326
		case 92: goto st317
		case 110: goto st326
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr166:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st634
st634:
	p++
	if p == pe { goto _test_eof634 }
	fallthrough
case 634:
// line 20128 "zparse.go"
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 79: goto st635
		case 83: goto st569
		case 92: goto st317
		case 111: goto st635
		case 115: goto st569
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st635:
	p++
	if p == pe { goto _test_eof635 }
	fallthrough
case 635:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 78: goto st636
		case 92: goto st317
		case 110: goto st636
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st636:
	p++
	if p == pe { goto _test_eof636 }
	fallthrough
case 636:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 69: goto st326
		case 92: goto st317
		case 101: goto st326
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1135:
// line 28 "zparse.rl"
	{ mark = p }
	goto st637
st637:
	p++
	if p == pe { goto _test_eof637 }
	fallthrough
case 637:
// line 20198 "zparse.go"
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 83: goto st609
		case 92: goto st565
		case 115: goto st609
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
tr1136:
// line 28 "zparse.rl"
	{ mark = p }
	goto st638
st638:
	p++
	if p == pe { goto _test_eof638 }
	fallthrough
case 638:
// line 20224 "zparse.go"
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 78: goto st609
		case 92: goto st565
		case 110: goto st609
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
tr1137:
// line 28 "zparse.rl"
	{ mark = p }
	goto st639
st639:
	p++
	if p == pe { goto _test_eof639 }
	fallthrough
case 639:
// line 20250 "zparse.go"
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 88: goto st640
		case 92: goto st565
		case 120: goto st640
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st640:
	p++
	if p == pe { goto _test_eof640 }
	fallthrough
case 640:
	switch data[p] {
		case 9: goto tr1189
		case 32: goto tr1190
		case 46: goto st565
		case 92: goto st565
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
tr1138:
// line 28 "zparse.rl"
	{ mark = p }
	goto st641
st641:
	p++
	if p == pe { goto _test_eof641 }
	fallthrough
case 641:
// line 20295 "zparse.go"
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 79: goto st642
		case 83: goto st644
		case 92: goto st565
		case 111: goto st642
		case 115: goto st644
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st642:
	p++
	if p == pe { goto _test_eof642 }
	fallthrough
case 642:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 78: goto st643
		case 92: goto st565
		case 110: goto st643
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st643:
	p++
	if p == pe { goto _test_eof643 }
	fallthrough
case 643:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 69: goto st609
		case 92: goto st565
		case 101: goto st609
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st644:
	p++
	if p == pe { goto _test_eof644 }
	fallthrough
case 644:
	switch data[p] {
		case 9: goto tr1194
		case 32: goto tr1195
		case 46: goto st565
		case 92: goto st565
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
tr1305:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st645
tr1260:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	goto st645
tr1195:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st645
tr1229:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	goto st645
st645:
	p++
	if p == pe { goto _test_eof645 }
	fallthrough
case 645:
// line 20457 "zparse.go"
	switch data[p] {
		case 9: goto tr1065
		case 32: goto st645
		case 46: goto tr571
		case 65: goto tr575
		case 67: goto tr576
		case 68: goto tr577
		case 72: goto tr578
		case 73: goto tr579
		case 77: goto tr580
		case 78: goto tr581
		case 82: goto tr582
		case 83: goto tr583
		case 92: goto tr571
		case 97: goto tr575
		case 99: goto tr576
		case 100: goto tr577
		case 104: goto tr578
		case 105: goto tr579
		case 109: goto tr580
		case 110: goto tr581
		case 114: goto tr582
		case 115: goto tr583
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr574 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr571 }
	} else {
		goto tr571
	}
	goto st0
tr574:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st646
st646:
	p++
	if p == pe { goto _test_eof646 }
	fallthrough
case 646:
// line 20501 "zparse.go"
	switch data[p] {
		case 9: goto tr1197
		case 32: goto tr1198
		case 46: goto st571
		case 92: goto st571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st646 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
tr575:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st647
st647:
	p++
	if p == pe { goto _test_eof647 }
	fallthrough
case 647:
// line 20527 "zparse.go"
	switch data[p] {
		case 9: goto tr1200
		case 32: goto tr1201
		case 46: goto st571
		case 78: goto st648
		case 92: goto st571
		case 110: goto st648
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st648:
	p++
	if p == pe { goto _test_eof648 }
	fallthrough
case 648:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 89: goto st649
		case 92: goto st571
		case 121: goto st649
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st649:
	p++
	if p == pe { goto _test_eof649 }
	fallthrough
case 649:
	switch data[p] {
		case 9: goto tr1204
		case 32: goto tr1205
		case 46: goto st571
		case 92: goto st571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
tr576:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st650
st650:
	p++
	if p == pe { goto _test_eof650 }
	fallthrough
case 650:
// line 20595 "zparse.go"
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 72: goto st649
		case 78: goto st651
		case 83: goto st649
		case 92: goto st571
		case 104: goto st649
		case 110: goto st651
		case 115: goto st649
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st651:
	p++
	if p == pe { goto _test_eof651 }
	fallthrough
case 651:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 65: goto st652
		case 92: goto st571
		case 97: goto st652
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st652:
	p++
	if p == pe { goto _test_eof652 }
	fallthrough
case 652:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 77: goto st653
		case 92: goto st571
		case 109: goto st653
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st653:
	p++
	if p == pe { goto _test_eof653 }
	fallthrough
case 653:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 69: goto st654
		case 92: goto st571
		case 101: goto st654
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st654:
	p++
	if p == pe { goto _test_eof654 }
	fallthrough
case 654:
	switch data[p] {
		case 9: goto tr1210
		case 32: goto tr1211
		case 46: goto st571
		case 92: goto st571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
tr577:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st655
st655:
	p++
	if p == pe { goto _test_eof655 }
	fallthrough
case 655:
// line 20709 "zparse.go"
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 78: goto st656
		case 83: goto st661
		case 92: goto st571
		case 110: goto st656
		case 115: goto st661
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st656:
	p++
	if p == pe { goto _test_eof656 }
	fallthrough
case 656:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 83: goto st657
		case 92: goto st571
		case 115: goto st657
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st657:
	p++
	if p == pe { goto _test_eof657 }
	fallthrough
case 657:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 75: goto st658
		case 92: goto st571
		case 107: goto st658
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st658:
	p++
	if p == pe { goto _test_eof658 }
	fallthrough
case 658:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 69: goto st659
		case 92: goto st571
		case 101: goto st659
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st659:
	p++
	if p == pe { goto _test_eof659 }
	fallthrough
case 659:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 89: goto st660
		case 92: goto st571
		case 121: goto st660
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st660:
	p++
	if p == pe { goto _test_eof660 }
	fallthrough
case 660:
	switch data[p] {
		case 9: goto tr1218
		case 32: goto tr1219
		case 46: goto st571
		case 92: goto st571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st661:
	p++
	if p == pe { goto _test_eof661 }
	fallthrough
case 661:
	switch data[p] {
		case 9: goto tr1220
		case 32: goto tr1221
		case 46: goto st571
		case 92: goto st571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
tr578:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st662
st662:
	p++
	if p == pe { goto _test_eof662 }
	fallthrough
case 662:
// line 20861 "zparse.go"
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 83: goto st649
		case 92: goto st571
		case 115: goto st649
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
tr579:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st663
st663:
	p++
	if p == pe { goto _test_eof663 }
	fallthrough
case 663:
// line 20889 "zparse.go"
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 78: goto st649
		case 92: goto st571
		case 110: goto st649
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
tr580:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st664
st664:
	p++
	if p == pe { goto _test_eof664 }
	fallthrough
case 664:
// line 20917 "zparse.go"
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 88: goto st665
		case 92: goto st571
		case 120: goto st665
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st665:
	p++
	if p == pe { goto _test_eof665 }
	fallthrough
case 665:
	switch data[p] {
		case 9: goto tr1223
		case 32: goto tr1224
		case 46: goto st571
		case 92: goto st571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
tr581:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st666
st666:
	p++
	if p == pe { goto _test_eof666 }
	fallthrough
case 666:
// line 20964 "zparse.go"
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 79: goto st667
		case 83: goto st669
		case 92: goto st571
		case 111: goto st667
		case 115: goto st669
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st667:
	p++
	if p == pe { goto _test_eof667 }
	fallthrough
case 667:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 78: goto st668
		case 92: goto st571
		case 110: goto st668
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st668:
	p++
	if p == pe { goto _test_eof668 }
	fallthrough
case 668:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 69: goto st649
		case 92: goto st571
		case 101: goto st649
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st669:
	p++
	if p == pe { goto _test_eof669 }
	fallthrough
case 669:
	switch data[p] {
		case 9: goto tr1228
		case 32: goto tr1229
		case 46: goto st571
		case 92: goto st571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
tr582:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st670
st670:
	p++
	if p == pe { goto _test_eof670 }
	fallthrough
case 670:
// line 21055 "zparse.go"
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 82: goto st671
		case 92: goto st571
		case 114: goto st671
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st671:
	p++
	if p == pe { goto _test_eof671 }
	fallthrough
case 671:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 83: goto st672
		case 92: goto st571
		case 115: goto st672
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st672:
	p++
	if p == pe { goto _test_eof672 }
	fallthrough
case 672:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 73: goto st673
		case 92: goto st571
		case 105: goto st673
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st673:
	p++
	if p == pe { goto _test_eof673 }
	fallthrough
case 673:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 71: goto st674
		case 92: goto st571
		case 103: goto st674
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st674:
	p++
	if p == pe { goto _test_eof674 }
	fallthrough
case 674:
	switch data[p] {
		case 9: goto tr1234
		case 32: goto tr1235
		case 46: goto st571
		case 92: goto st571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
tr1311:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st675
tr1266:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st675
tr1251:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st675
tr1235:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st675
st675:
	p++
	if p == pe { goto _test_eof675 }
	fallthrough
case 675:
// line 21236 "zparse.go"
	switch data[p] {
		case 9: goto tr1076
		case 32: goto st675
		case 46: goto st317
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto st317
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr594 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr594:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st676
st676:
	p++
	if p == pe { goto _test_eof676 }
	fallthrough
case 676:
// line 21280 "zparse.go"
	switch data[p] {
		case 9: goto tr1237
		case 32: goto tr1238
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st676 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1238:
// line 35 "zparse.rl"
	{ ttl, _ :=  strconv.Atoi(data[mark:p]); hdr.Ttl = uint32(ttl) }
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st677
st677:
	p++
	if p == pe { goto _test_eof677 }
	fallthrough
case 677:
// line 21306 "zparse.go"
	switch data[p] {
		case 9: goto tr1081
		case 32: goto st677
		case 46: goto st317
		case 65: goto tr499
		case 67: goto tr500
		case 68: goto tr501
		case 72: goto tr502
		case 73: goto tr503
		case 77: goto tr504
		case 78: goto tr505
		case 82: goto tr506
		case 83: goto tr507
		case 92: goto st317
		case 97: goto tr499
		case 99: goto tr500
		case 100: goto tr501
		case 104: goto tr502
		case 105: goto tr503
		case 109: goto tr504
		case 110: goto tr505
		case 114: goto tr506
		case 115: goto tr507
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1083 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr583:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st678
st678:
	p++
	if p == pe { goto _test_eof678 }
	fallthrough
case 678:
// line 21350 "zparse.go"
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 79: goto st679
		case 92: goto st571
		case 111: goto st679
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st679:
	p++
	if p == pe { goto _test_eof679 }
	fallthrough
case 679:
	switch data[p] {
		case 9: goto tr1067
		case 32: goto tr1068
		case 46: goto st571
		case 65: goto st680
		case 92: goto st571
		case 97: goto st680
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
st680:
	p++
	if p == pe { goto _test_eof680 }
	fallthrough
case 680:
	switch data[p] {
		case 9: goto tr1243
		case 32: goto tr1244
		case 46: goto st571
		case 92: goto st571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st571 }
	} else {
		goto st571
	}
	goto st0
tr1245:
// line 28 "zparse.rl"
	{ mark = p }
	goto st681
tr1315:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st681
tr1270:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st681
tr1255:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	goto st681
tr1244:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st681
st681:
	p++
	if p == pe { goto _test_eof681 }
	fallthrough
case 681:
// line 21493 "zparse.go"
	switch data[p] {
		case 9: goto tr1121
		case 32: goto tr1245
		case 46: goto tr156
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto tr156
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr159 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr1139:
// line 28 "zparse.rl"
	{ mark = p }
	goto st682
st682:
	p++
	if p == pe { goto _test_eof682 }
	fallthrough
case 682:
// line 21535 "zparse.go"
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 82: goto st683
		case 92: goto st565
		case 114: goto st683
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st683:
	p++
	if p == pe { goto _test_eof683 }
	fallthrough
case 683:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 83: goto st684
		case 92: goto st565
		case 115: goto st684
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st684:
	p++
	if p == pe { goto _test_eof684 }
	fallthrough
case 684:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 73: goto st685
		case 92: goto st565
		case 105: goto st685
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st685:
	p++
	if p == pe { goto _test_eof685 }
	fallthrough
case 685:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 71: goto st686
		case 92: goto st565
		case 103: goto st686
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st686:
	p++
	if p == pe { goto _test_eof686 }
	fallthrough
case 686:
	switch data[p] {
		case 9: goto tr1250
		case 32: goto tr1251
		case 46: goto st565
		case 92: goto st565
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
tr1140:
// line 28 "zparse.rl"
	{ mark = p }
	goto st687
st687:
	p++
	if p == pe { goto _test_eof687 }
	fallthrough
case 687:
// line 21643 "zparse.go"
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 79: goto st688
		case 92: goto st565
		case 111: goto st688
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st688:
	p++
	if p == pe { goto _test_eof688 }
	fallthrough
case 688:
	switch data[p] {
		case 9: goto tr1057
		case 32: goto tr1058
		case 46: goto st565
		case 65: goto st689
		case 92: goto st565
		case 97: goto st689
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
st689:
	p++
	if p == pe { goto _test_eof689 }
	fallthrough
case 689:
	switch data[p] {
		case 9: goto tr1254
		case 32: goto tr1255
		case 46: goto st565
		case 92: goto st565
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st565 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st565 }
	} else {
		goto st565
	}
	goto st0
tr534:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st690
st690:
	p++
	if p == pe { goto _test_eof690 }
	fallthrough
case 690:
// line 21711 "zparse.go"
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 79: goto st691
		case 83: goto st693
		case 92: goto st337
		case 111: goto st691
		case 115: goto st693
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st691:
	p++
	if p == pe { goto _test_eof691 }
	fallthrough
case 691:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 78: goto st692
		case 92: goto st337
		case 110: goto st692
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st692:
	p++
	if p == pe { goto _test_eof692 }
	fallthrough
case 692:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 69: goto st541
		case 92: goto st337
		case 101: goto st541
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st693:
	p++
	if p == pe { goto _test_eof693 }
	fallthrough
case 693:
	switch data[p] {
		case 9: goto tr1259
		case 32: goto tr1260
		case 46: goto st337
		case 92: goto st337
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
tr535:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st694
st694:
	p++
	if p == pe { goto _test_eof694 }
	fallthrough
case 694:
// line 21802 "zparse.go"
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 82: goto st695
		case 92: goto st337
		case 114: goto st695
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st695:
	p++
	if p == pe { goto _test_eof695 }
	fallthrough
case 695:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 83: goto st696
		case 92: goto st337
		case 115: goto st696
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st696:
	p++
	if p == pe { goto _test_eof696 }
	fallthrough
case 696:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 73: goto st697
		case 92: goto st337
		case 105: goto st697
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st697:
	p++
	if p == pe { goto _test_eof697 }
	fallthrough
case 697:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 71: goto st698
		case 92: goto st337
		case 103: goto st698
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st698:
	p++
	if p == pe { goto _test_eof698 }
	fallthrough
case 698:
	switch data[p] {
		case 9: goto tr1265
		case 32: goto tr1266
		case 46: goto st337
		case 92: goto st337
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
tr536:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st699
st699:
	p++
	if p == pe { goto _test_eof699 }
	fallthrough
case 699:
// line 21912 "zparse.go"
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 79: goto st700
		case 92: goto st337
		case 111: goto st700
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st700:
	p++
	if p == pe { goto _test_eof700 }
	fallthrough
case 700:
	switch data[p] {
		case 9: goto tr684
		case 32: goto tr685
		case 46: goto st337
		case 65: goto st701
		case 92: goto st337
		case 97: goto st701
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
st701:
	p++
	if p == pe { goto _test_eof701 }
	fallthrough
case 701:
	switch data[p] {
		case 9: goto tr1269
		case 32: goto tr1270
		case 46: goto st337
		case 92: goto st337
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
tr488:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st237
tr460:
// line 28 "zparse.rl"
	{ mark = p }
	goto st237
st237:
	p++
	if p == pe { goto _test_eof237 }
	fallthrough
case 237:
// line 21984 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 78: goto st238
		case 83: goto st245
		case 92: goto st69
		case 110: goto st238
		case 115: goto st245
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st238:
	p++
	if p == pe { goto _test_eof238 }
	fallthrough
case 238:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 83: goto st239
		case 92: goto st69
		case 115: goto st239
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st239:
	p++
	if p == pe { goto _test_eof239 }
	fallthrough
case 239:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 75: goto st240
		case 92: goto st69
		case 107: goto st240
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st240:
	p++
	if p == pe { goto _test_eof240 }
	fallthrough
case 240:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 69: goto st241
		case 92: goto st69
		case 101: goto st241
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st241:
	p++
	if p == pe { goto _test_eof241 }
	fallthrough
case 241:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 89: goto st242
		case 92: goto st69
		case 121: goto st242
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st242:
	p++
	if p == pe { goto _test_eof242 }
	fallthrough
case 242:
	switch data[p] {
		case 9: goto tr543
		case 32: goto tr543
		case 46: goto st69
		case 92: goto st69
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr543:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st243
st243:
	p++
	if p == pe { goto _test_eof243 }
	fallthrough
case 243:
// line 22125 "zparse.go"
	switch data[p] {
		case 9: goto st243
		case 32: goto tr545
		case 46: goto tr156
		case 92: goto tr156
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr546 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr545:
// line 28 "zparse.rl"
	{ mark = p }
	goto st702
st702:
	p++
	if p == pe { goto _test_eof702 }
	fallthrough
case 702:
// line 22149 "zparse.go"
	switch data[p] {
		case 9: goto tr1271
		case 32: goto tr545
		case 46: goto tr156
		case 92: goto tr156
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr546 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr1271:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st244
st244:
	p++
	if p == pe { goto _test_eof244 }
	fallthrough
case 244:
// line 22186 "zparse.go"
	switch data[p] {
		case 9: goto st244
		case 32: goto tr548
		case 46: goto tr156
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto tr156
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr549 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr548:
// line 28 "zparse.rl"
	{ mark = p }
	goto st703
st703:
	p++
	if p == pe { goto _test_eof703 }
	fallthrough
case 703:
// line 22228 "zparse.go"
	switch data[p] {
		case 9: goto tr1271
		case 32: goto tr548
		case 46: goto tr156
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto tr156
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr549 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
st245:
	p++
	if p == pe { goto _test_eof245 }
	fallthrough
case 245:
	switch data[p] {
		case 9: goto tr550
		case 32: goto tr550
		case 46: goto st69
		case 92: goto st69
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr550:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st246
st246:
	p++
	if p == pe { goto _test_eof246 }
	fallthrough
case 246:
// line 22299 "zparse.go"
	switch data[p] {
		case 9: goto st246
		case 32: goto tr552
		case 46: goto tr156
		case 92: goto tr156
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr553 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr552:
// line 28 "zparse.rl"
	{ mark = p }
	goto st704
st704:
	p++
	if p == pe { goto _test_eof704 }
	fallthrough
case 704:
// line 22323 "zparse.go"
	switch data[p] {
		case 9: goto tr1272
		case 32: goto tr552
		case 46: goto tr156
		case 92: goto tr156
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr553 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr1272:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st247
st247:
	p++
	if p == pe { goto _test_eof247 }
	fallthrough
case 247:
// line 22360 "zparse.go"
	switch data[p] {
		case 9: goto st247
		case 32: goto tr555
		case 46: goto tr156
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto tr156
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr556 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr555:
// line 28 "zparse.rl"
	{ mark = p }
	goto st705
st705:
	p++
	if p == pe { goto _test_eof705 }
	fallthrough
case 705:
// line 22402 "zparse.go"
	switch data[p] {
		case 9: goto tr1272
		case 32: goto tr555
		case 46: goto tr156
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto tr156
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr556 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr553:
// line 28 "zparse.rl"
	{ mark = p }
	goto st706
st706:
	p++
	if p == pe { goto _test_eof706 }
	fallthrough
case 706:
// line 22444 "zparse.go"
	switch data[p] {
		case 9: goto tr1273
		case 32: goto tr1274
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st706 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1274:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st707
st707:
	p++
	if p == pe { goto _test_eof707 }
	fallthrough
case 707:
// line 22468 "zparse.go"
	switch data[p] {
		case 9: goto tr1168
		case 32: goto st707
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1170 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr489:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st248
st248:
	p++
	if p == pe { goto _test_eof248 }
	fallthrough
case 248:
// line 22494 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 83: goto st228
		case 92: goto st69
		case 115: goto st228
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr490:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st249
st249:
	p++
	if p == pe { goto _test_eof249 }
	fallthrough
case 249:
// line 22522 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 78: goto st228
		case 92: goto st69
		case 110: goto st228
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr491:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st250
tr463:
// line 28 "zparse.rl"
	{ mark = p }
	goto st250
st250:
	p++
	if p == pe { goto _test_eof250 }
	fallthrough
case 250:
// line 22554 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 88: goto st251
		case 92: goto st69
		case 120: goto st251
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st251:
	p++
	if p == pe { goto _test_eof251 }
	fallthrough
case 251:
	switch data[p] {
		case 9: goto tr558
		case 32: goto tr558
		case 46: goto st69
		case 92: goto st69
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr558:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st252
st252:
	p++
	if p == pe { goto _test_eof252 }
	fallthrough
case 252:
// line 22609 "zparse.go"
	switch data[p] {
		case 9: goto st252
		case 32: goto tr560
		case 46: goto tr156
		case 92: goto tr156
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr561 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr560:
// line 28 "zparse.rl"
	{ mark = p }
	goto st708
st708:
	p++
	if p == pe { goto _test_eof708 }
	fallthrough
case 708:
// line 22633 "zparse.go"
	switch data[p] {
		case 9: goto tr1277
		case 32: goto tr560
		case 46: goto tr156
		case 92: goto tr156
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr561 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr1277:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st253
st253:
	p++
	if p == pe { goto _test_eof253 }
	fallthrough
case 253:
// line 22670 "zparse.go"
	switch data[p] {
		case 9: goto st253
		case 32: goto tr563
		case 46: goto tr156
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto tr156
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr564 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr563:
// line 28 "zparse.rl"
	{ mark = p }
	goto st709
st709:
	p++
	if p == pe { goto _test_eof709 }
	fallthrough
case 709:
// line 22712 "zparse.go"
	switch data[p] {
		case 9: goto tr1277
		case 32: goto tr563
		case 46: goto tr156
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto tr156
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr564 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr492:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st254
st254:
	p++
	if p == pe { goto _test_eof254 }
	fallthrough
case 254:
// line 22756 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 79: goto st255
		case 83: goto st257
		case 92: goto st69
		case 111: goto st255
		case 115: goto st257
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st255:
	p++
	if p == pe { goto _test_eof255 }
	fallthrough
case 255:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 78: goto st256
		case 92: goto st69
		case 110: goto st256
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st256:
	p++
	if p == pe { goto _test_eof256 }
	fallthrough
case 256:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 69: goto st228
		case 92: goto st69
		case 101: goto st228
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st257:
	p++
	if p == pe { goto _test_eof257 }
	fallthrough
case 257:
	switch data[p] {
		case 9: goto tr568
		case 32: goto tr568
		case 46: goto st69
		case 92: goto st69
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr568:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st258
st258:
	p++
	if p == pe { goto _test_eof258 }
	fallthrough
case 258:
// line 22855 "zparse.go"
	switch data[p] {
		case 9: goto st258
		case 32: goto tr570
		case 46: goto tr571
		case 92: goto tr571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr571 }
	} else {
		goto tr571
	}
	goto st0
tr570:
// line 28 "zparse.rl"
	{ mark = p }
	goto st710
st710:
	p++
	if p == pe { goto _test_eof710 }
	fallthrough
case 710:
// line 22879 "zparse.go"
	switch data[p] {
		case 9: goto tr1278
		case 32: goto tr570
		case 46: goto tr571
		case 92: goto tr571
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr571 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr571 }
	} else {
		goto tr571
	}
	goto st0
tr1278:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st259
st259:
	p++
	if p == pe { goto _test_eof259 }
	fallthrough
case 259:
// line 22916 "zparse.go"
	switch data[p] {
		case 9: goto st259
		case 32: goto tr573
		case 46: goto tr571
		case 65: goto tr575
		case 67: goto tr576
		case 68: goto tr577
		case 72: goto tr578
		case 73: goto tr579
		case 77: goto tr580
		case 78: goto tr581
		case 82: goto tr582
		case 83: goto tr583
		case 92: goto tr571
		case 97: goto tr575
		case 99: goto tr576
		case 100: goto tr577
		case 104: goto tr578
		case 105: goto tr579
		case 109: goto tr580
		case 110: goto tr581
		case 114: goto tr582
		case 115: goto tr583
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr574 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr571 }
	} else {
		goto tr571
	}
	goto st0
tr573:
// line 28 "zparse.rl"
	{ mark = p }
	goto st711
st711:
	p++
	if p == pe { goto _test_eof711 }
	fallthrough
case 711:
// line 22958 "zparse.go"
	switch data[p] {
		case 9: goto tr1278
		case 32: goto tr573
		case 46: goto tr571
		case 65: goto tr575
		case 67: goto tr576
		case 68: goto tr577
		case 72: goto tr578
		case 73: goto tr579
		case 77: goto tr580
		case 78: goto tr581
		case 82: goto tr582
		case 83: goto tr583
		case 92: goto tr571
		case 97: goto tr575
		case 99: goto tr576
		case 100: goto tr577
		case 104: goto tr578
		case 105: goto tr579
		case 109: goto tr580
		case 110: goto tr581
		case 114: goto tr582
		case 115: goto tr583
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr574 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr571 }
	} else {
		goto tr571
	}
	goto st0
tr493:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st260
tr465:
// line 28 "zparse.rl"
	{ mark = p }
	goto st260
st260:
	p++
	if p == pe { goto _test_eof260 }
	fallthrough
case 260:
// line 23006 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 82: goto st261
		case 92: goto st69
		case 114: goto st261
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st261:
	p++
	if p == pe { goto _test_eof261 }
	fallthrough
case 261:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 83: goto st262
		case 92: goto st69
		case 115: goto st262
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st262:
	p++
	if p == pe { goto _test_eof262 }
	fallthrough
case 262:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 73: goto st263
		case 92: goto st69
		case 105: goto st263
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st263:
	p++
	if p == pe { goto _test_eof263 }
	fallthrough
case 263:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 71: goto st264
		case 92: goto st69
		case 103: goto st264
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st264:
	p++
	if p == pe { goto _test_eof264 }
	fallthrough
case 264:
	switch data[p] {
		case 9: goto tr588
		case 32: goto tr588
		case 46: goto st69
		case 92: goto st69
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr588:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st265
st265:
	p++
	if p == pe { goto _test_eof265 }
	fallthrough
case 265:
// line 23124 "zparse.go"
	switch data[p] {
		case 9: goto st265
		case 32: goto tr590
		case 46: goto tr156
		case 92: goto tr156
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr591 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr590:
// line 28 "zparse.rl"
	{ mark = p }
	goto st712
st712:
	p++
	if p == pe { goto _test_eof712 }
	fallthrough
case 712:
// line 23148 "zparse.go"
	switch data[p] {
		case 9: goto tr1279
		case 32: goto tr590
		case 46: goto tr156
		case 92: goto tr156
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr591 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr1279:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	goto st266
st266:
	p++
	if p == pe { goto _test_eof266 }
	fallthrough
case 266:
// line 23185 "zparse.go"
	switch data[p] {
		case 9: goto st266
		case 32: goto tr593
		case 46: goto tr156
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto tr156
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr594 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr593:
// line 28 "zparse.rl"
	{ mark = p }
	goto st713
st713:
	p++
	if p == pe { goto _test_eof713 }
	fallthrough
case 713:
// line 23227 "zparse.go"
	switch data[p] {
		case 9: goto tr1279
		case 32: goto tr593
		case 46: goto tr156
		case 65: goto tr160
		case 67: goto tr161
		case 68: goto tr162
		case 72: goto tr163
		case 73: goto tr164
		case 77: goto tr165
		case 78: goto tr166
		case 82: goto tr167
		case 83: goto tr168
		case 92: goto tr156
		case 97: goto tr160
		case 99: goto tr161
		case 100: goto tr162
		case 104: goto tr163
		case 105: goto tr164
		case 109: goto tr165
		case 110: goto tr166
		case 114: goto tr167
		case 115: goto tr168
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr594 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr494:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st267
tr466:
// line 28 "zparse.rl"
	{ mark = p }
	goto st267
st267:
	p++
	if p == pe { goto _test_eof267 }
	fallthrough
case 267:
// line 23275 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 79: goto st268
		case 92: goto st69
		case 111: goto st268
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st268:
	p++
	if p == pe { goto _test_eof268 }
	fallthrough
case 268:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 65: goto st269
		case 92: goto st69
		case 97: goto st269
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st269:
	p++
	if p == pe { goto _test_eof269 }
	fallthrough
case 269:
	switch data[p] {
		case 9: goto tr597
		case 32: goto tr597
		case 46: goto st69
		case 92: goto st69
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr1115:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st714
st714:
	p++
	if p == pe { goto _test_eof714 }
	fallthrough
case 714:
// line 23341 "zparse.go"
	switch data[p] {
		case 9: goto tr1280
		case 32: goto st714
		case 46: goto tr1282
		case 92: goto tr1282
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1282 }
	} else {
		goto tr1282
	}
	goto st0
tr1282:
// line 28 "zparse.rl"
	{ mark = p }
	goto st715
st715:
	p++
	if p == pe { goto _test_eof715 }
	fallthrough
case 715:
// line 23365 "zparse.go"
	switch data[p] {
		case 9: goto tr1283
		case 32: goto tr1284
		case 46: goto st715
		case 92: goto st715
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st715 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st715 }
	} else {
		goto st715
	}
	goto st0
st716:
	p++
	if p == pe { goto _test_eof716 }
	fallthrough
case 716:
	switch data[p] {
		case 9: goto tr1286
		case 32: goto tr1287
		case 46: goto st337
		case 92: goto st337
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st337 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st337 }
	} else {
		goto st337
	}
	goto st0
tr477:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st717
st717:
	p++
	if p == pe { goto _test_eof717 }
	fallthrough
case 717:
// line 23410 "zparse.go"
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 78: goto st718
		case 83: goto st723
		case 92: goto st322
		case 110: goto st718
		case 115: goto st723
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st718:
	p++
	if p == pe { goto _test_eof718 }
	fallthrough
case 718:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 83: goto st719
		case 92: goto st322
		case 115: goto st719
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st719:
	p++
	if p == pe { goto _test_eof719 }
	fallthrough
case 719:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 75: goto st720
		case 92: goto st322
		case 107: goto st720
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st720:
	p++
	if p == pe { goto _test_eof720 }
	fallthrough
case 720:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 69: goto st721
		case 92: goto st322
		case 101: goto st721
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st721:
	p++
	if p == pe { goto _test_eof721 }
	fallthrough
case 721:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 89: goto st722
		case 92: goto st322
		case 121: goto st722
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st722:
	p++
	if p == pe { goto _test_eof722 }
	fallthrough
case 722:
	switch data[p] {
		case 9: goto tr1294
		case 32: goto tr1295
		case 46: goto st322
		case 92: goto st322
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st723:
	p++
	if p == pe { goto _test_eof723 }
	fallthrough
case 723:
	switch data[p] {
		case 9: goto tr1296
		case 32: goto tr1297
		case 46: goto st322
		case 92: goto st322
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
tr478:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st724
st724:
	p++
	if p == pe { goto _test_eof724 }
	fallthrough
case 724:
// line 23562 "zparse.go"
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 83: goto st532
		case 92: goto st322
		case 115: goto st532
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
tr479:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st725
st725:
	p++
	if p == pe { goto _test_eof725 }
	fallthrough
case 725:
// line 23590 "zparse.go"
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 78: goto st532
		case 92: goto st322
		case 110: goto st532
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
tr480:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st726
st726:
	p++
	if p == pe { goto _test_eof726 }
	fallthrough
case 726:
// line 23618 "zparse.go"
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 88: goto st727
		case 92: goto st322
		case 120: goto st727
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st727:
	p++
	if p == pe { goto _test_eof727 }
	fallthrough
case 727:
	switch data[p] {
		case 9: goto tr1299
		case 32: goto tr1300
		case 46: goto st322
		case 92: goto st322
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
tr481:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st728
st728:
	p++
	if p == pe { goto _test_eof728 }
	fallthrough
case 728:
// line 23665 "zparse.go"
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 79: goto st729
		case 83: goto st731
		case 92: goto st322
		case 111: goto st729
		case 115: goto st731
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st729:
	p++
	if p == pe { goto _test_eof729 }
	fallthrough
case 729:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 78: goto st730
		case 92: goto st322
		case 110: goto st730
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st730:
	p++
	if p == pe { goto _test_eof730 }
	fallthrough
case 730:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 69: goto st532
		case 92: goto st322
		case 101: goto st532
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st731:
	p++
	if p == pe { goto _test_eof731 }
	fallthrough
case 731:
	switch data[p] {
		case 9: goto tr1304
		case 32: goto tr1305
		case 46: goto st322
		case 92: goto st322
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
tr482:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st732
st732:
	p++
	if p == pe { goto _test_eof732 }
	fallthrough
case 732:
// line 23756 "zparse.go"
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 82: goto st733
		case 92: goto st322
		case 114: goto st733
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st733:
	p++
	if p == pe { goto _test_eof733 }
	fallthrough
case 733:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 83: goto st734
		case 92: goto st322
		case 115: goto st734
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st734:
	p++
	if p == pe { goto _test_eof734 }
	fallthrough
case 734:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 73: goto st735
		case 92: goto st322
		case 105: goto st735
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st735:
	p++
	if p == pe { goto _test_eof735 }
	fallthrough
case 735:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 71: goto st736
		case 92: goto st322
		case 103: goto st736
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st736:
	p++
	if p == pe { goto _test_eof736 }
	fallthrough
case 736:
	switch data[p] {
		case 9: goto tr1310
		case 32: goto tr1311
		case 46: goto st322
		case 92: goto st322
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
tr483:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st737
st737:
	p++
	if p == pe { goto _test_eof737 }
	fallthrough
case 737:
// line 23866 "zparse.go"
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 79: goto st738
		case 92: goto st322
		case 111: goto st738
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st738:
	p++
	if p == pe { goto _test_eof738 }
	fallthrough
case 738:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 65: goto st739
		case 92: goto st322
		case 97: goto st739
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st739:
	p++
	if p == pe { goto _test_eof739 }
	fallthrough
case 739:
	switch data[p] {
		case 9: goto tr1314
		case 32: goto tr1315
		case 46: goto st322
		case 92: goto st322
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st740:
	p++
	if p == pe { goto _test_eof740 }
	fallthrough
case 740:
	switch data[p] {
		case 9: goto tr664
		case 32: goto tr665
		case 46: goto st322
		case 89: goto st532
		case 92: goto st322
		case 121: goto st532
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st322 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st322 }
	} else {
		goto st322
	}
	goto st0
st270:
	p++
	if p == pe { goto _test_eof270 }
	fallthrough
case 270:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 89: goto st271
		case 92: goto st69
		case 121: goto st271
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st271:
	p++
	if p == pe { goto _test_eof271 }
	fallthrough
case 271:
	switch data[p] {
		case 9: goto tr599
		case 32: goto tr599
		case 46: goto st69
		case 92: goto st69
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr599:
// line 33 "zparse.rl"
	{ hdr.Class = Str_class[data[mark:p]] }
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st272
st272:
	p++
	if p == pe { goto _test_eof272 }
	fallthrough
case 272:
// line 23995 "zparse.go"
	switch data[p] {
		case 9: goto st272
		case 32: goto tr601
		case 46: goto tr156
		case 65: goto tr514
		case 67: goto tr515
		case 68: goto tr501
		case 77: goto tr504
		case 78: goto tr516
		case 82: goto tr506
		case 83: goto tr507
		case 92: goto tr156
		case 97: goto tr514
		case 99: goto tr515
		case 100: goto tr501
		case 109: goto tr504
		case 110: goto tr516
		case 114: goto tr506
		case 115: goto tr507
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr156 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr601:
// line 28 "zparse.rl"
	{ mark = p }
	goto st741
st741:
	p++
	if p == pe { goto _test_eof741 }
	fallthrough
case 741:
// line 24033 "zparse.go"
	switch data[p] {
		case 9: goto tr652
		case 32: goto tr601
		case 46: goto tr156
		case 65: goto tr514
		case 67: goto tr515
		case 68: goto tr501
		case 77: goto tr504
		case 78: goto tr516
		case 82: goto tr506
		case 83: goto tr507
		case 92: goto tr156
		case 97: goto tr514
		case 99: goto tr515
		case 100: goto tr501
		case 109: goto tr504
		case 110: goto tr516
		case 114: goto tr506
		case 115: goto tr507
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto tr156 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto tr156 }
	} else {
		goto tr156
	}
	goto st0
tr459:
// line 28 "zparse.rl"
	{ mark = p }
	goto st273
st273:
	p++
	if p == pe { goto _test_eof273 }
	fallthrough
case 273:
// line 24071 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 72: goto st271
		case 78: goto st231
		case 83: goto st271
		case 92: goto st69
		case 104: goto st271
		case 110: goto st231
		case 115: goto st271
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr461:
// line 28 "zparse.rl"
	{ mark = p }
	goto st274
st274:
	p++
	if p == pe { goto _test_eof274 }
	fallthrough
case 274:
// line 24101 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 83: goto st271
		case 92: goto st69
		case 115: goto st271
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr462:
// line 28 "zparse.rl"
	{ mark = p }
	goto st275
st275:
	p++
	if p == pe { goto _test_eof275 }
	fallthrough
case 275:
// line 24127 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 78: goto st271
		case 92: goto st69
		case 110: goto st271
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr464:
// line 28 "zparse.rl"
	{ mark = p }
	goto st276
st276:
	p++
	if p == pe { goto _test_eof276 }
	fallthrough
case 276:
// line 24153 "zparse.go"
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 79: goto st277
		case 83: goto st257
		case 92: goto st69
		case 111: goto st277
		case 115: goto st257
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st277:
	p++
	if p == pe { goto _test_eof277 }
	fallthrough
case 277:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 78: goto st278
		case 92: goto st69
		case 110: goto st278
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
st278:
	p++
	if p == pe { goto _test_eof278 }
	fallthrough
case 278:
	switch data[p] {
		case 9: goto tr152
		case 32: goto tr152
		case 46: goto st69
		case 69: goto st271
		case 92: goto st69
		case 101: goto st271
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st69 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st69 }
	} else {
		goto st69
	}
	goto st0
tr996:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st742
st742:
	p++
	if p == pe { goto _test_eof742 }
	fallthrough
case 742:
// line 24223 "zparse.go"
	switch data[p] {
		case 9: goto tr1316
		case 32: goto st742
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1318 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1318:
// line 28 "zparse.rl"
	{ mark = p }
	goto st743
st743:
	p++
	if p == pe { goto _test_eof743 }
	fallthrough
case 743:
// line 24247 "zparse.go"
	switch data[p] {
		case 9: goto tr1319
		case 32: goto tr1320
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st743 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1320:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st744
st744:
	p++
	if p == pe { goto _test_eof744 }
	fallthrough
case 744:
// line 24271 "zparse.go"
	switch data[p] {
		case 9: goto tr1322
		case 32: goto st744
		case 46: goto tr1324
		case 92: goto tr1324
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1324 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1324 }
	} else {
		goto tr1324
	}
	goto st0
tr1324:
// line 28 "zparse.rl"
	{ mark = p }
	goto st745
st745:
	p++
	if p == pe { goto _test_eof745 }
	fallthrough
case 745:
// line 24295 "zparse.go"
	switch data[p] {
		case 9: goto tr1325
		case 32: goto tr1326
		case 46: goto st745
		case 92: goto st745
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st745 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st745 }
	} else {
		goto st745
	}
	goto st0
tr1326:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st746
st746:
	p++
	if p == pe { goto _test_eof746 }
	fallthrough
case 746:
// line 24319 "zparse.go"
	switch data[p] {
		case 9: goto tr1328
		case 32: goto tr1329
		case 46: goto tr1182
		case 92: goto tr1182
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1182 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1182 }
	} else {
		goto tr1182
	}
	goto st0
tr1329:
// line 28 "zparse.rl"
	{ mark = p }
	goto st747
st747:
	p++
	if p == pe { goto _test_eof747 }
	fallthrough
case 747:
// line 24343 "zparse.go"
	switch data[p] {
		case 9: goto tr1330
		case 32: goto tr1329
		case 46: goto tr1182
		case 92: goto tr1182
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1182 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1182 }
	} else {
		goto tr1182
	}
	goto st0
tr231:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st748
tr251:
// line 28 "zparse.rl"
	{ mark = p }
	goto st748
st748:
	p++
	if p == pe { goto _test_eof748 }
	fallthrough
case 748:
// line 24373 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 79: goto st749
		case 92: goto st383
		case 111: goto st749
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st749:
	p++
	if p == pe { goto _test_eof749 }
	fallthrough
case 749:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 65: goto st750
		case 92: goto st383
		case 97: goto st750
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st750:
	p++
	if p == pe { goto _test_eof750 }
	fallthrough
case 750:
	switch data[p] {
		case 9: goto tr1333
		case 32: goto tr1334
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1336:
// line 28 "zparse.rl"
	{ mark = p }
	goto st751
tr1334:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st751
st751:
	p++
	if p == pe { goto _test_eof751 }
	fallthrough
case 751:
// line 24451 "zparse.go"
	switch data[p] {
		case 9: goto tr1335
		case 32: goto tr1336
		case 46: goto tr219
		case 92: goto tr219
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr219 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr219 }
	} else {
		goto tr219
	}
	goto st0
tr852:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st752
st752:
	p++
	if p == pe { goto _test_eof752 }
	fallthrough
case 752:
// line 24475 "zparse.go"
	switch data[p] {
		case 9: goto tr1337
		case 32: goto st752
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1339 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr1339:
// line 28 "zparse.rl"
	{ mark = p }
	goto st753
st753:
	p++
	if p == pe { goto _test_eof753 }
	fallthrough
case 753:
// line 24499 "zparse.go"
	switch data[p] {
		case 9: goto tr1340
		case 32: goto tr1341
		case 46: goto st383
		case 92: goto st383
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st753 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr792:
// line 28 "zparse.rl"
	{ mark = p }
	goto st754
st754:
	p++
	if p == pe { goto _test_eof754 }
	fallthrough
case 754:
// line 24523 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 83: goto st506
		case 92: goto st383
		case 115: goto st506
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr224:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st755
st755:
	p++
	if p == pe { goto _test_eof755 }
	fallthrough
case 755:
// line 24551 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 72: goto st392
		case 78: goto st398
		case 83: goto st392
		case 92: goto st383
		case 104: goto st392
		case 110: goto st398
		case 115: goto st392
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr226:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st756
st756:
	p++
	if p == pe { goto _test_eof756 }
	fallthrough
case 756:
// line 24583 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 83: goto st392
		case 92: goto st383
		case 115: goto st392
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr227:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st757
st757:
	p++
	if p == pe { goto _test_eof757 }
	fallthrough
case 757:
// line 24611 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 78: goto st392
		case 92: goto st383
		case 110: goto st392
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr229:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st758
st758:
	p++
	if p == pe { goto _test_eof758 }
	fallthrough
case 758:
// line 24639 "zparse.go"
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 79: goto st759
		case 83: goto st506
		case 92: goto st383
		case 111: goto st759
		case 115: goto st506
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st759:
	p++
	if p == pe { goto _test_eof759 }
	fallthrough
case 759:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 78: goto st760
		case 92: goto st383
		case 110: goto st760
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st760:
	p++
	if p == pe { goto _test_eof760 }
	fallthrough
case 760:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 69: goto st392
		case 92: goto st383
		case 101: goto st392
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
st761:
	p++
	if p == pe { goto _test_eof761 }
	fallthrough
case 761:
	switch data[p] {
		case 9: goto tr768
		case 32: goto st383
		case 46: goto st383
		case 89: goto st426
		case 92: goto st383
		case 121: goto st426
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st383 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st383 }
	} else {
		goto st383
	}
	goto st0
tr766:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st762
st762:
	p++
	if p == pe { goto _test_eof762 }
	fallthrough
case 762:
// line 24738 "zparse.go"
	switch data[p] {
		case 9: goto tr1345
		case 32: goto st762
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1347 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1347:
// line 28 "zparse.rl"
	{ mark = p }
	goto st763
st763:
	p++
	if p == pe { goto _test_eof763 }
	fallthrough
case 763:
// line 24762 "zparse.go"
	switch data[p] {
		case 9: goto tr1348
		case 32: goto tr1349
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st763 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1349:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st764
st764:
	p++
	if p == pe { goto _test_eof764 }
	fallthrough
case 764:
// line 24786 "zparse.go"
	switch data[p] {
		case 9: goto tr1351
		case 32: goto st764
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1353 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1353:
// line 28 "zparse.rl"
	{ mark = p }
	goto st765
st765:
	p++
	if p == pe { goto _test_eof765 }
	fallthrough
case 765:
// line 24810 "zparse.go"
	switch data[p] {
		case 9: goto tr1354
		case 32: goto tr1355
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st765 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1355:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st766
st766:
	p++
	if p == pe { goto _test_eof766 }
	fallthrough
case 766:
// line 24834 "zparse.go"
	switch data[p] {
		case 9: goto tr1357
		case 32: goto st766
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1359 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1359:
// line 28 "zparse.rl"
	{ mark = p }
	goto st767
st767:
	p++
	if p == pe { goto _test_eof767 }
	fallthrough
case 767:
// line 24858 "zparse.go"
	switch data[p] {
		case 9: goto tr1360
		case 32: goto tr1361
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st767 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1361:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st768
st768:
	p++
	if p == pe { goto _test_eof768 }
	fallthrough
case 768:
// line 24882 "zparse.go"
	switch data[p] {
		case 9: goto tr1363
		case 32: goto tr1364
		case 46: goto tr836
		case 92: goto tr836
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr836 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr836 }
	} else {
		goto tr836
	}
	goto st0
tr1364:
// line 28 "zparse.rl"
	{ mark = p }
	goto st769
st769:
	p++
	if p == pe { goto _test_eof769 }
	fallthrough
case 769:
// line 24906 "zparse.go"
	switch data[p] {
		case 9: goto tr1365
		case 32: goto tr1364
		case 46: goto tr836
		case 92: goto tr836
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr836 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr836 }
	} else {
		goto tr836
	}
	goto st0
tr72:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st770
tr201:
// line 28 "zparse.rl"
	{ mark = p }
	goto st770
st770:
	p++
	if p == pe { goto _test_eof770 }
	fallthrough
case 770:
// line 24936 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 88: goto st771
		case 92: goto st285
		case 120: goto st771
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st771:
	p++
	if p == pe { goto _test_eof771 }
	fallthrough
case 771:
	switch data[p] {
		case 9: goto tr1367
		case 32: goto tr1368
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1368:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st772
st772:
	p++
	if p == pe { goto _test_eof772 }
	fallthrough
case 772:
// line 24989 "zparse.go"
	switch data[p] {
		case 9: goto tr1369
		case 32: goto st772
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1371 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1371:
// line 28 "zparse.rl"
	{ mark = p }
	goto st773
st773:
	p++
	if p == pe { goto _test_eof773 }
	fallthrough
case 773:
// line 25013 "zparse.go"
	switch data[p] {
		case 9: goto tr1372
		case 32: goto tr1373
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st773 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1373:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st774
st774:
	p++
	if p == pe { goto _test_eof774 }
	fallthrough
case 774:
// line 25037 "zparse.go"
	switch data[p] {
		case 9: goto tr1375
		case 32: goto st774
		case 46: goto tr1377
		case 92: goto tr1377
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1377 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1377 }
	} else {
		goto tr1377
	}
	goto st0
tr1377:
// line 28 "zparse.rl"
	{ mark = p }
	goto st775
st775:
	p++
	if p == pe { goto _test_eof775 }
	fallthrough
case 775:
// line 25061 "zparse.go"
	switch data[p] {
		case 9: goto tr1378
		case 32: goto tr1379
		case 46: goto st775
		case 92: goto st775
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st775 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st775 }
	} else {
		goto st775
	}
	goto st0
tr713:
// line 28 "zparse.rl"
	{ mark = p }
	goto st776
st776:
	p++
	if p == pe { goto _test_eof776 }
	fallthrough
case 776:
// line 25085 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 83: goto st777
		case 92: goto st285
		case 115: goto st777
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st777:
	p++
	if p == pe { goto _test_eof777 }
	fallthrough
case 777:
	switch data[p] {
		case 9: goto tr1382
		case 32: goto tr1383
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1383:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st778
st778:
	p++
	if p == pe { goto _test_eof778 }
	fallthrough
case 778:
// line 25138 "zparse.go"
	switch data[p] {
		case 9: goto tr1384
		case 32: goto st778
		case 46: goto tr1386
		case 92: goto tr1386
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1386 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1386 }
	} else {
		goto tr1386
	}
	goto st0
tr1386:
// line 28 "zparse.rl"
	{ mark = p }
	goto st779
st779:
	p++
	if p == pe { goto _test_eof779 }
	fallthrough
case 779:
// line 25162 "zparse.go"
	switch data[p] {
		case 9: goto tr1387
		case 32: goto tr1388
		case 46: goto st779
		case 92: goto st779
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st779 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st779 }
	} else {
		goto st779
	}
	goto st0
tr74:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st780
tr203:
// line 28 "zparse.rl"
	{ mark = p }
	goto st780
st780:
	p++
	if p == pe { goto _test_eof780 }
	fallthrough
case 780:
// line 25192 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 82: goto st781
		case 92: goto st285
		case 114: goto st781
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st781:
	p++
	if p == pe { goto _test_eof781 }
	fallthrough
case 781:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 83: goto st782
		case 92: goto st285
		case 115: goto st782
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st782:
	p++
	if p == pe { goto _test_eof782 }
	fallthrough
case 782:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 73: goto st783
		case 92: goto st285
		case 105: goto st783
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st783:
	p++
	if p == pe { goto _test_eof783 }
	fallthrough
case 783:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 71: goto st784
		case 92: goto st285
		case 103: goto st784
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st784:
	p++
	if p == pe { goto _test_eof784 }
	fallthrough
case 784:
	switch data[p] {
		case 9: goto tr1394
		case 32: goto tr1395
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1395:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st785
st785:
	p++
	if p == pe { goto _test_eof785 }
	fallthrough
case 785:
// line 25308 "zparse.go"
	switch data[p] {
		case 9: goto tr1396
		case 32: goto st785
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1398 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1398:
// line 28 "zparse.rl"
	{ mark = p }
	goto st786
st786:
	p++
	if p == pe { goto _test_eof786 }
	fallthrough
case 786:
// line 25332 "zparse.go"
	switch data[p] {
		case 9: goto tr1399
		case 32: goto tr1400
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st786 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1400:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st787
st787:
	p++
	if p == pe { goto _test_eof787 }
	fallthrough
case 787:
// line 25356 "zparse.go"
	switch data[p] {
		case 9: goto tr1402
		case 32: goto st787
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1404 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1404:
// line 28 "zparse.rl"
	{ mark = p }
	goto st788
st788:
	p++
	if p == pe { goto _test_eof788 }
	fallthrough
case 788:
// line 25380 "zparse.go"
	switch data[p] {
		case 9: goto tr1405
		case 32: goto tr1406
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st788 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1406:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st789
st789:
	p++
	if p == pe { goto _test_eof789 }
	fallthrough
case 789:
// line 25404 "zparse.go"
	switch data[p] {
		case 9: goto tr1408
		case 32: goto st789
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1410 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1410:
// line 28 "zparse.rl"
	{ mark = p }
	goto st790
st790:
	p++
	if p == pe { goto _test_eof790 }
	fallthrough
case 790:
// line 25428 "zparse.go"
	switch data[p] {
		case 9: goto tr1411
		case 32: goto tr1412
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st790 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1412:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st791
st791:
	p++
	if p == pe { goto _test_eof791 }
	fallthrough
case 791:
// line 25452 "zparse.go"
	switch data[p] {
		case 9: goto tr1414
		case 32: goto st791
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1416 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1416:
// line 28 "zparse.rl"
	{ mark = p }
	goto st792
st792:
	p++
	if p == pe { goto _test_eof792 }
	fallthrough
case 792:
// line 25476 "zparse.go"
	switch data[p] {
		case 9: goto tr1417
		case 32: goto tr1418
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st792 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1418:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st793
st793:
	p++
	if p == pe { goto _test_eof793 }
	fallthrough
case 793:
// line 25500 "zparse.go"
	switch data[p] {
		case 9: goto tr1420
		case 32: goto st793
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1422 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1422:
// line 28 "zparse.rl"
	{ mark = p }
	goto st794
st794:
	p++
	if p == pe { goto _test_eof794 }
	fallthrough
case 794:
// line 25524 "zparse.go"
	switch data[p] {
		case 9: goto tr1423
		case 32: goto tr1424
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st794 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1424:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st795
st795:
	p++
	if p == pe { goto _test_eof795 }
	fallthrough
case 795:
// line 25548 "zparse.go"
	switch data[p] {
		case 9: goto tr1426
		case 32: goto st795
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1428 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1428:
// line 28 "zparse.rl"
	{ mark = p }
	goto st796
st796:
	p++
	if p == pe { goto _test_eof796 }
	fallthrough
case 796:
// line 25572 "zparse.go"
	switch data[p] {
		case 9: goto tr1429
		case 32: goto tr1430
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st796 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1430:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st797
st797:
	p++
	if p == pe { goto _test_eof797 }
	fallthrough
case 797:
// line 25596 "zparse.go"
	switch data[p] {
		case 9: goto tr1432
		case 32: goto st797
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1434 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1434:
// line 28 "zparse.rl"
	{ mark = p }
	goto st798
st798:
	p++
	if p == pe { goto _test_eof798 }
	fallthrough
case 798:
// line 25620 "zparse.go"
	switch data[p] {
		case 9: goto tr1435
		case 32: goto tr1436
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st798 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1436:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st799
st799:
	p++
	if p == pe { goto _test_eof799 }
	fallthrough
case 799:
// line 25644 "zparse.go"
	switch data[p] {
		case 9: goto tr1438
		case 32: goto st799
		case 46: goto tr1440
		case 92: goto tr1440
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1440 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1440 }
	} else {
		goto tr1440
	}
	goto st0
tr1440:
// line 28 "zparse.rl"
	{ mark = p }
	goto st800
st800:
	p++
	if p == pe { goto _test_eof800 }
	fallthrough
case 800:
// line 25668 "zparse.go"
	switch data[p] {
		case 9: goto tr1441
		case 32: goto tr1442
		case 46: goto st800
		case 92: goto st800
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st800 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st800 }
	} else {
		goto st800
	}
	goto st0
tr1442:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
	goto st801
st801:
	p++
	if p == pe { goto _test_eof801 }
	fallthrough
case 801:
// line 25692 "zparse.go"
	switch data[p] {
		case 9: goto tr1444
		case 32: goto tr1445
		case 46: goto tr1446
		case 92: goto tr1446
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1446 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1446 }
	} else {
		goto tr1446
	}
	goto st0
tr1445:
// line 28 "zparse.rl"
	{ mark = p }
	goto st802
st802:
	p++
	if p == pe { goto _test_eof802 }
	fallthrough
case 802:
// line 25716 "zparse.go"
	switch data[p] {
		case 9: goto tr1447
		case 32: goto tr1445
		case 46: goto tr1446
		case 92: goto tr1446
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1446 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1446 }
	} else {
		goto tr1446
	}
	goto st0
tr1446:
// line 28 "zparse.rl"
	{ mark = p }
	goto st803
st803:
	p++
	if p == pe { goto _test_eof803 }
	fallthrough
case 803:
// line 25740 "zparse.go"
	switch data[p] {
		case 9: goto tr1448
		case 32: goto st803
		case 46: goto st803
		case 92: goto st803
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st803 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st803 }
	} else {
		goto st803
	}
	goto st0
tr75:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st804
tr204:
// line 28 "zparse.rl"
	{ mark = p }
	goto st804
st804:
	p++
	if p == pe { goto _test_eof804 }
	fallthrough
case 804:
// line 25770 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 79: goto st805
		case 92: goto st285
		case 111: goto st805
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st805:
	p++
	if p == pe { goto _test_eof805 }
	fallthrough
case 805:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 65: goto st806
		case 92: goto st285
		case 97: goto st806
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st806:
	p++
	if p == pe { goto _test_eof806 }
	fallthrough
case 806:
	switch data[p] {
		case 9: goto tr1452
		case 32: goto tr1453
		case 46: goto st285
		case 92: goto st285
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr1455:
// line 28 "zparse.rl"
	{ mark = p }
	goto st807
tr1453:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st807
st807:
	p++
	if p == pe { goto _test_eof807 }
	fallthrough
case 807:
// line 25848 "zparse.go"
	switch data[p] {
		case 9: goto tr1454
		case 32: goto tr1455
		case 46: goto tr63
		case 92: goto tr63
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr63 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr63 }
	} else {
		goto tr63
	}
	goto st0
tr68:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st808
st808:
	p++
	if p == pe { goto _test_eof808 }
	fallthrough
case 808:
// line 25874 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 72: goto st358
		case 78: goto st362
		case 83: goto st358
		case 92: goto st285
		case 104: goto st358
		case 110: goto st362
		case 115: goto st358
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr70:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st809
st809:
	p++
	if p == pe { goto _test_eof809 }
	fallthrough
case 809:
// line 25906 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 83: goto st358
		case 92: goto st285
		case 115: goto st358
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr71:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st810
st810:
	p++
	if p == pe { goto _test_eof810 }
	fallthrough
case 810:
// line 25934 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 78: goto st358
		case 92: goto st285
		case 110: goto st358
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr73:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st811
st811:
	p++
	if p == pe { goto _test_eof811 }
	fallthrough
case 811:
// line 25962 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 79: goto st812
		case 83: goto st777
		case 92: goto st285
		case 111: goto st812
		case 115: goto st777
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st812:
	p++
	if p == pe { goto _test_eof812 }
	fallthrough
case 812:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 78: goto st813
		case 92: goto st285
		case 110: goto st813
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st813:
	p++
	if p == pe { goto _test_eof813 }
	fallthrough
case 813:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 69: goto st358
		case 92: goto st285
		case 101: goto st358
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr199:
// line 28 "zparse.rl"
	{ mark = p }
	goto st814
st814:
	p++
	if p == pe { goto _test_eof814 }
	fallthrough
case 814:
// line 26032 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 83: goto st350
		case 92: goto st285
		case 115: goto st350
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr200:
// line 28 "zparse.rl"
	{ mark = p }
	goto st815
st815:
	p++
	if p == pe { goto _test_eof815 }
	fallthrough
case 815:
// line 26058 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 78: goto st350
		case 92: goto st285
		case 110: goto st350
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr202:
// line 28 "zparse.rl"
	{ mark = p }
	goto st816
st816:
	p++
	if p == pe { goto _test_eof816 }
	fallthrough
case 816:
// line 26084 "zparse.go"
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 79: goto st817
		case 83: goto st777
		case 92: goto st285
		case 111: goto st817
		case 115: goto st777
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st817:
	p++
	if p == pe { goto _test_eof817 }
	fallthrough
case 817:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 78: goto st818
		case 92: goto st285
		case 110: goto st818
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st818:
	p++
	if p == pe { goto _test_eof818 }
	fallthrough
case 818:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 69: goto st350
		case 92: goto st285
		case 101: goto st350
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
tr704:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st819
st819:
	p++
	if p == pe { goto _test_eof819 }
	fallthrough
case 819:
// line 26154 "zparse.go"
	switch data[p] {
		case 9: goto tr1460
		case 32: goto st819
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1462 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1462:
// line 28 "zparse.rl"
	{ mark = p }
	goto st820
st820:
	p++
	if p == pe { goto _test_eof820 }
	fallthrough
case 820:
// line 26178 "zparse.go"
	switch data[p] {
		case 9: goto tr1463
		case 32: goto tr1464
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st820 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1464:
// line 30 "zparse.rl"
	{ n, _ := strconv.Atoi(data[mark:p]); num[j] = n; j++ }
	goto st821
st821:
	p++
	if p == pe { goto _test_eof821 }
	fallthrough
case 821:
// line 26202 "zparse.go"
	switch data[p] {
		case 9: goto tr1466
		case 32: goto tr1467
		case 46: goto tr1446
		case 92: goto tr1446
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1446 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1446 }
	} else {
		goto tr1446
	}
	goto st0
tr1467:
// line 28 "zparse.rl"
	{ mark = p }
	goto st822
st822:
	p++
	if p == pe { goto _test_eof822 }
	fallthrough
case 822:
// line 26226 "zparse.go"
	switch data[p] {
		case 9: goto tr1468
		case 32: goto tr1467
		case 46: goto tr1446
		case 92: goto tr1446
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr1446 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto tr1446 }
	} else {
		goto tr1446
	}
	goto st0
st823:
	p++
	if p == pe { goto _test_eof823 }
	fallthrough
case 823:
	switch data[p] {
		case 9: goto tr1469
		case 32: goto tr1470
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
tr1470:
// line 37 "zparse.rl"
	{ 
                    i := Str_rr[data[mark:p]]
                    mk, known := rr_mk[int(i)]
                    if ! known {
                        // ...
                    }
                    r = mk()
                    hdr.Rrtype = i
                }
	goto st824
st824:
	p++
	if p == pe { goto _test_eof824 }
	fallthrough
case 824:
// line 26277 "zparse.go"
	switch data[p] {
		case 9: goto tr1163
		case 32: goto st824
		case 46: goto st317
		case 92: goto st317
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto tr553 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st825:
	p++
	if p == pe { goto _test_eof825 }
	fallthrough
case 825:
	switch data[p] {
		case 9: goto tr653
		case 32: goto st317
		case 46: goto st317
		case 89: goto st557
		case 92: goto st317
		case 121: goto st557
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st317 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st317 }
	} else {
		goto st317
	}
	goto st0
st826:
	p++
	if p == pe { goto _test_eof826 }
	fallthrough
case 826:
	switch data[p] {
		case 9: goto tr1472
		case 32: goto tr1472
		case 46: goto st282
		case 92: goto st282
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
tr92:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st827
st827:
	p++
	if p == pe { goto _test_eof827 }
	fallthrough
case 827:
// line 26343 "zparse.go"
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 83: goto st301
		case 92: goto st282
		case 115: goto st301
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
tr93:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st828
st828:
	p++
	if p == pe { goto _test_eof828 }
	fallthrough
case 828:
// line 26371 "zparse.go"
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 78: goto st301
		case 92: goto st282
		case 110: goto st301
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
tr94:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st829
st829:
	p++
	if p == pe { goto _test_eof829 }
	fallthrough
case 829:
// line 26399 "zparse.go"
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 88: goto st830
		case 92: goto st282
		case 120: goto st830
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st830:
	p++
	if p == pe { goto _test_eof830 }
	fallthrough
case 830:
	switch data[p] {
		case 9: goto tr1474
		case 32: goto tr1474
		case 46: goto st282
		case 92: goto st282
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
tr95:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st831
st831:
	p++
	if p == pe { goto _test_eof831 }
	fallthrough
case 831:
// line 26446 "zparse.go"
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 79: goto st832
		case 83: goto st834
		case 92: goto st282
		case 111: goto st832
		case 115: goto st834
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st832:
	p++
	if p == pe { goto _test_eof832 }
	fallthrough
case 832:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 78: goto st833
		case 92: goto st282
		case 110: goto st833
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st833:
	p++
	if p == pe { goto _test_eof833 }
	fallthrough
case 833:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 69: goto st301
		case 92: goto st282
		case 101: goto st301
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st834:
	p++
	if p == pe { goto _test_eof834 }
	fallthrough
case 834:
	switch data[p] {
		case 9: goto tr1478
		case 32: goto tr1478
		case 46: goto st282
		case 92: goto st282
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
tr96:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st835
st835:
	p++
	if p == pe { goto _test_eof835 }
	fallthrough
case 835:
// line 26537 "zparse.go"
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 82: goto st836
		case 92: goto st282
		case 114: goto st836
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st836:
	p++
	if p == pe { goto _test_eof836 }
	fallthrough
case 836:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 83: goto st837
		case 92: goto st282
		case 115: goto st837
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st837:
	p++
	if p == pe { goto _test_eof837 }
	fallthrough
case 837:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 73: goto st838
		case 92: goto st282
		case 105: goto st838
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st838:
	p++
	if p == pe { goto _test_eof838 }
	fallthrough
case 838:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 71: goto st839
		case 92: goto st282
		case 103: goto st839
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st839:
	p++
	if p == pe { goto _test_eof839 }
	fallthrough
case 839:
	switch data[p] {
		case 9: goto tr1483
		case 32: goto tr1483
		case 46: goto st282
		case 92: goto st282
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
tr97:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st840
st840:
	p++
	if p == pe { goto _test_eof840 }
	fallthrough
case 840:
// line 26647 "zparse.go"
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 79: goto st841
		case 92: goto st282
		case 111: goto st841
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st841:
	p++
	if p == pe { goto _test_eof841 }
	fallthrough
case 841:
	switch data[p] {
		case 9: goto tr607
		case 32: goto tr607
		case 46: goto st282
		case 65: goto st842
		case 92: goto st282
		case 97: goto st842
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
st842:
	p++
	if p == pe { goto _test_eof842 }
	fallthrough
case 842:
	switch data[p] {
		case 9: goto tr1486
		case 32: goto tr1486
		case 46: goto st282
		case 92: goto st282
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st282 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st282 }
	} else {
		goto st282
	}
	goto st0
tr80:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st843
st843:
	p++
	if p == pe { goto _test_eof843 }
	fallthrough
case 843:
// line 26715 "zparse.go"
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 78: goto st844
		case 83: goto st849
		case 92: goto st281
		case 110: goto st844
		case 115: goto st849
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st844:
	p++
	if p == pe { goto _test_eof844 }
	fallthrough
case 844:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 83: goto st845
		case 92: goto st281
		case 115: goto st845
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st845:
	p++
	if p == pe { goto _test_eof845 }
	fallthrough
case 845:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 75: goto st846
		case 92: goto st281
		case 107: goto st846
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st846:
	p++
	if p == pe { goto _test_eof846 }
	fallthrough
case 846:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 69: goto st847
		case 92: goto st281
		case 101: goto st847
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st847:
	p++
	if p == pe { goto _test_eof847 }
	fallthrough
case 847:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 89: goto st848
		case 92: goto st281
		case 121: goto st848
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st848:
	p++
	if p == pe { goto _test_eof848 }
	fallthrough
case 848:
	switch data[p] {
		case 9: goto tr1493
		case 32: goto tr1493
		case 46: goto st281
		case 92: goto st281
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st849:
	p++
	if p == pe { goto _test_eof849 }
	fallthrough
case 849:
	switch data[p] {
		case 9: goto tr1494
		case 32: goto tr1494
		case 46: goto st281
		case 92: goto st281
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
tr81:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st850
st850:
	p++
	if p == pe { goto _test_eof850 }
	fallthrough
case 850:
// line 26867 "zparse.go"
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 83: goto st292
		case 92: goto st281
		case 115: goto st292
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
tr82:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st851
st851:
	p++
	if p == pe { goto _test_eof851 }
	fallthrough
case 851:
// line 26895 "zparse.go"
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 78: goto st292
		case 92: goto st281
		case 110: goto st292
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
tr83:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st852
st852:
	p++
	if p == pe { goto _test_eof852 }
	fallthrough
case 852:
// line 26923 "zparse.go"
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 88: goto st853
		case 92: goto st281
		case 120: goto st853
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st853:
	p++
	if p == pe { goto _test_eof853 }
	fallthrough
case 853:
	switch data[p] {
		case 9: goto tr1496
		case 32: goto tr1496
		case 46: goto st281
		case 92: goto st281
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
tr84:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st854
st854:
	p++
	if p == pe { goto _test_eof854 }
	fallthrough
case 854:
// line 26970 "zparse.go"
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 79: goto st855
		case 83: goto st857
		case 92: goto st281
		case 111: goto st855
		case 115: goto st857
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st855:
	p++
	if p == pe { goto _test_eof855 }
	fallthrough
case 855:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 78: goto st856
		case 92: goto st281
		case 110: goto st856
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st856:
	p++
	if p == pe { goto _test_eof856 }
	fallthrough
case 856:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 69: goto st292
		case 92: goto st281
		case 101: goto st292
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st857:
	p++
	if p == pe { goto _test_eof857 }
	fallthrough
case 857:
	switch data[p] {
		case 9: goto tr1500
		case 32: goto tr1500
		case 46: goto st281
		case 92: goto st281
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
tr85:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st858
st858:
	p++
	if p == pe { goto _test_eof858 }
	fallthrough
case 858:
// line 27061 "zparse.go"
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 82: goto st859
		case 92: goto st281
		case 114: goto st859
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st859:
	p++
	if p == pe { goto _test_eof859 }
	fallthrough
case 859:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 83: goto st860
		case 92: goto st281
		case 115: goto st860
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st860:
	p++
	if p == pe { goto _test_eof860 }
	fallthrough
case 860:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 73: goto st861
		case 92: goto st281
		case 105: goto st861
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st861:
	p++
	if p == pe { goto _test_eof861 }
	fallthrough
case 861:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 71: goto st862
		case 92: goto st281
		case 103: goto st862
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st862:
	p++
	if p == pe { goto _test_eof862 }
	fallthrough
case 862:
	switch data[p] {
		case 9: goto tr1505
		case 32: goto tr1505
		case 46: goto st281
		case 92: goto st281
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
tr86:
// line 28 "zparse.rl"
	{ mark = p }
// line 34 "zparse.rl"
	{ /* fmt.Printf("defttl {%s}\n", data[mark:p]) */ }
	goto st863
st863:
	p++
	if p == pe { goto _test_eof863 }
	fallthrough
case 863:
// line 27171 "zparse.go"
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 79: goto st864
		case 92: goto st281
		case 111: goto st864
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st864:
	p++
	if p == pe { goto _test_eof864 }
	fallthrough
case 864:
	switch data[p] {
		case 9: goto tr605
		case 32: goto tr605
		case 46: goto st281
		case 65: goto st865
		case 92: goto st281
		case 97: goto st865
	}
	if data[p] < 66 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 98 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st865:
	p++
	if p == pe { goto _test_eof865 }
	fallthrough
case 865:
	switch data[p] {
		case 9: goto tr1508
		case 32: goto tr1508
		case 46: goto st281
		case 92: goto st281
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st281 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st281 }
	} else {
		goto st281
	}
	goto st0
st866:
	p++
	if p == pe { goto _test_eof866 }
	fallthrough
case 866:
	switch data[p] {
		case 9: goto tr610
		case 32: goto st285
		case 46: goto st285
		case 89: goto st350
		case 92: goto st285
		case 121: goto st350
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st285 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st285 }
	} else {
		goto st285
	}
	goto st0
st279:
	p++
	if p == pe { goto _test_eof279 }
	fallthrough
case 279:
	switch data[p] {
		case 9: goto tr347
		case 32: goto tr347
	}
	goto st0
st280:
	p++
	if p == pe { goto _test_eof280 }
	fallthrough
case 280:
	switch data[p] {
		case 9: goto tr604
		case 32: goto tr604
		case 46: goto st280
		case 92: goto st280
	}
	if data[p] < 65 {
		if 48 <= data[p] && data[p] <= 57 { goto st280 }
	} else if data[p] > 90 {
		if 97 <= data[p] && data[p] <= 122 { goto st280 }
	} else {
		goto st280
	}
	goto st0
	}
	_test_eof2: cs = 2; goto _test_eof; 
	_test_eof3: cs = 3; goto _test_eof; 
	_test_eof4: cs = 4; goto _test_eof; 
	_test_eof5: cs = 5; goto _test_eof; 
	_test_eof6: cs = 6; goto _test_eof; 
	_test_eof281: cs = 281; goto _test_eof; 
	_test_eof7: cs = 7; goto _test_eof; 
	_test_eof8: cs = 8; goto _test_eof; 
	_test_eof9: cs = 9; goto _test_eof; 
	_test_eof10: cs = 10; goto _test_eof; 
	_test_eof11: cs = 11; goto _test_eof; 
	_test_eof12: cs = 12; goto _test_eof; 
	_test_eof13: cs = 13; goto _test_eof; 
	_test_eof14: cs = 14; goto _test_eof; 
	_test_eof15: cs = 15; goto _test_eof; 
	_test_eof16: cs = 16; goto _test_eof; 
	_test_eof282: cs = 282; goto _test_eof; 
	_test_eof17: cs = 17; goto _test_eof; 
	_test_eof18: cs = 18; goto _test_eof; 
	_test_eof19: cs = 19; goto _test_eof; 
	_test_eof20: cs = 20; goto _test_eof; 
	_test_eof21: cs = 21; goto _test_eof; 
	_test_eof22: cs = 22; goto _test_eof; 
	_test_eof23: cs = 23; goto _test_eof; 
	_test_eof24: cs = 24; goto _test_eof; 
	_test_eof25: cs = 25; goto _test_eof; 
	_test_eof26: cs = 26; goto _test_eof; 
	_test_eof27: cs = 27; goto _test_eof; 
	_test_eof28: cs = 28; goto _test_eof; 
	_test_eof29: cs = 29; goto _test_eof; 
	_test_eof283: cs = 283; goto _test_eof; 
	_test_eof30: cs = 30; goto _test_eof; 
	_test_eof284: cs = 284; goto _test_eof; 
	_test_eof285: cs = 285; goto _test_eof; 
	_test_eof286: cs = 286; goto _test_eof; 
	_test_eof287: cs = 287; goto _test_eof; 
	_test_eof288: cs = 288; goto _test_eof; 
	_test_eof31: cs = 31; goto _test_eof; 
	_test_eof289: cs = 289; goto _test_eof; 
	_test_eof290: cs = 290; goto _test_eof; 
	_test_eof291: cs = 291; goto _test_eof; 
	_test_eof292: cs = 292; goto _test_eof; 
	_test_eof293: cs = 293; goto _test_eof; 
	_test_eof294: cs = 294; goto _test_eof; 
	_test_eof295: cs = 295; goto _test_eof; 
	_test_eof296: cs = 296; goto _test_eof; 
	_test_eof297: cs = 297; goto _test_eof; 
	_test_eof32: cs = 32; goto _test_eof; 
	_test_eof298: cs = 298; goto _test_eof; 
	_test_eof299: cs = 299; goto _test_eof; 
	_test_eof300: cs = 300; goto _test_eof; 
	_test_eof301: cs = 301; goto _test_eof; 
	_test_eof302: cs = 302; goto _test_eof; 
	_test_eof303: cs = 303; goto _test_eof; 
	_test_eof304: cs = 304; goto _test_eof; 
	_test_eof305: cs = 305; goto _test_eof; 
	_test_eof306: cs = 306; goto _test_eof; 
	_test_eof307: cs = 307; goto _test_eof; 
	_test_eof308: cs = 308; goto _test_eof; 
	_test_eof309: cs = 309; goto _test_eof; 
	_test_eof310: cs = 310; goto _test_eof; 
	_test_eof311: cs = 311; goto _test_eof; 
	_test_eof312: cs = 312; goto _test_eof; 
	_test_eof33: cs = 33; goto _test_eof; 
	_test_eof34: cs = 34; goto _test_eof; 
	_test_eof35: cs = 35; goto _test_eof; 
	_test_eof36: cs = 36; goto _test_eof; 
	_test_eof37: cs = 37; goto _test_eof; 
	_test_eof38: cs = 38; goto _test_eof; 
	_test_eof39: cs = 39; goto _test_eof; 
	_test_eof40: cs = 40; goto _test_eof; 
	_test_eof41: cs = 41; goto _test_eof; 
	_test_eof42: cs = 42; goto _test_eof; 
	_test_eof43: cs = 43; goto _test_eof; 
	_test_eof313: cs = 313; goto _test_eof; 
	_test_eof44: cs = 44; goto _test_eof; 
	_test_eof45: cs = 45; goto _test_eof; 
	_test_eof46: cs = 46; goto _test_eof; 
	_test_eof47: cs = 47; goto _test_eof; 
	_test_eof48: cs = 48; goto _test_eof; 
	_test_eof314: cs = 314; goto _test_eof; 
	_test_eof49: cs = 49; goto _test_eof; 
	_test_eof50: cs = 50; goto _test_eof; 
	_test_eof51: cs = 51; goto _test_eof; 
	_test_eof52: cs = 52; goto _test_eof; 
	_test_eof53: cs = 53; goto _test_eof; 
	_test_eof54: cs = 54; goto _test_eof; 
	_test_eof55: cs = 55; goto _test_eof; 
	_test_eof56: cs = 56; goto _test_eof; 
	_test_eof57: cs = 57; goto _test_eof; 
	_test_eof58: cs = 58; goto _test_eof; 
	_test_eof59: cs = 59; goto _test_eof; 
	_test_eof60: cs = 60; goto _test_eof; 
	_test_eof61: cs = 61; goto _test_eof; 
	_test_eof62: cs = 62; goto _test_eof; 
	_test_eof63: cs = 63; goto _test_eof; 
	_test_eof64: cs = 64; goto _test_eof; 
	_test_eof65: cs = 65; goto _test_eof; 
	_test_eof66: cs = 66; goto _test_eof; 
	_test_eof67: cs = 67; goto _test_eof; 
	_test_eof68: cs = 68; goto _test_eof; 
	_test_eof69: cs = 69; goto _test_eof; 
	_test_eof70: cs = 70; goto _test_eof; 
	_test_eof315: cs = 315; goto _test_eof; 
	_test_eof71: cs = 71; goto _test_eof; 
	_test_eof316: cs = 316; goto _test_eof; 
	_test_eof317: cs = 317; goto _test_eof; 
	_test_eof318: cs = 318; goto _test_eof; 
	_test_eof319: cs = 319; goto _test_eof; 
	_test_eof320: cs = 320; goto _test_eof; 
	_test_eof321: cs = 321; goto _test_eof; 
	_test_eof322: cs = 322; goto _test_eof; 
	_test_eof323: cs = 323; goto _test_eof; 
	_test_eof324: cs = 324; goto _test_eof; 
	_test_eof325: cs = 325; goto _test_eof; 
	_test_eof326: cs = 326; goto _test_eof; 
	_test_eof327: cs = 327; goto _test_eof; 
	_test_eof328: cs = 328; goto _test_eof; 
	_test_eof329: cs = 329; goto _test_eof; 
	_test_eof330: cs = 330; goto _test_eof; 
	_test_eof331: cs = 331; goto _test_eof; 
	_test_eof332: cs = 332; goto _test_eof; 
	_test_eof333: cs = 333; goto _test_eof; 
	_test_eof334: cs = 334; goto _test_eof; 
	_test_eof335: cs = 335; goto _test_eof; 
	_test_eof336: cs = 336; goto _test_eof; 
	_test_eof337: cs = 337; goto _test_eof; 
	_test_eof338: cs = 338; goto _test_eof; 
	_test_eof339: cs = 339; goto _test_eof; 
	_test_eof340: cs = 340; goto _test_eof; 
	_test_eof341: cs = 341; goto _test_eof; 
	_test_eof342: cs = 342; goto _test_eof; 
	_test_eof343: cs = 343; goto _test_eof; 
	_test_eof344: cs = 344; goto _test_eof; 
	_test_eof345: cs = 345; goto _test_eof; 
	_test_eof72: cs = 72; goto _test_eof; 
	_test_eof73: cs = 73; goto _test_eof; 
	_test_eof74: cs = 74; goto _test_eof; 
	_test_eof75: cs = 75; goto _test_eof; 
	_test_eof76: cs = 76; goto _test_eof; 
	_test_eof77: cs = 77; goto _test_eof; 
	_test_eof78: cs = 78; goto _test_eof; 
	_test_eof79: cs = 79; goto _test_eof; 
	_test_eof80: cs = 80; goto _test_eof; 
	_test_eof81: cs = 81; goto _test_eof; 
	_test_eof82: cs = 82; goto _test_eof; 
	_test_eof83: cs = 83; goto _test_eof; 
	_test_eof84: cs = 84; goto _test_eof; 
	_test_eof85: cs = 85; goto _test_eof; 
	_test_eof86: cs = 86; goto _test_eof; 
	_test_eof87: cs = 87; goto _test_eof; 
	_test_eof88: cs = 88; goto _test_eof; 
	_test_eof89: cs = 89; goto _test_eof; 
	_test_eof90: cs = 90; goto _test_eof; 
	_test_eof91: cs = 91; goto _test_eof; 
	_test_eof346: cs = 346; goto _test_eof; 
	_test_eof347: cs = 347; goto _test_eof; 
	_test_eof92: cs = 92; goto _test_eof; 
	_test_eof93: cs = 93; goto _test_eof; 
	_test_eof94: cs = 94; goto _test_eof; 
	_test_eof348: cs = 348; goto _test_eof; 
	_test_eof349: cs = 349; goto _test_eof; 
	_test_eof350: cs = 350; goto _test_eof; 
	_test_eof351: cs = 351; goto _test_eof; 
	_test_eof352: cs = 352; goto _test_eof; 
	_test_eof353: cs = 353; goto _test_eof; 
	_test_eof354: cs = 354; goto _test_eof; 
	_test_eof355: cs = 355; goto _test_eof; 
	_test_eof356: cs = 356; goto _test_eof; 
	_test_eof357: cs = 357; goto _test_eof; 
	_test_eof358: cs = 358; goto _test_eof; 
	_test_eof359: cs = 359; goto _test_eof; 
	_test_eof360: cs = 360; goto _test_eof; 
	_test_eof361: cs = 361; goto _test_eof; 
	_test_eof362: cs = 362; goto _test_eof; 
	_test_eof363: cs = 363; goto _test_eof; 
	_test_eof364: cs = 364; goto _test_eof; 
	_test_eof365: cs = 365; goto _test_eof; 
	_test_eof366: cs = 366; goto _test_eof; 
	_test_eof367: cs = 367; goto _test_eof; 
	_test_eof368: cs = 368; goto _test_eof; 
	_test_eof369: cs = 369; goto _test_eof; 
	_test_eof370: cs = 370; goto _test_eof; 
	_test_eof371: cs = 371; goto _test_eof; 
	_test_eof372: cs = 372; goto _test_eof; 
	_test_eof373: cs = 373; goto _test_eof; 
	_test_eof374: cs = 374; goto _test_eof; 
	_test_eof375: cs = 375; goto _test_eof; 
	_test_eof376: cs = 376; goto _test_eof; 
	_test_eof377: cs = 377; goto _test_eof; 
	_test_eof378: cs = 378; goto _test_eof; 
	_test_eof379: cs = 379; goto _test_eof; 
	_test_eof380: cs = 380; goto _test_eof; 
	_test_eof95: cs = 95; goto _test_eof; 
	_test_eof96: cs = 96; goto _test_eof; 
	_test_eof97: cs = 97; goto _test_eof; 
	_test_eof98: cs = 98; goto _test_eof; 
	_test_eof99: cs = 99; goto _test_eof; 
	_test_eof100: cs = 100; goto _test_eof; 
	_test_eof101: cs = 101; goto _test_eof; 
	_test_eof381: cs = 381; goto _test_eof; 
	_test_eof102: cs = 102; goto _test_eof; 
	_test_eof382: cs = 382; goto _test_eof; 
	_test_eof383: cs = 383; goto _test_eof; 
	_test_eof384: cs = 384; goto _test_eof; 
	_test_eof385: cs = 385; goto _test_eof; 
	_test_eof386: cs = 386; goto _test_eof; 
	_test_eof387: cs = 387; goto _test_eof; 
	_test_eof388: cs = 388; goto _test_eof; 
	_test_eof389: cs = 389; goto _test_eof; 
	_test_eof390: cs = 390; goto _test_eof; 
	_test_eof391: cs = 391; goto _test_eof; 
	_test_eof392: cs = 392; goto _test_eof; 
	_test_eof393: cs = 393; goto _test_eof; 
	_test_eof394: cs = 394; goto _test_eof; 
	_test_eof395: cs = 395; goto _test_eof; 
	_test_eof396: cs = 396; goto _test_eof; 
	_test_eof397: cs = 397; goto _test_eof; 
	_test_eof398: cs = 398; goto _test_eof; 
	_test_eof399: cs = 399; goto _test_eof; 
	_test_eof400: cs = 400; goto _test_eof; 
	_test_eof401: cs = 401; goto _test_eof; 
	_test_eof402: cs = 402; goto _test_eof; 
	_test_eof403: cs = 403; goto _test_eof; 
	_test_eof404: cs = 404; goto _test_eof; 
	_test_eof405: cs = 405; goto _test_eof; 
	_test_eof406: cs = 406; goto _test_eof; 
	_test_eof407: cs = 407; goto _test_eof; 
	_test_eof408: cs = 408; goto _test_eof; 
	_test_eof409: cs = 409; goto _test_eof; 
	_test_eof410: cs = 410; goto _test_eof; 
	_test_eof411: cs = 411; goto _test_eof; 
	_test_eof412: cs = 412; goto _test_eof; 
	_test_eof413: cs = 413; goto _test_eof; 
	_test_eof414: cs = 414; goto _test_eof; 
	_test_eof415: cs = 415; goto _test_eof; 
	_test_eof416: cs = 416; goto _test_eof; 
	_test_eof417: cs = 417; goto _test_eof; 
	_test_eof418: cs = 418; goto _test_eof; 
	_test_eof419: cs = 419; goto _test_eof; 
	_test_eof420: cs = 420; goto _test_eof; 
	_test_eof421: cs = 421; goto _test_eof; 
	_test_eof103: cs = 103; goto _test_eof; 
	_test_eof104: cs = 104; goto _test_eof; 
	_test_eof105: cs = 105; goto _test_eof; 
	_test_eof422: cs = 422; goto _test_eof; 
	_test_eof423: cs = 423; goto _test_eof; 
	_test_eof106: cs = 106; goto _test_eof; 
	_test_eof107: cs = 107; goto _test_eof; 
	_test_eof108: cs = 108; goto _test_eof; 
	_test_eof424: cs = 424; goto _test_eof; 
	_test_eof425: cs = 425; goto _test_eof; 
	_test_eof426: cs = 426; goto _test_eof; 
	_test_eof427: cs = 427; goto _test_eof; 
	_test_eof428: cs = 428; goto _test_eof; 
	_test_eof429: cs = 429; goto _test_eof; 
	_test_eof430: cs = 430; goto _test_eof; 
	_test_eof109: cs = 109; goto _test_eof; 
	_test_eof110: cs = 110; goto _test_eof; 
	_test_eof111: cs = 111; goto _test_eof; 
	_test_eof431: cs = 431; goto _test_eof; 
	_test_eof432: cs = 432; goto _test_eof; 
	_test_eof433: cs = 433; goto _test_eof; 
	_test_eof434: cs = 434; goto _test_eof; 
	_test_eof435: cs = 435; goto _test_eof; 
	_test_eof436: cs = 436; goto _test_eof; 
	_test_eof437: cs = 437; goto _test_eof; 
	_test_eof438: cs = 438; goto _test_eof; 
	_test_eof439: cs = 439; goto _test_eof; 
	_test_eof440: cs = 440; goto _test_eof; 
	_test_eof441: cs = 441; goto _test_eof; 
	_test_eof442: cs = 442; goto _test_eof; 
	_test_eof443: cs = 443; goto _test_eof; 
	_test_eof444: cs = 444; goto _test_eof; 
	_test_eof445: cs = 445; goto _test_eof; 
	_test_eof446: cs = 446; goto _test_eof; 
	_test_eof447: cs = 447; goto _test_eof; 
	_test_eof448: cs = 448; goto _test_eof; 
	_test_eof449: cs = 449; goto _test_eof; 
	_test_eof450: cs = 450; goto _test_eof; 
	_test_eof451: cs = 451; goto _test_eof; 
	_test_eof452: cs = 452; goto _test_eof; 
	_test_eof453: cs = 453; goto _test_eof; 
	_test_eof112: cs = 112; goto _test_eof; 
	_test_eof454: cs = 454; goto _test_eof; 
	_test_eof455: cs = 455; goto _test_eof; 
	_test_eof456: cs = 456; goto _test_eof; 
	_test_eof457: cs = 457; goto _test_eof; 
	_test_eof458: cs = 458; goto _test_eof; 
	_test_eof459: cs = 459; goto _test_eof; 
	_test_eof460: cs = 460; goto _test_eof; 
	_test_eof461: cs = 461; goto _test_eof; 
	_test_eof462: cs = 462; goto _test_eof; 
	_test_eof463: cs = 463; goto _test_eof; 
	_test_eof464: cs = 464; goto _test_eof; 
	_test_eof465: cs = 465; goto _test_eof; 
	_test_eof466: cs = 466; goto _test_eof; 
	_test_eof467: cs = 467; goto _test_eof; 
	_test_eof468: cs = 468; goto _test_eof; 
	_test_eof469: cs = 469; goto _test_eof; 
	_test_eof470: cs = 470; goto _test_eof; 
	_test_eof471: cs = 471; goto _test_eof; 
	_test_eof472: cs = 472; goto _test_eof; 
	_test_eof473: cs = 473; goto _test_eof; 
	_test_eof474: cs = 474; goto _test_eof; 
	_test_eof475: cs = 475; goto _test_eof; 
	_test_eof476: cs = 476; goto _test_eof; 
	_test_eof477: cs = 477; goto _test_eof; 
	_test_eof478: cs = 478; goto _test_eof; 
	_test_eof479: cs = 479; goto _test_eof; 
	_test_eof480: cs = 480; goto _test_eof; 
	_test_eof481: cs = 481; goto _test_eof; 
	_test_eof482: cs = 482; goto _test_eof; 
	_test_eof113: cs = 113; goto _test_eof; 
	_test_eof114: cs = 114; goto _test_eof; 
	_test_eof115: cs = 115; goto _test_eof; 
	_test_eof483: cs = 483; goto _test_eof; 
	_test_eof484: cs = 484; goto _test_eof; 
	_test_eof485: cs = 485; goto _test_eof; 
	_test_eof116: cs = 116; goto _test_eof; 
	_test_eof117: cs = 117; goto _test_eof; 
	_test_eof118: cs = 118; goto _test_eof; 
	_test_eof119: cs = 119; goto _test_eof; 
	_test_eof120: cs = 120; goto _test_eof; 
	_test_eof486: cs = 486; goto _test_eof; 
	_test_eof121: cs = 121; goto _test_eof; 
	_test_eof122: cs = 122; goto _test_eof; 
	_test_eof123: cs = 123; goto _test_eof; 
	_test_eof124: cs = 124; goto _test_eof; 
	_test_eof125: cs = 125; goto _test_eof; 
	_test_eof126: cs = 126; goto _test_eof; 
	_test_eof127: cs = 127; goto _test_eof; 
	_test_eof128: cs = 128; goto _test_eof; 
	_test_eof129: cs = 129; goto _test_eof; 
	_test_eof130: cs = 130; goto _test_eof; 
	_test_eof131: cs = 131; goto _test_eof; 
	_test_eof132: cs = 132; goto _test_eof; 
	_test_eof133: cs = 133; goto _test_eof; 
	_test_eof134: cs = 134; goto _test_eof; 
	_test_eof487: cs = 487; goto _test_eof; 
	_test_eof135: cs = 135; goto _test_eof; 
	_test_eof136: cs = 136; goto _test_eof; 
	_test_eof137: cs = 137; goto _test_eof; 
	_test_eof138: cs = 138; goto _test_eof; 
	_test_eof139: cs = 139; goto _test_eof; 
	_test_eof140: cs = 140; goto _test_eof; 
	_test_eof141: cs = 141; goto _test_eof; 
	_test_eof142: cs = 142; goto _test_eof; 
	_test_eof143: cs = 143; goto _test_eof; 
	_test_eof144: cs = 144; goto _test_eof; 
	_test_eof145: cs = 145; goto _test_eof; 
	_test_eof146: cs = 146; goto _test_eof; 
	_test_eof147: cs = 147; goto _test_eof; 
	_test_eof148: cs = 148; goto _test_eof; 
	_test_eof149: cs = 149; goto _test_eof; 
	_test_eof150: cs = 150; goto _test_eof; 
	_test_eof151: cs = 151; goto _test_eof; 
	_test_eof152: cs = 152; goto _test_eof; 
	_test_eof153: cs = 153; goto _test_eof; 
	_test_eof154: cs = 154; goto _test_eof; 
	_test_eof155: cs = 155; goto _test_eof; 
	_test_eof156: cs = 156; goto _test_eof; 
	_test_eof157: cs = 157; goto _test_eof; 
	_test_eof158: cs = 158; goto _test_eof; 
	_test_eof159: cs = 159; goto _test_eof; 
	_test_eof160: cs = 160; goto _test_eof; 
	_test_eof161: cs = 161; goto _test_eof; 
	_test_eof488: cs = 488; goto _test_eof; 
	_test_eof162: cs = 162; goto _test_eof; 
	_test_eof163: cs = 163; goto _test_eof; 
	_test_eof164: cs = 164; goto _test_eof; 
	_test_eof489: cs = 489; goto _test_eof; 
	_test_eof165: cs = 165; goto _test_eof; 
	_test_eof166: cs = 166; goto _test_eof; 
	_test_eof167: cs = 167; goto _test_eof; 
	_test_eof168: cs = 168; goto _test_eof; 
	_test_eof169: cs = 169; goto _test_eof; 
	_test_eof170: cs = 170; goto _test_eof; 
	_test_eof171: cs = 171; goto _test_eof; 
	_test_eof172: cs = 172; goto _test_eof; 
	_test_eof173: cs = 173; goto _test_eof; 
	_test_eof174: cs = 174; goto _test_eof; 
	_test_eof175: cs = 175; goto _test_eof; 
	_test_eof176: cs = 176; goto _test_eof; 
	_test_eof177: cs = 177; goto _test_eof; 
	_test_eof178: cs = 178; goto _test_eof; 
	_test_eof179: cs = 179; goto _test_eof; 
	_test_eof180: cs = 180; goto _test_eof; 
	_test_eof181: cs = 181; goto _test_eof; 
	_test_eof182: cs = 182; goto _test_eof; 
	_test_eof183: cs = 183; goto _test_eof; 
	_test_eof184: cs = 184; goto _test_eof; 
	_test_eof185: cs = 185; goto _test_eof; 
	_test_eof186: cs = 186; goto _test_eof; 
	_test_eof187: cs = 187; goto _test_eof; 
	_test_eof188: cs = 188; goto _test_eof; 
	_test_eof189: cs = 189; goto _test_eof; 
	_test_eof190: cs = 190; goto _test_eof; 
	_test_eof191: cs = 191; goto _test_eof; 
	_test_eof192: cs = 192; goto _test_eof; 
	_test_eof193: cs = 193; goto _test_eof; 
	_test_eof194: cs = 194; goto _test_eof; 
	_test_eof195: cs = 195; goto _test_eof; 
	_test_eof196: cs = 196; goto _test_eof; 
	_test_eof197: cs = 197; goto _test_eof; 
	_test_eof198: cs = 198; goto _test_eof; 
	_test_eof199: cs = 199; goto _test_eof; 
	_test_eof200: cs = 200; goto _test_eof; 
	_test_eof490: cs = 490; goto _test_eof; 
	_test_eof491: cs = 491; goto _test_eof; 
	_test_eof492: cs = 492; goto _test_eof; 
	_test_eof493: cs = 493; goto _test_eof; 
	_test_eof494: cs = 494; goto _test_eof; 
	_test_eof495: cs = 495; goto _test_eof; 
	_test_eof496: cs = 496; goto _test_eof; 
	_test_eof497: cs = 497; goto _test_eof; 
	_test_eof498: cs = 498; goto _test_eof; 
	_test_eof499: cs = 499; goto _test_eof; 
	_test_eof201: cs = 201; goto _test_eof; 
	_test_eof500: cs = 500; goto _test_eof; 
	_test_eof501: cs = 501; goto _test_eof; 
	_test_eof502: cs = 502; goto _test_eof; 
	_test_eof503: cs = 503; goto _test_eof; 
	_test_eof504: cs = 504; goto _test_eof; 
	_test_eof505: cs = 505; goto _test_eof; 
	_test_eof506: cs = 506; goto _test_eof; 
	_test_eof507: cs = 507; goto _test_eof; 
	_test_eof508: cs = 508; goto _test_eof; 
	_test_eof509: cs = 509; goto _test_eof; 
	_test_eof510: cs = 510; goto _test_eof; 
	_test_eof511: cs = 511; goto _test_eof; 
	_test_eof512: cs = 512; goto _test_eof; 
	_test_eof513: cs = 513; goto _test_eof; 
	_test_eof514: cs = 514; goto _test_eof; 
	_test_eof515: cs = 515; goto _test_eof; 
	_test_eof202: cs = 202; goto _test_eof; 
	_test_eof203: cs = 203; goto _test_eof; 
	_test_eof204: cs = 204; goto _test_eof; 
	_test_eof516: cs = 516; goto _test_eof; 
	_test_eof517: cs = 517; goto _test_eof; 
	_test_eof205: cs = 205; goto _test_eof; 
	_test_eof206: cs = 206; goto _test_eof; 
	_test_eof207: cs = 207; goto _test_eof; 
	_test_eof518: cs = 518; goto _test_eof; 
	_test_eof519: cs = 519; goto _test_eof; 
	_test_eof208: cs = 208; goto _test_eof; 
	_test_eof209: cs = 209; goto _test_eof; 
	_test_eof210: cs = 210; goto _test_eof; 
	_test_eof520: cs = 520; goto _test_eof; 
	_test_eof521: cs = 521; goto _test_eof; 
	_test_eof211: cs = 211; goto _test_eof; 
	_test_eof212: cs = 212; goto _test_eof; 
	_test_eof213: cs = 213; goto _test_eof; 
	_test_eof522: cs = 522; goto _test_eof; 
	_test_eof523: cs = 523; goto _test_eof; 
	_test_eof214: cs = 214; goto _test_eof; 
	_test_eof215: cs = 215; goto _test_eof; 
	_test_eof216: cs = 216; goto _test_eof; 
	_test_eof524: cs = 524; goto _test_eof; 
	_test_eof525: cs = 525; goto _test_eof; 
	_test_eof217: cs = 217; goto _test_eof; 
	_test_eof218: cs = 218; goto _test_eof; 
	_test_eof219: cs = 219; goto _test_eof; 
	_test_eof220: cs = 220; goto _test_eof; 
	_test_eof221: cs = 221; goto _test_eof; 
	_test_eof526: cs = 526; goto _test_eof; 
	_test_eof222: cs = 222; goto _test_eof; 
	_test_eof527: cs = 527; goto _test_eof; 
	_test_eof528: cs = 528; goto _test_eof; 
	_test_eof529: cs = 529; goto _test_eof; 
	_test_eof530: cs = 530; goto _test_eof; 
	_test_eof531: cs = 531; goto _test_eof; 
	_test_eof532: cs = 532; goto _test_eof; 
	_test_eof533: cs = 533; goto _test_eof; 
	_test_eof534: cs = 534; goto _test_eof; 
	_test_eof535: cs = 535; goto _test_eof; 
	_test_eof536: cs = 536; goto _test_eof; 
	_test_eof537: cs = 537; goto _test_eof; 
	_test_eof538: cs = 538; goto _test_eof; 
	_test_eof539: cs = 539; goto _test_eof; 
	_test_eof540: cs = 540; goto _test_eof; 
	_test_eof541: cs = 541; goto _test_eof; 
	_test_eof542: cs = 542; goto _test_eof; 
	_test_eof543: cs = 543; goto _test_eof; 
	_test_eof544: cs = 544; goto _test_eof; 
	_test_eof545: cs = 545; goto _test_eof; 
	_test_eof546: cs = 546; goto _test_eof; 
	_test_eof547: cs = 547; goto _test_eof; 
	_test_eof548: cs = 548; goto _test_eof; 
	_test_eof549: cs = 549; goto _test_eof; 
	_test_eof550: cs = 550; goto _test_eof; 
	_test_eof551: cs = 551; goto _test_eof; 
	_test_eof552: cs = 552; goto _test_eof; 
	_test_eof553: cs = 553; goto _test_eof; 
	_test_eof554: cs = 554; goto _test_eof; 
	_test_eof555: cs = 555; goto _test_eof; 
	_test_eof556: cs = 556; goto _test_eof; 
	_test_eof557: cs = 557; goto _test_eof; 
	_test_eof558: cs = 558; goto _test_eof; 
	_test_eof559: cs = 559; goto _test_eof; 
	_test_eof560: cs = 560; goto _test_eof; 
	_test_eof561: cs = 561; goto _test_eof; 
	_test_eof562: cs = 562; goto _test_eof; 
	_test_eof563: cs = 563; goto _test_eof; 
	_test_eof564: cs = 564; goto _test_eof; 
	_test_eof565: cs = 565; goto _test_eof; 
	_test_eof566: cs = 566; goto _test_eof; 
	_test_eof567: cs = 567; goto _test_eof; 
	_test_eof568: cs = 568; goto _test_eof; 
	_test_eof569: cs = 569; goto _test_eof; 
	_test_eof570: cs = 570; goto _test_eof; 
	_test_eof571: cs = 571; goto _test_eof; 
	_test_eof572: cs = 572; goto _test_eof; 
	_test_eof573: cs = 573; goto _test_eof; 
	_test_eof574: cs = 574; goto _test_eof; 
	_test_eof575: cs = 575; goto _test_eof; 
	_test_eof576: cs = 576; goto _test_eof; 
	_test_eof577: cs = 577; goto _test_eof; 
	_test_eof578: cs = 578; goto _test_eof; 
	_test_eof579: cs = 579; goto _test_eof; 
	_test_eof580: cs = 580; goto _test_eof; 
	_test_eof581: cs = 581; goto _test_eof; 
	_test_eof582: cs = 582; goto _test_eof; 
	_test_eof583: cs = 583; goto _test_eof; 
	_test_eof584: cs = 584; goto _test_eof; 
	_test_eof585: cs = 585; goto _test_eof; 
	_test_eof586: cs = 586; goto _test_eof; 
	_test_eof587: cs = 587; goto _test_eof; 
	_test_eof588: cs = 588; goto _test_eof; 
	_test_eof589: cs = 589; goto _test_eof; 
	_test_eof590: cs = 590; goto _test_eof; 
	_test_eof223: cs = 223; goto _test_eof; 
	_test_eof224: cs = 224; goto _test_eof; 
	_test_eof225: cs = 225; goto _test_eof; 
	_test_eof591: cs = 591; goto _test_eof; 
	_test_eof592: cs = 592; goto _test_eof; 
	_test_eof593: cs = 593; goto _test_eof; 
	_test_eof594: cs = 594; goto _test_eof; 
	_test_eof595: cs = 595; goto _test_eof; 
	_test_eof226: cs = 226; goto _test_eof; 
	_test_eof227: cs = 227; goto _test_eof; 
	_test_eof228: cs = 228; goto _test_eof; 
	_test_eof229: cs = 229; goto _test_eof; 
	_test_eof596: cs = 596; goto _test_eof; 
	_test_eof597: cs = 597; goto _test_eof; 
	_test_eof230: cs = 230; goto _test_eof; 
	_test_eof231: cs = 231; goto _test_eof; 
	_test_eof232: cs = 232; goto _test_eof; 
	_test_eof233: cs = 233; goto _test_eof; 
	_test_eof234: cs = 234; goto _test_eof; 
	_test_eof235: cs = 235; goto _test_eof; 
	_test_eof598: cs = 598; goto _test_eof; 
	_test_eof236: cs = 236; goto _test_eof; 
	_test_eof599: cs = 599; goto _test_eof; 
	_test_eof600: cs = 600; goto _test_eof; 
	_test_eof601: cs = 601; goto _test_eof; 
	_test_eof602: cs = 602; goto _test_eof; 
	_test_eof603: cs = 603; goto _test_eof; 
	_test_eof604: cs = 604; goto _test_eof; 
	_test_eof605: cs = 605; goto _test_eof; 
	_test_eof606: cs = 606; goto _test_eof; 
	_test_eof607: cs = 607; goto _test_eof; 
	_test_eof608: cs = 608; goto _test_eof; 
	_test_eof609: cs = 609; goto _test_eof; 
	_test_eof610: cs = 610; goto _test_eof; 
	_test_eof611: cs = 611; goto _test_eof; 
	_test_eof612: cs = 612; goto _test_eof; 
	_test_eof613: cs = 613; goto _test_eof; 
	_test_eof614: cs = 614; goto _test_eof; 
	_test_eof615: cs = 615; goto _test_eof; 
	_test_eof616: cs = 616; goto _test_eof; 
	_test_eof617: cs = 617; goto _test_eof; 
	_test_eof618: cs = 618; goto _test_eof; 
	_test_eof619: cs = 619; goto _test_eof; 
	_test_eof620: cs = 620; goto _test_eof; 
	_test_eof621: cs = 621; goto _test_eof; 
	_test_eof622: cs = 622; goto _test_eof; 
	_test_eof623: cs = 623; goto _test_eof; 
	_test_eof624: cs = 624; goto _test_eof; 
	_test_eof625: cs = 625; goto _test_eof; 
	_test_eof626: cs = 626; goto _test_eof; 
	_test_eof627: cs = 627; goto _test_eof; 
	_test_eof628: cs = 628; goto _test_eof; 
	_test_eof629: cs = 629; goto _test_eof; 
	_test_eof630: cs = 630; goto _test_eof; 
	_test_eof631: cs = 631; goto _test_eof; 
	_test_eof632: cs = 632; goto _test_eof; 
	_test_eof633: cs = 633; goto _test_eof; 
	_test_eof634: cs = 634; goto _test_eof; 
	_test_eof635: cs = 635; goto _test_eof; 
	_test_eof636: cs = 636; goto _test_eof; 
	_test_eof637: cs = 637; goto _test_eof; 
	_test_eof638: cs = 638; goto _test_eof; 
	_test_eof639: cs = 639; goto _test_eof; 
	_test_eof640: cs = 640; goto _test_eof; 
	_test_eof641: cs = 641; goto _test_eof; 
	_test_eof642: cs = 642; goto _test_eof; 
	_test_eof643: cs = 643; goto _test_eof; 
	_test_eof644: cs = 644; goto _test_eof; 
	_test_eof645: cs = 645; goto _test_eof; 
	_test_eof646: cs = 646; goto _test_eof; 
	_test_eof647: cs = 647; goto _test_eof; 
	_test_eof648: cs = 648; goto _test_eof; 
	_test_eof649: cs = 649; goto _test_eof; 
	_test_eof650: cs = 650; goto _test_eof; 
	_test_eof651: cs = 651; goto _test_eof; 
	_test_eof652: cs = 652; goto _test_eof; 
	_test_eof653: cs = 653; goto _test_eof; 
	_test_eof654: cs = 654; goto _test_eof; 
	_test_eof655: cs = 655; goto _test_eof; 
	_test_eof656: cs = 656; goto _test_eof; 
	_test_eof657: cs = 657; goto _test_eof; 
	_test_eof658: cs = 658; goto _test_eof; 
	_test_eof659: cs = 659; goto _test_eof; 
	_test_eof660: cs = 660; goto _test_eof; 
	_test_eof661: cs = 661; goto _test_eof; 
	_test_eof662: cs = 662; goto _test_eof; 
	_test_eof663: cs = 663; goto _test_eof; 
	_test_eof664: cs = 664; goto _test_eof; 
	_test_eof665: cs = 665; goto _test_eof; 
	_test_eof666: cs = 666; goto _test_eof; 
	_test_eof667: cs = 667; goto _test_eof; 
	_test_eof668: cs = 668; goto _test_eof; 
	_test_eof669: cs = 669; goto _test_eof; 
	_test_eof670: cs = 670; goto _test_eof; 
	_test_eof671: cs = 671; goto _test_eof; 
	_test_eof672: cs = 672; goto _test_eof; 
	_test_eof673: cs = 673; goto _test_eof; 
	_test_eof674: cs = 674; goto _test_eof; 
	_test_eof675: cs = 675; goto _test_eof; 
	_test_eof676: cs = 676; goto _test_eof; 
	_test_eof677: cs = 677; goto _test_eof; 
	_test_eof678: cs = 678; goto _test_eof; 
	_test_eof679: cs = 679; goto _test_eof; 
	_test_eof680: cs = 680; goto _test_eof; 
	_test_eof681: cs = 681; goto _test_eof; 
	_test_eof682: cs = 682; goto _test_eof; 
	_test_eof683: cs = 683; goto _test_eof; 
	_test_eof684: cs = 684; goto _test_eof; 
	_test_eof685: cs = 685; goto _test_eof; 
	_test_eof686: cs = 686; goto _test_eof; 
	_test_eof687: cs = 687; goto _test_eof; 
	_test_eof688: cs = 688; goto _test_eof; 
	_test_eof689: cs = 689; goto _test_eof; 
	_test_eof690: cs = 690; goto _test_eof; 
	_test_eof691: cs = 691; goto _test_eof; 
	_test_eof692: cs = 692; goto _test_eof; 
	_test_eof693: cs = 693; goto _test_eof; 
	_test_eof694: cs = 694; goto _test_eof; 
	_test_eof695: cs = 695; goto _test_eof; 
	_test_eof696: cs = 696; goto _test_eof; 
	_test_eof697: cs = 697; goto _test_eof; 
	_test_eof698: cs = 698; goto _test_eof; 
	_test_eof699: cs = 699; goto _test_eof; 
	_test_eof700: cs = 700; goto _test_eof; 
	_test_eof701: cs = 701; goto _test_eof; 
	_test_eof237: cs = 237; goto _test_eof; 
	_test_eof238: cs = 238; goto _test_eof; 
	_test_eof239: cs = 239; goto _test_eof; 
	_test_eof240: cs = 240; goto _test_eof; 
	_test_eof241: cs = 241; goto _test_eof; 
	_test_eof242: cs = 242; goto _test_eof; 
	_test_eof243: cs = 243; goto _test_eof; 
	_test_eof702: cs = 702; goto _test_eof; 
	_test_eof244: cs = 244; goto _test_eof; 
	_test_eof703: cs = 703; goto _test_eof; 
	_test_eof245: cs = 245; goto _test_eof; 
	_test_eof246: cs = 246; goto _test_eof; 
	_test_eof704: cs = 704; goto _test_eof; 
	_test_eof247: cs = 247; goto _test_eof; 
	_test_eof705: cs = 705; goto _test_eof; 
	_test_eof706: cs = 706; goto _test_eof; 
	_test_eof707: cs = 707; goto _test_eof; 
	_test_eof248: cs = 248; goto _test_eof; 
	_test_eof249: cs = 249; goto _test_eof; 
	_test_eof250: cs = 250; goto _test_eof; 
	_test_eof251: cs = 251; goto _test_eof; 
	_test_eof252: cs = 252; goto _test_eof; 
	_test_eof708: cs = 708; goto _test_eof; 
	_test_eof253: cs = 253; goto _test_eof; 
	_test_eof709: cs = 709; goto _test_eof; 
	_test_eof254: cs = 254; goto _test_eof; 
	_test_eof255: cs = 255; goto _test_eof; 
	_test_eof256: cs = 256; goto _test_eof; 
	_test_eof257: cs = 257; goto _test_eof; 
	_test_eof258: cs = 258; goto _test_eof; 
	_test_eof710: cs = 710; goto _test_eof; 
	_test_eof259: cs = 259; goto _test_eof; 
	_test_eof711: cs = 711; goto _test_eof; 
	_test_eof260: cs = 260; goto _test_eof; 
	_test_eof261: cs = 261; goto _test_eof; 
	_test_eof262: cs = 262; goto _test_eof; 
	_test_eof263: cs = 263; goto _test_eof; 
	_test_eof264: cs = 264; goto _test_eof; 
	_test_eof265: cs = 265; goto _test_eof; 
	_test_eof712: cs = 712; goto _test_eof; 
	_test_eof266: cs = 266; goto _test_eof; 
	_test_eof713: cs = 713; goto _test_eof; 
	_test_eof267: cs = 267; goto _test_eof; 
	_test_eof268: cs = 268; goto _test_eof; 
	_test_eof269: cs = 269; goto _test_eof; 
	_test_eof714: cs = 714; goto _test_eof; 
	_test_eof715: cs = 715; goto _test_eof; 
	_test_eof716: cs = 716; goto _test_eof; 
	_test_eof717: cs = 717; goto _test_eof; 
	_test_eof718: cs = 718; goto _test_eof; 
	_test_eof719: cs = 719; goto _test_eof; 
	_test_eof720: cs = 720; goto _test_eof; 
	_test_eof721: cs = 721; goto _test_eof; 
	_test_eof722: cs = 722; goto _test_eof; 
	_test_eof723: cs = 723; goto _test_eof; 
	_test_eof724: cs = 724; goto _test_eof; 
	_test_eof725: cs = 725; goto _test_eof; 
	_test_eof726: cs = 726; goto _test_eof; 
	_test_eof727: cs = 727; goto _test_eof; 
	_test_eof728: cs = 728; goto _test_eof; 
	_test_eof729: cs = 729; goto _test_eof; 
	_test_eof730: cs = 730; goto _test_eof; 
	_test_eof731: cs = 731; goto _test_eof; 
	_test_eof732: cs = 732; goto _test_eof; 
	_test_eof733: cs = 733; goto _test_eof; 
	_test_eof734: cs = 734; goto _test_eof; 
	_test_eof735: cs = 735; goto _test_eof; 
	_test_eof736: cs = 736; goto _test_eof; 
	_test_eof737: cs = 737; goto _test_eof; 
	_test_eof738: cs = 738; goto _test_eof; 
	_test_eof739: cs = 739; goto _test_eof; 
	_test_eof740: cs = 740; goto _test_eof; 
	_test_eof270: cs = 270; goto _test_eof; 
	_test_eof271: cs = 271; goto _test_eof; 
	_test_eof272: cs = 272; goto _test_eof; 
	_test_eof741: cs = 741; goto _test_eof; 
	_test_eof273: cs = 273; goto _test_eof; 
	_test_eof274: cs = 274; goto _test_eof; 
	_test_eof275: cs = 275; goto _test_eof; 
	_test_eof276: cs = 276; goto _test_eof; 
	_test_eof277: cs = 277; goto _test_eof; 
	_test_eof278: cs = 278; goto _test_eof; 
	_test_eof742: cs = 742; goto _test_eof; 
	_test_eof743: cs = 743; goto _test_eof; 
	_test_eof744: cs = 744; goto _test_eof; 
	_test_eof745: cs = 745; goto _test_eof; 
	_test_eof746: cs = 746; goto _test_eof; 
	_test_eof747: cs = 747; goto _test_eof; 
	_test_eof748: cs = 748; goto _test_eof; 
	_test_eof749: cs = 749; goto _test_eof; 
	_test_eof750: cs = 750; goto _test_eof; 
	_test_eof751: cs = 751; goto _test_eof; 
	_test_eof752: cs = 752; goto _test_eof; 
	_test_eof753: cs = 753; goto _test_eof; 
	_test_eof754: cs = 754; goto _test_eof; 
	_test_eof755: cs = 755; goto _test_eof; 
	_test_eof756: cs = 756; goto _test_eof; 
	_test_eof757: cs = 757; goto _test_eof; 
	_test_eof758: cs = 758; goto _test_eof; 
	_test_eof759: cs = 759; goto _test_eof; 
	_test_eof760: cs = 760; goto _test_eof; 
	_test_eof761: cs = 761; goto _test_eof; 
	_test_eof762: cs = 762; goto _test_eof; 
	_test_eof763: cs = 763; goto _test_eof; 
	_test_eof764: cs = 764; goto _test_eof; 
	_test_eof765: cs = 765; goto _test_eof; 
	_test_eof766: cs = 766; goto _test_eof; 
	_test_eof767: cs = 767; goto _test_eof; 
	_test_eof768: cs = 768; goto _test_eof; 
	_test_eof769: cs = 769; goto _test_eof; 
	_test_eof770: cs = 770; goto _test_eof; 
	_test_eof771: cs = 771; goto _test_eof; 
	_test_eof772: cs = 772; goto _test_eof; 
	_test_eof773: cs = 773; goto _test_eof; 
	_test_eof774: cs = 774; goto _test_eof; 
	_test_eof775: cs = 775; goto _test_eof; 
	_test_eof776: cs = 776; goto _test_eof; 
	_test_eof777: cs = 777; goto _test_eof; 
	_test_eof778: cs = 778; goto _test_eof; 
	_test_eof779: cs = 779; goto _test_eof; 
	_test_eof780: cs = 780; goto _test_eof; 
	_test_eof781: cs = 781; goto _test_eof; 
	_test_eof782: cs = 782; goto _test_eof; 
	_test_eof783: cs = 783; goto _test_eof; 
	_test_eof784: cs = 784; goto _test_eof; 
	_test_eof785: cs = 785; goto _test_eof; 
	_test_eof786: cs = 786; goto _test_eof; 
	_test_eof787: cs = 787; goto _test_eof; 
	_test_eof788: cs = 788; goto _test_eof; 
	_test_eof789: cs = 789; goto _test_eof; 
	_test_eof790: cs = 790; goto _test_eof; 
	_test_eof791: cs = 791; goto _test_eof; 
	_test_eof792: cs = 792; goto _test_eof; 
	_test_eof793: cs = 793; goto _test_eof; 
	_test_eof794: cs = 794; goto _test_eof; 
	_test_eof795: cs = 795; goto _test_eof; 
	_test_eof796: cs = 796; goto _test_eof; 
	_test_eof797: cs = 797; goto _test_eof; 
	_test_eof798: cs = 798; goto _test_eof; 
	_test_eof799: cs = 799; goto _test_eof; 
	_test_eof800: cs = 800; goto _test_eof; 
	_test_eof801: cs = 801; goto _test_eof; 
	_test_eof802: cs = 802; goto _test_eof; 
	_test_eof803: cs = 803; goto _test_eof; 
	_test_eof804: cs = 804; goto _test_eof; 
	_test_eof805: cs = 805; goto _test_eof; 
	_test_eof806: cs = 806; goto _test_eof; 
	_test_eof807: cs = 807; goto _test_eof; 
	_test_eof808: cs = 808; goto _test_eof; 
	_test_eof809: cs = 809; goto _test_eof; 
	_test_eof810: cs = 810; goto _test_eof; 
	_test_eof811: cs = 811; goto _test_eof; 
	_test_eof812: cs = 812; goto _test_eof; 
	_test_eof813: cs = 813; goto _test_eof; 
	_test_eof814: cs = 814; goto _test_eof; 
	_test_eof815: cs = 815; goto _test_eof; 
	_test_eof816: cs = 816; goto _test_eof; 
	_test_eof817: cs = 817; goto _test_eof; 
	_test_eof818: cs = 818; goto _test_eof; 
	_test_eof819: cs = 819; goto _test_eof; 
	_test_eof820: cs = 820; goto _test_eof; 
	_test_eof821: cs = 821; goto _test_eof; 
	_test_eof822: cs = 822; goto _test_eof; 
	_test_eof823: cs = 823; goto _test_eof; 
	_test_eof824: cs = 824; goto _test_eof; 
	_test_eof825: cs = 825; goto _test_eof; 
	_test_eof826: cs = 826; goto _test_eof; 
	_test_eof827: cs = 827; goto _test_eof; 
	_test_eof828: cs = 828; goto _test_eof; 
	_test_eof829: cs = 829; goto _test_eof; 
	_test_eof830: cs = 830; goto _test_eof; 
	_test_eof831: cs = 831; goto _test_eof; 
	_test_eof832: cs = 832; goto _test_eof; 
	_test_eof833: cs = 833; goto _test_eof; 
	_test_eof834: cs = 834; goto _test_eof; 
	_test_eof835: cs = 835; goto _test_eof; 
	_test_eof836: cs = 836; goto _test_eof; 
	_test_eof837: cs = 837; goto _test_eof; 
	_test_eof838: cs = 838; goto _test_eof; 
	_test_eof839: cs = 839; goto _test_eof; 
	_test_eof840: cs = 840; goto _test_eof; 
	_test_eof841: cs = 841; goto _test_eof; 
	_test_eof842: cs = 842; goto _test_eof; 
	_test_eof843: cs = 843; goto _test_eof; 
	_test_eof844: cs = 844; goto _test_eof; 
	_test_eof845: cs = 845; goto _test_eof; 
	_test_eof846: cs = 846; goto _test_eof; 
	_test_eof847: cs = 847; goto _test_eof; 
	_test_eof848: cs = 848; goto _test_eof; 
	_test_eof849: cs = 849; goto _test_eof; 
	_test_eof850: cs = 850; goto _test_eof; 
	_test_eof851: cs = 851; goto _test_eof; 
	_test_eof852: cs = 852; goto _test_eof; 
	_test_eof853: cs = 853; goto _test_eof; 
	_test_eof854: cs = 854; goto _test_eof; 
	_test_eof855: cs = 855; goto _test_eof; 
	_test_eof856: cs = 856; goto _test_eof; 
	_test_eof857: cs = 857; goto _test_eof; 
	_test_eof858: cs = 858; goto _test_eof; 
	_test_eof859: cs = 859; goto _test_eof; 
	_test_eof860: cs = 860; goto _test_eof; 
	_test_eof861: cs = 861; goto _test_eof; 
	_test_eof862: cs = 862; goto _test_eof; 
	_test_eof863: cs = 863; goto _test_eof; 
	_test_eof864: cs = 864; goto _test_eof; 
	_test_eof865: cs = 865; goto _test_eof; 
	_test_eof866: cs = 866; goto _test_eof; 
	_test_eof279: cs = 279; goto _test_eof; 
	_test_eof280: cs = 280; goto _test_eof; 

	_test_eof: {}
	if p == eof {
	switch cs {
	case 281, 289, 290, 291, 292, 293, 294, 295, 296, 297, 486, 843, 844, 845, 846, 847, 848, 849, 850, 851, 852, 853, 854, 855, 856, 857, 858, 859, 860, 861, 862, 863, 864, 865:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
	break
	case 314, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469, 470, 471, 472, 473, 474, 475, 476, 477, 478, 479, 480, 481, 482, 483, 484, 485, 489:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
	break
	case 282, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 487, 826, 827, 828, 829, 830, 831, 832, 833, 834, 835, 836, 837, 838, 839, 840, 841, 842:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
	break
	case 313, 431, 432, 433, 434, 435, 436, 437, 438, 439, 440, 441, 442, 443, 444, 445, 446, 447, 448, 449, 450, 451, 452, 453, 488, 490, 491, 492, 493, 494, 495, 496, 497, 500:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
	break
	case 381, 382, 383, 384, 385, 386, 387, 389, 390, 391, 392, 393, 394, 395, 396, 397, 398, 399, 400, 401, 402, 404, 405, 406, 407, 408, 409, 410, 411, 412, 413, 414, 415, 416, 419, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 430, 498, 499, 501, 503, 504, 505, 506, 507, 509, 510, 511, 512, 513, 514, 515, 516, 517, 518, 519, 520, 521, 522, 523, 524, 525, 742, 743, 744, 745, 746, 748, 749, 750, 751, 752, 753, 754, 755, 756, 757, 758, 759, 760, 761:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	break
	case 283, 284, 285, 286, 287, 288, 348, 349, 350, 351, 352, 353, 355, 356, 357, 358, 359, 360, 361, 362, 363, 364, 365, 366, 368, 369, 370, 371, 372, 373, 374, 375, 376, 377, 378, 379, 380, 762, 763, 764, 765, 766, 767, 768, 770, 771, 772, 773, 774, 776, 777, 778, 780, 781, 782, 783, 784, 785, 786, 787, 788, 789, 790, 791, 792, 793, 794, 795, 796, 797, 798, 799, 800, 801, 804, 805, 806, 807, 808, 809, 810, 811, 812, 813, 814, 815, 816, 817, 818, 866:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	break
	case 315, 316, 317, 318, 319, 320, 321, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 333, 334, 335, 336, 338, 339, 340, 341, 342, 343, 344, 345, 346, 347, 526, 527, 530, 537, 553, 554, 555, 556, 557, 558, 559, 560, 561, 562, 563, 564, 566, 567, 568, 569, 570, 572, 573, 574, 575, 576, 577, 578, 579, 580, 581, 582, 583, 584, 585, 586, 587, 588, 589, 590, 591, 592, 593, 594, 595, 596, 597, 598, 599, 604, 605, 606, 622, 623, 624, 625, 626, 627, 628, 631, 632, 633, 634, 635, 636, 645, 675, 676, 677, 681, 702, 703, 704, 705, 706, 707, 708, 709, 710, 711, 712, 713, 714, 715, 741, 819, 820, 821, 823, 824, 825:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	break
	case 417, 418, 769:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	break
	case 629, 630, 747:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	break
	case 802, 803, 822:
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	break
	case 388:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	break
	case 354:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	break
	case 322, 528, 529, 531, 532, 533, 534, 535, 536, 717, 718, 719, 720, 721, 722, 723, 724, 725, 726, 727, 728, 729, 730, 731, 732, 733, 734, 735, 736, 737, 738, 739, 740:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 4 "types.rl"
	{
            r.(*RR_A).Hdr = *hdr
            r.(*RR_A).A = net.ParseIP(data[mark:p])
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	break
	case 508:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	break
	case 779:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	break
	case 571, 646, 647, 648, 649, 650, 651, 652, 653, 654, 655, 656, 657, 658, 659, 660, 661, 662, 663, 664, 665, 666, 667, 668, 669, 670, 671, 672, 673, 674, 678, 679, 680:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 8 "types.rl"
	{
            r.(*RR_NS).Hdr = *hdr
            r.(*RR_NS).Ns = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	break
	case 403:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	break
	case 367:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	break
	case 337, 538, 539, 540, 541, 542, 543, 544, 545, 546, 547, 548, 549, 550, 551, 552, 600, 601, 602, 603, 690, 691, 692, 693, 694, 695, 696, 697, 698, 699, 700, 701, 716:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 12 "types.rl"
	{
            r.(*RR_CNAME).Hdr = *hdr
            r.(*RR_CNAME).Cname = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	break
	case 502:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 31 "types.rl"
	{
            r.(*RR_DS).Hdr = *hdr;
            r.(*RR_DS).KeyTag = uint16(num[0])
            r.(*RR_DS).Algorithm = uint8(num[1])
            r.(*RR_DS).DigestType = uint8(num[2])
            r.(*RR_DS).Digest = txt[0]
        }
	break
	case 775:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 38 "types.rl"
	{
            r.(*RR_DNSKEY).Hdr = *hdr;
            r.(*RR_DNSKEY).Flags = uint16(num[0])
            r.(*RR_DNSKEY).Protocol = uint8(num[1])
            r.(*RR_DNSKEY).Algorithm = uint8(num[2])
            r.(*RR_DNSKEY).PublicKey = txt[0]
        }
	break
	case 565, 607, 608, 609, 610, 611, 612, 613, 614, 615, 616, 617, 618, 619, 620, 621, 637, 638, 639, 640, 641, 642, 643, 644, 682, 683, 684, 685, 686, 687, 688, 689:
// line 31 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 26 "types.rl"
	{
            r.(*RR_MX).Hdr = *hdr;
            r.(*RR_MX).Pref = uint16(num[0])
            r.(*RR_MX).Mx = txt[0]
        }
// line 32 "zparse.rl"
	{ txt[k] = data[mark:p]; k++ }
// line 45 "types.rl"
	{
            r.(*RR_RRSIG).Hdr = *hdr;
            r.(*RR_RRSIG).TypeCovered = uint16(num[0])
            r.(*RR_RRSIG).Algorithm = uint8(num[1])
            r.(*RR_RRSIG).Labels = uint8(num[2])
            r.(*RR_RRSIG).OrigTtl = uint32(num[3])
            r.(*RR_RRSIG).Expiration = uint32(num[4])
            r.(*RR_RRSIG).Inception = uint32(num[5])
            r.(*RR_RRSIG).KeyTag = uint16(num[6])
            r.(*RR_RRSIG).SignerName = txt[0]
            r.(*RR_RRSIG).Signature = txt[1]
        }
	break
// line 28547 "zparse.go"
	}
	}

	_out: {}
	}

// line 80 "zparse.rl"


        if cs < z_first_final {
                // No clue what I'm doing what so ever
                if p == pe {
                        return nil, os.ErrorString("unexpected eof")
                } else {
                        return nil, os.ErrorString(fmt.Sprintf("error at position %d", p))
                }
        }
        return r ,nil
}
