package dns

import ( "testing"; "fmt")

func TestConversion(t *testing.T) {
/*
        println(StringToSeconds("6w8d50"))
        println(StringToSeconds("50"))
        println(StringToSeconds("1m1m"))
        println(StringToSeconds("1w"))
        println(StringToSeconds("1d"))
        println(StringToSeconds("2d"))
        println(StringToSeconds("1d1d"))
*/
/*
        println(SecondsToString(604800))        // 1w
        println(SecondsToString(604799))        // 1w-1
        println(SecondsToString(86400))         // 1d
        println(SecondsToString(86401))         // 1d+1
        println(SecondsToString(86399))         // 1d-1
        println(SecondsToString(86))            // 1m26
        println(SecondsToString(60))            // 1m
        println(SecondsToString(59))            // 59
        */
}

func TestPrivateKeyRead(t *testing.T) {
a:=`Private-key-format: v1.3
Algorithm: 5 (RSASHA1)
Modulus: vyVjCzz87g3rg9vDj1NJ1tlFP7lEY2pEQLkWGXAFuZM6Fw/bNmEH/z3ybDfsJqx4QQ6YZXN8V2kbzY7oX+tExf6AMiMIcKYzEGwg5xBYFh33du4G+6kE/VzG906ubpaIEnrZOMTdGqE7OwptAqrqXe4uGXY99ZqNdqutOKQyIzs=
PublicExponent: AQAB
PrivateExponent: PFg/RoMAjt8SJVSyDoOK4itBs3Z34rLfzVchZPJ6vDWAt1soJ6jGb4xNBmE5SpRUeqVy80RcUvQ59NFTB0UtNo/zAXhC1RfKiFCNRFTyV3k6a9CMLPAU9g4peW91lw87HXnYALTC9bTiTAoMU3vKvNx80F5qfK7qY/N28S1PMeE=
Prime1: +vPWyp37iUa7/LbhejOX/KdkhfwECUCdJF0uEePjaBCSf85xceEBzU89JFk9dCojtVqcI8xLKnRKRixg07Rc+Q==
Prime2: wv2aVWr13Cq2vRkKiHlqqP9vihGuDN/kWfmXb7slJH3s2i9+yI7vepAlow9SY8lNHOqXibEaAFsP3aj5OAAS0w==
Exponent1: sChCenBzhWV1yGvH0zQsWFpYogTKAISuyjvufvhtRTt82uJbmAjObwRUcxOBo+2Aq2kzeZ2Klf6TtLaqMXHGYQ==
Exponent2: hXiKeAWrHXWveGj3qMtTkzKl6uCHPxDSgjQy0KxNlFkOE5uHMUmF62NYH/GQ9/UG79A0wm+T2MJ8bcIINaj3OQ==
Coefficient: xzZBvs2/IT7+iRQdn9I4slRTg9ryIecx7oKEKYTOEeyL2qq7rfY/FwZGy3EqyA/3lrkfFLx76qOeqAmCTUaU4w==
Created: 20101221142359
Publish: 20101221142359
Activate: 20101221142359`

        k := new(RR_DNSKEY)
        p,err := k.PrivateKeySetString(a)
        println(err)
        p = p
        fmt.Printf("%v\n", k)
}
