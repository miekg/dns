package dns

import ( "testing")

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

        println(SecondsToString(604800))        // 1w
        println(SecondsToString(604799))        // 1w-1
        println(SecondsToString(86400))         // 1d
        println(SecondsToString(86401))         // 1d+1
        println(SecondsToString(86399))         // 1d-1
        println(SecondsToString(86))            // 1m26
        println(SecondsToString(60))            // 1m
        println(SecondsToString(59))            // 59
}
