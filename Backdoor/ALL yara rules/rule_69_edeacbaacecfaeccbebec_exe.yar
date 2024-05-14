rule edeacbaacecfaeccbebec_exe {
strings:
        $s1 = "runtime.printbool"
        $s2 = "json:\"is_admin\""
        $s3 = "*[]http.ConnState"
        $s4 = "*big.RoundingMode"
        $s5 = "*map[uint32]int32"
        $s6 = "io/ioutil.Discard"
        $s7 = ")?/a*F,#)_+-){*7)"
        $s8 = "runtime.didothers"
        $s9 = "asn1:\"optional\""
        $s10 = "unicode.Cuneiform"
        $s11 = "reflect.makeBytes"
        $s12 = "*rc4.KeySizeError"
        $s13 = "net/url.getscheme"
        $s14 = "client.RestoreDep"
        $s15 = "useRegisteredProtocol"
        $s16 = "$f64.3fc7466496cb03de"
        $s17 = "syscall.Signal.String"
        $s18 = "assignEncodingAndSize"
        $s19 = "reflect.StructTag.Get"
        $s20 = "type..eq.net.UnixAddr"
condition:
    uint16(0) == 0x5a4d and filesize < 7943KB and
    4 of them
}
    
