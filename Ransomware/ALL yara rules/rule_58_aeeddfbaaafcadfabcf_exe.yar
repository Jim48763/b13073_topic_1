rule aeeddfbaaafcadfabcf_exe {
strings:
        $s1 = ")?/a*F,#)_+-){*7)"
        $s2 = "runtime.uint64mod"
        $s3 = "*map[uint32]int32"
        $s4 = "asn1:\"optional\""
        $s5 = "*[][]*http.Cookie"
        $s6 = "runtime.assertI2I"
        $s7 = "runtime.runqsteal"
        $s8 = "3*3@3I3m4(6V6k8L:"
        $s9 = "WriteWindowUpdate"
        $s10 = "runtime.emptyfunc"
        $s11 = "*[]http.ConnState"
        $s12 = "net.SplitHostPort"
        $s13 = "useRegisteredProtocol"
        $s14 = "runtime.cansemacquire"
        $s15 = "FirstMulticastAddress"
        $s16 = "assignEncodingAndSize"
        $s17 = "type..eq.net.UnixAddr"
        $s18 = "net/textproto.NewReader"
        $s19 = "6L6P6\\6,7\\7`7h7l789h9l9t9x9t;"
        $s20 = "syscall.FindFirstFile"
condition:
    uint16(0) == 0x5a4d and filesize < 3966KB and
    4 of them
}
    
