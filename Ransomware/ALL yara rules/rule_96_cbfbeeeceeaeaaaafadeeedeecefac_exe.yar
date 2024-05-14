rule cbfbeeeceeaeaaaafadeeedeecefac_exe {
strings:
        $s1 = "$strconv.NumError"
        $s2 = "*big.RoundingMode"
        $s3 = "asn1:\"optional\""
        $s4 = "*hash<int,string>"
        $s5 = "$syscall.LazyProc"
        $s6 = "*[]map[string]int"
        $s7 = "unicode.Cuneiform"
        $s8 = "runtime.didothers"
        $s9 = "leftRotations.ptr"
        $s10 = "$f64.3fc7466496cb03de"
        $s11 = "type..eq.net.dnsRR_NS"
        $s12 = "$runtime.stringStruct"
        $s13 = "runtime.cansemacquire"
        $s14 = "syscall.InvalidHandle"
        $s15 = "__`A`-M#--7-77:7AABaAAACKKKLW7_0KA"
        $s16 = "encoding/pem.decodeError"
        $s17 = "runtime.getproccount"
        $s18 = "runtime.tagGoroutine"
        $s19 = "strings.countGeneric"
        $s20 = "runtime.externalthreadhandler"
condition:
    uint16(0) == 0x5a4d and filesize < 3065KB and
    4 of them
}
    
