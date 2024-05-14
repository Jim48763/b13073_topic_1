rule eaabecacedabeddddfc_exe {
strings:
        $s1 = "[2][65536]uintptr"
        $s2 = "runtime.scanstack"
        $s3 = "runtime.printbool"
        $s4 = "leftRotations.ptr"
        $s5 = "path/filepath.Dir"
        $s6 = "os.FileMode.IsDir"
        $s7 = "reflect.DeepEqual"
        $s8 = "transformComplete"
        $s9 = "runtime.didothers"
        $s10 = "asn1:\"optional\""
        $s11 = "unicode.Cuneiform"
        $s12 = "reflect.makeBytes"
        $s13 = "net/url.getscheme"
        $s14 = "keyAgreement.itab"
        $s15 = "*strconv.NumError"
        $s16 = "$f64.3fc7466496cb03de"
        $s17 = "syscall.Signal.String"
        $s18 = "assignEncodingAndSize"
        $s19 = "runtime.cansemacquire"
        $s20 = "OpH+GPL+WXL+_`L+ghL+opH"
condition:
    uint16(0) == 0x5a4d and filesize < 6687KB and
    4 of them
}
    
