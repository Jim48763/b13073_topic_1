rule bfaffefcddfbeecffbbabdbafeaffd_exe {
strings:
        $s1 = "*map[uint32]int32"
        $s2 = "*func(*[][]uint8)"
        $s3 = "asn1:\"optional\""
        $s4 = "*[][]*http.Cookie"
        $s5 = "runtime.assertI2I"
        $s6 = "syscall.Ftruncate"
        $s7 = "abortStreamLocked"
        $s8 = "runtime.runqsteal"
        $s9 = "crypto/md5/md5.go"
        $s10 = "hasPrecisionScale"
        $s11 = "WriteWindowUpdate"
        $s12 = "*[]http.ConnState"
        $s13 = "net.SplitHostPort"
        $s14 = "net/url.getScheme"
        $s15 = "*regexp.runeSlice"
        $s16 = "regexp.(*Regexp).Copy"
        $s17 = "timerModifiedEarliest"
        $s18 = "useRegisteredProtocol"
        $s19 = "CRLDistributionPoints"
        $s20 = "runtime.cansemacquire"
condition:
    uint16(0) == 0x5a4d and filesize < 6951KB and
    4 of them
}
    
