rule dbbcdebefbfbcdadcafbedccfccace_exe {
strings:
        $s1 = "asn1:\"optional\""
        $s2 = "*syscall.Sockaddr"
        $s3 = "*[]map[string]int"
        $s4 = "runtime.runqsteal"
        $s5 = "crypto/md5/md5.go"
        $s6 = "*regexp.runeSlice"
        $s7 = "syscall.Signal.String"
        $s8 = "timerModifiedEarliest"
        $s9 = "runtime.cansemacquire"
        $s10 = "DHJ00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899eMv"
        $s11 = "runtime.getproccount"
        $s12 = "type..eq.runtime.mOS"
        $s13 = "runtime.selectnbsend"
        $s14 = "runtime.queuefinalizer"
        $s15 = "CreateIoCompletionPort"
        $s16 = "encoding/asn1/common.go"
        $s17 = "fatal error: cgo callback before cgo call"
        $s18 = "*regexp.onePassProg"
        $s19 = "runtime.clobberfree"
        $s20 = "runtime.dodeltimer0"
condition:
    uint16(0) == 0x5a4d and filesize < 3497KB and
    4 of them
}
    
