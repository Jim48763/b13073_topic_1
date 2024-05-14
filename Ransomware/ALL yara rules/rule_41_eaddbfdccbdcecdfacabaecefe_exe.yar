rule eaddbfdccbdcecdfacabaecefe_exe {
strings:
        $s1 = "runtime.uint64mod"
        $s2 = "asn1:\"optional\""
        $s3 = "*syscall.Sockaddr"
        $s4 = "*[]map[string]int"
        $s5 = "runtime.runqsteal"
        $s6 = "crypto/md5/md5.go"
        $s7 = "runtime.emptyfunc"
        $s8 = "*regexp.runeSlice"
        $s9 = "syscall.Signal.String"
        $s10 = "timerModifiedEarliest"
        $s11 = "runtime.cansemacquire"
        $s12 = "runtime.getproccount"
        $s13 = "runtime.selectnbsend"
        $s14 = "hasScavengeCandidate"
        $s15 = "runtime.externalthreadhandler"
        $s16 = "runtime.queuefinalizer"
        $s17 = "CreateIoCompletionPort"
        $s18 = "encoding/asn1/common.go"
        $s19 = "fatal error: cgo callback before cgo call"
        $s20 = "*regexp.onePassProg"
condition:
    uint16(0) == 0x5a4d and filesize < 2244KB and
    4 of them
}
    
