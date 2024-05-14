rule eddedaedceffcaadd_exe {
strings:
        $s1 = "asn1:\"optional\""
        $s2 = "runtime.assertI2I"
        $s3 = "*[]map[string]int"
        $s4 = "runtime.runqsteal"
        $s5 = "crypto/md5/md5.go"
        $s6 = "dvnzzn7I.IAVJsdlV"
        $s7 = "net.SplitHostPort"
        $s8 = "*regexp.runeSlice"
        $s9 = "timerModifiedEarliest"
        $s10 = "runtime.cansemacquire"
        $s11 = "FirstMulticastAddress"
        $s12 = "syscall.CreateProcessAsUser"
        $s13 = "runtime.getproccount"
        $s14 = "type..eq.runtime.mOS"
        $s15 = "*cipher.cbcEncrypter"
        $s16 = "runtime.selectnbsend"
        $s17 = "os/exec.lookExtensions"
        $s18 = "runtime.queuefinalizer"
        $s19 = "CreateIoCompletionPort"
        $s20 = "fatal error: cgo callback before cgo call"
condition:
    uint16(0) == 0x5a4d and filesize < 3120KB and
    4 of them
}
    
