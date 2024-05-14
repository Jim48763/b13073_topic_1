rule dcabaeccecfabcacaddcde_exe {
strings:
        $s1 = "asn1:\"optional\""
        $s2 = "runtime.assertI2I"
        $s3 = "*syscall.Sockaddr"
        $s4 = "*[]map[string]int"
        $s5 = "runtime.runqsteal"
        $s6 = "crypto/md5/md5.go"
        $s7 = "syscall.Signal.String"
        $s8 = "timerModifiedEarliest"
        $s9 = "runtime.cansemacquire"
        $s10 = "syscall.CreateProcessAsUser"
        $s11 = "runtime.getproccount"
        $s12 = "type..eq.runtime.mOS"
        $s13 = "os/exec.lookExtensions"
        $s14 = "runtime.queuefinalizer"
        $s15 = "CreateIoCompletionPort"
        $s16 = "encoding/asn1/common.go"
        $s17 = "fatal error: cgo callback before cgo call"
        $s18 = "io.discard.ReadFrom"
        $s19 = "runtime.clobberfree"
        $s20 = "runtime.dodeltimer0"
condition:
    uint16(0) == 0x5a4d and filesize < 2160KB and
    4 of them
}
    
