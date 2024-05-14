rule addbffaedacadedfcbdbbbab_exe {
strings:
        $s1 = "*pe.DataDirectory"
        $s2 = "*syscall.Sockaddr"
        $s3 = "*[]map[string]int"
        $s4 = "runtime.runqsteal"
        $s5 = "MinorImageVersion"
        $s6 = "timerModifiedEarliest"
        $s7 = "runtime.cansemacquire"
        $s8 = "assignEncodingAndSize"
        $s9 = "syscall.FindFirstFile"
        $s10 = "runtime.getproccount"
        $s11 = "type..eq.runtime.mOS"
        $s12 = "runtime.(*itab).init"
        $s13 = "hasScavengeCandidate"
        $s14 = "runtime.externalthreadhandler"
        $s15 = "runtime.queuefinalizer"
        $s16 = "CreateIoCompletionPort"
        $s17 = "fatal error: cgo callback before cgo call"
        $s18 = "NumberOfLineNumbers"
        $s19 = "runtime.modulesinit"
        $s20 = "runtime.dodeltimer0"
condition:
    uint16(0) == 0x5a4d and filesize < 1909KB and
    4 of them
}
    
