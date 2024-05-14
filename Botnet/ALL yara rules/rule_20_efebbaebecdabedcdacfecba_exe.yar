rule efebbaebecdabedcdacfecba_exe {
strings:
        $s1 = "*runtime.mapextra"
        $s2 = "fmt.(*pp).fmt0x64"
        $s3 = "*syscall.LazyProc"
        $s4 = "unicode.Cuneiform"
        $s5 = "runtime.staticuint64s"
        $s6 = "timerModifiedEarliest"
        $s7 = "runtime.cansemacquire"
        $s8 = "hasScavengeCandidate"
        $s9 = "runtime/internal/sys"
        $s10 = "runtime.fastrandseed"
        $s11 = "runtime.externalthreadhandler"
        $s12 = "CreateIoCompletionPort"
        $s13 = "fatal error: cgo callback before cgo call"
        $s14 = "unicode.SignWriting"
        $s15 = "runtime.clobberfree"
        $s16 = "runtime.castogscanstatus"
        $s17 = "unicode.Hebrew"
        $s18 = "runSafePointFn"
        $s19 = "runtime.GOROOT"
        $s20 = "freeSpanLocked"
condition:
    uint16(0) == 0x5a4d and filesize < 2404KB and
    4 of them
}
    
