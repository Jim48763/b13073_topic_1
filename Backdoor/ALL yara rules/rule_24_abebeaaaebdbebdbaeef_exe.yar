rule abebeaaaebdbebdbaeef_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "oyagefuhqjx"
        $s3 = "`local vftable'"
        $s4 = "TerminateProcess"
        $s5 = "SetFilePointerEx"
        $s6 = "EnterCriticalSection"
        $s7 = "kcgpyesjmkfi"
        $s8 = "fceuizrtxyqy"
        $s9 = "FindFirstFileExA"
        $s10 = "rrhohtqlnkzuw"
        $s11 = "phwgikfmfaosh"
        $s12 = "hbtrgnfzqcddh"
        $s13 = "Unknown exception"
        $s14 = "RtlCaptureContext"
        $s15 = "CorExitProcess"
        $s16 = "LoadLibraryExW"
        $s17 = "`udt returning'"
        $s18 = "vemuycsheyzvjmd"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "dingkpynhjpjybpl"
condition:
    uint16(0) == 0x5a4d and filesize < 408KB and
    4 of them
}
    
