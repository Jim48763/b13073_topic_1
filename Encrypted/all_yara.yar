import pe
rule dfbbcbadccfdbeedadbdaafabbdcaab_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "`local vftable'"
        $s3 = "TerminateProcess"
        $s4 = "GetModuleHandleW"
        $s5 = "GetCurrentThreadId"
        $s6 = "SetEndOfFile"
        $s7 = "GetTickCount"
        $s8 = "Start ransomware test."
        $s9 = "Unknown exception"
        $s10 = "No files found"
        $s11 = "SetHandleCount"
        $s12 = "`udt returning'"
        $s13 = "</assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD"
        $s14 = "GetSystemTimeAsFileTime"
        $s15 = "InterlockedDecrement"
        $s16 = "GetProcessHeap"
        $s17 = "IsProcessorFeaturePresent"
        $s18 = "GetCurrentProcess"
        $s19 = "1 1$1(1,1014181<1@1D1H1L1P1T1X1\\1`1d1h1l1p1t1x1|1"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 84KB and
    4 of them
}
    