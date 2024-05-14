rule dbaefdbdcfbcbcbacfdbfadddab_exe {
strings:
        $s1 = "`local vftable'"
        $s2 = "GetComputerNameA"
        $s3 = "GetModuleHandleW"
        $s4 = "TerminateProcess"
        $s5 = "EnterCriticalSection"
        $s6 = "GetCurrentThreadId"
        $s7 = "SetEndOfFile"
        $s8 = "GetTickCount"
        $s9 = "GetSystemInfo"
        $s10 = "Unknown exception"
        $s11 = "SetHandleCount"
        $s12 = "`udt returning'"
        $s13 = "GetSystemTimeAsFileTime"
        $s14 = "InterlockedDecrement"
        $s15 = "GetProcessHeap"
        $s16 = "IsProcessorFeaturePresent"
        $s17 = "GetCurrentProcess"
        $s18 = "GetSystemMetrics"
        $s19 = "CreateDirectoryA"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 72KB and
    4 of them
}
    