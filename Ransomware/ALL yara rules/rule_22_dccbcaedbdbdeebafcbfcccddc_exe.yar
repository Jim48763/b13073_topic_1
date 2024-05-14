rule dccbcaedbdbdeebafcbfcccddc_exe {
strings:
        $s1 = "contirecovery.best"
        $s2 = "`local vftable'"
        $s3 = "TerminateProcess"
        $s4 = "GetModuleHandleW"
        $s5 = "SetFilePointerEx"
        $s6 = "EnterCriticalSection"
        $s7 = "GetCurrentThreadId"
        $s8 = "GetLocalTime"
        $s9 = "FindFirstFileExW"
        $s10 = "Unknown exception"
        $s11 = "LoadLibraryExW"
        $s12 = "CorExitProcess"
        $s13 = "`udt returning'"
        $s14 = "    </security>"
        $s15 = "GetSystemTimeAsFileTime"
        $s16 = "GetProcessHeap"
        $s17 = "AreFileApisANSI"
        $s18 = "IsProcessorFeaturePresent"
        $s19 = "operator co_await"
        $s20 = "GetCurrentProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 213KB and
    4 of them
}
    
