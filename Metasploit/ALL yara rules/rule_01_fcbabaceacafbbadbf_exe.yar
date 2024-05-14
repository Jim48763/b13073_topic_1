rule fcbabaceacafbbadbf_exe {
strings:
        $s1 = "GetConsoleOutputCP"
        $s2 = "`local vftable'"
        $s3 = "TerminateProcess"
        $s4 = "GetModuleHandleW"
        $s5 = "SetFilePointerEx"
        $s6 = "EnterCriticalSection"
        $s7 = "GetCurrentThreadId"
        $s8 = "FindFirstFileExW"
        $s9 = "LoadLibraryExW"
        $s10 = "CorExitProcess"
        $s11 = "`udt returning'"
        $s12 = "GetSystemTimeAsFileTime"
        $s13 = "GetProcessHeap"
        $s14 = "AreFileApisANSI"
        $s15 = "2#5+5b5i5s8*:2:]:d:"
        $s16 = "IsProcessorFeaturePresent"
        $s17 = "operator co_await"
        $s18 = "GetCurrentProcess"
        $s19 = "!_is_double"
        $s20 = " Base Class Array'"
condition:
    uint16(0) == 0x5a4d and filesize < 106KB and
    4 of them
}
    
