rule aafceaaadeebbddebabdcde_dll {
strings:
        $s1 = "invalid string position"
        $s2 = "`local vftable'"
        $s3 = "TerminateProcess"
        $s4 = "GetModuleHandleW"
        $s5 = "SetFilePointerEx"
        $s6 = "EnterCriticalSection"
        $s7 = "7 7$7(7,7074787<7@7D7H7L7P7T7X7\\7`7l=t=|="
        $s8 = "GetCurrentThreadId"
        $s9 = "GetLocalTime"
        $s10 = "conti_v3.dll"
        $s11 = "FindFirstFileExA"
        $s12 = "Unknown exception"
        $s13 = "LoadLibraryExW"
        $s14 = "CorExitProcess"
        $s15 = "`udt returning'"
        $s16 = "    </security>"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "GetProcessHeap"
        $s19 = "IsProcessorFeaturePresent"
        $s20 = "operator co_await"
condition:
    uint16(0) == 0x5a4d and filesize < 195KB and
    4 of them
}
    
