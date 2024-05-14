rule ccfeccfffbafebbaedaaebdefbae_exe {
strings:
        $s1 = "z`p#``coadonkeg"
        $s2 = "`local vftable'"
        $s3 = "TerminateProcess"
        $s4 = "SetFilePointerEx"
        $s5 = "EnterCriticalSection"
        $s6 = "FindFirstFileExW"
        $s7 = "RtlCaptureContext"
        $s8 = "LoadLibraryExW"
        $s9 = "`udt returning'"
        $s10 = "GetSystemTimeAsFileTime"
        $s11 = "GetProcessHeap"
        $s12 = "AreFileApisANSI"
        $s13 = "IsProcessorFeaturePresent"
        $s14 = "operator co_await"
        $s15 = "ExitProcess"
        $s16 = "Washington1"
        $s17 = "RtlUnwindEx"
        $s18 = " Base Class Array'"
        $s19 = "IsDebuggerPresent"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 656KB and
    4 of them
}
    
