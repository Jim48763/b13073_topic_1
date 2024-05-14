rule cbbeaaddebebfcaafefbddf_exe {
strings:
        $s1 = "PQ7R5STUVWX"
        $s2 = "_initialize_narrow_environment"
        $s3 = "TerminateProcess"
        $s4 = "GetModuleHandleW"
        $s5 = "@winRainbow2! rainbow"
        $s6 = "GetCurrentThreadId"
        $s7 = "CreateCompatibleDC"
        $s8 = "GetTickCount"
        $s9 = "[\\]^]_`abcd-"
        $s10 = "NtRaiseHardError"
        $s11 = "GetSystemTimeAsFileTime"
        $s12 = "IsProcessorFeaturePresent"
        $s13 = "GetCurrentProcess"
        $s14 = "__current_exception_context"
        $s15 = "GetSystemMetrics"
        $s16 = "</assembly>"
        $s17 = "IsDebuggerPresent"
        $s18 = "_initialize_onexit_table"
        $s19 = "RedrawWindow"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 178KB and
    4 of them
}
    
