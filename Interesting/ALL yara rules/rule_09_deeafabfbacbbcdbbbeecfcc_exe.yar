rule deeafabfbacbbcdbbbeecfcc_exe {
strings:
        $s1 = "GetWindowDC"
        $s2 = "PQ7R5STUVWX"
        $s3 = "_initialize_narrow_environment"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleW"
        $s6 = "GetCurrentThreadId"
        $s7 = "CreateCompatibleDC"
        $s8 = "GetTickCount"
        $s9 = "[\\]^]_`abcd-"
        $s10 = "SystemQuestion"
        $s11 = "NtRaiseHardError"
        $s12 = "GetSystemTimeAsFileTime"
        $s13 = "PlaySoundA"
        $s14 = "IsProcessorFeaturePresent"
        $s15 = "GetCurrentProcess"
        $s16 = "__current_exception_context"
        $s17 = "GetSystemMetrics"
        $s18 = "RSDS$7]-T3I"
        $s19 = "</assembly>"
        $s20 = "IsDebuggerPresent"
condition:
    uint16(0) == 0x5a4d and filesize < 179KB and
    4 of them
}
    
