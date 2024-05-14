rule aecdcbdecccbefdcdeccbcaeaec_exe {
strings:
        $s1 = "RegSetValueExA"
        $s2 = "GetWindowDC"
        $s3 = "_initialize_narrow_environment"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleW"
        $s6 = "GetCurrentThreadId"
        $s7 = "CreateCompatibleDC"
        $s8 = "nopqrstsCPAD"
        $s9 = "_`abcdefg8fh"
        $s10 = "GetTickCount"
        $s11 = "NtRaiseHardError"
        $s12 = "RegCreateKeyExA"
        $s13 = "GetSystemTimeAsFileTime"
        $s14 = "U.3[*1;\"M"
        $s15 = "'()*+,-./0"
        $s16 = "IsProcessorFeaturePresent"
        $s17 = "GetCurrentProcess"
        $s18 = "__current_exception_context"
        $s19 = "GetSystemMetrics"
        $s20 = "</assembly>"
condition:
    uint16(0) == 0x5a4d and filesize < 111KB and
    4 of them
}
    
