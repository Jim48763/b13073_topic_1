rule dfacdfeeecedafcddfaabc_exe {
strings:
        $s1 = "k^lmnopqr===st"
        $s2 = "=>7?@ABCD77EFG"
        $s3 = "_initialize_narrow_environment"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleW"
        $s6 = "GetCurrentThreadId"
        $s7 = "CreateCompatibleDC"
        $s8 = "GetTickCount"
        $s9 = "NOPQRSTTUVJW"
        $s10 = "bajkKKlmdaQG'"
        $s11 = "NtRaiseHardError"
        $s12 = "GetSystemTimeAsFileTime"
        $s13 = "i*bf6!W9't"
        $s14 = "IsProcessorFeaturePresent"
        $s15 = "GetCurrentProcess"
        $s16 = "__current_exception_context"
        $s17 = "GetSystemMetrics"
        $s18 = "</assembly>"
        $s19 = "IsDebuggerPresent"
        $s20 = "_initialize_onexit_table"
condition:
    uint16(0) == 0x5a4d and filesize < 86KB and
    4 of them
}
    
