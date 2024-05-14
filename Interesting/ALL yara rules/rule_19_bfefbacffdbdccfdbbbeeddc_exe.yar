rule bfefbacffdbdccfdbbbeeddc_exe {
strings:
        $s1 = "_get_initial_narrow_environment"
        $s2 = "RegSetValueExA"
        $s3 = "GetModuleHandleW"
        $s4 = "TerminateProcess"
        $s5 = "GetCurrentThreadId"
        $s6 = "RegCreateKeyExA"
        $s7 = "GetSystemTimeAsFileTime"
        $s8 = "IsProcessorFeaturePresent"
        $s9 = "GetCurrentProcess"
        $s10 = "</assembly>"
        $s11 = "IsDebuggerPresent"
        $s12 = "_initialize_onexit_table"
        $s13 = "_controlfp_s"
        $s14 = "ADVAPI32.dll"
        $s15 = "KERNEL32.dll"
        $s16 = "    <security>"
        $s17 = "USER32.dll"
        $s18 = "3\"3#4,474>4^4d4j4p4v4|4"
        $s19 = "CloseHandle"
        $s20 = "MessageBoxA"
condition:
    uint16(0) == 0x5a4d and filesize < 18KB and
    4 of them
}
    
