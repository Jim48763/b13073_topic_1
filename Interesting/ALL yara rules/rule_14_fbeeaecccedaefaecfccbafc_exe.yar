rule fbeeaecccedaefaecfccbafc_exe {
strings:
        $s1 = "_initialize_narrow_environment"
        $s2 = "GetModuleHandleW"
        $s3 = "TerminateProcess"
        $s4 = "CreateCompatibleDC"
        $s5 = "GetCurrentThreadId"
        $s6 = "GetTickCount"
        $s7 = "NtRaiseHardError"
        $s8 = "GetSystemTimeAsFileTime"
        $s9 = "IsProcessorFeaturePresent"
        $s10 = "GetCurrentProcess"
        $s11 = "GetSystemMetrics"
        $s12 = "</assembly>"
        $s13 = "IsDebuggerPresent"
        $s14 = "_initialize_onexit_table"
        $s15 = "_controlfp_s"
        $s16 = "RedrawWindow"
        $s17 = "KERNEL32.dll"
        $s18 = "    <security>"
        $s19 = "VirtualAlloc"
        $s20 = "USER32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 18KB and
    4 of them
}
    
