rule aaddafacdbfbfeadeefeeaf_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "_initialize_narrow_environment"
        $s4 = "FileDescription"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleW"
        $s7 = "__std_type_info_destroy_list"
        $s8 = "GetCurrentThreadId"
        $s9 = "GetSystemTimeAsFileTime"
        $s10 = "OpenProcessToken"
        $s11 = "VirtualProtect"
        $s12 = "LegalTrademarks"
        $s13 = "MiKTeX.org"
        $s14 = "IsProcessorFeaturePresent"
        $s15 = "GetCurrentProcess"
        $s16 = "_execute_onexit_table"
        $s17 = "ExitProcess"
        $s18 = "IsDebuggerPresent"
        $s19 = "_initialize_onexit_table"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 47KB and
    4 of them
}
    
