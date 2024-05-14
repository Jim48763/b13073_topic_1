rule dcdcceadafcfbcacbfadfefceceda_exe {
strings:
        $s1 = "_initialize_narrow_environment"
        $s2 = "GetConsoleWindow"
        $s3 = "TerminateProcess"
        $s4 = "GetModuleHandleW"
        $s5 = "GetCurrentThreadId"
        $s6 = "MSVCP140.dll"
        $s7 = "Unknown exception"
        $s8 = "GetSystemTimeAsFileTime"
        $s9 = "IsProcessorFeaturePresent"
        $s10 = "GetCurrentProcess"
        $s11 = "__current_exception_context"
        $s12 = "</assembly>"
        $s13 = "IsDebuggerPresent"
        $s14 = "_initialize_onexit_table"
        $s15 = "KERNEL32.dll"
        $s16 = "_controlfp_s"
        $s17 = ".rdata$voltmd"
        $s18 = "    <security>"
        $s19 = "bad allocation"
        $s20 = "__std_terminate"
condition:
    uint16(0) == 0x5a4d and filesize < 22KB and
    4 of them
}
    
