rule ebfbbcacdffebddfaaefedcf_exe {
strings:
        $s1 = "_beginthreadex"
        $s2 = "_CorExeMain"
        $s3 = "_initialize_narrow_environment"
        $s4 = "IsWindowVisible"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleA"
        $s7 = "__std_type_info_destroy_list"
        $s8 = "__std_exception_copy"
        $s9 = "MSVCP140.dll"
        $s10 = "SetWindowPos"
        $s11 = "GetThreadContext"
        $s12 = "SuspendThread"
        $s13 = "Unknown exception"
        $s14 = "RtlCaptureContext"
        $s15 = "GetSystemTimeAsFileTime"
        $s16 = "SymInitialize"
        $s17 = "VirtualProtect"
        $s18 = "IsProcessorFeaturePresent"
        $s19 = "_execute_onexit_table"
        $s20 = "GetCurrentThread"
condition:
    uint16(0) == 0x5a4d and filesize < 47KB and
    4 of them
}
    
