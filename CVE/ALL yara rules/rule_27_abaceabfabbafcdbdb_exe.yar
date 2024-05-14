rule abaceabfabbafcdbdb_exe {
strings:
        $s1 = "RtlNtStatusToDosError"
        $s2 = "SetThreadPriority"
        $s3 = "TerminateProcess"
        $s4 = "RemoveDirectoryW"
        $s5 = "GetModuleHandleW"
        $s6 = "_initialize_wide_environment"
        $s7 = "__std_exception_copy"
        $s8 = "MSVCP140.dll"
        $s9 = "Unknown exception"
        $s10 = "RtlCaptureContext"
        $s11 = "OpenSCManagerW"
        $s12 = "\\splwow64.exe"
        $s13 = "NtRaiseHardError"
        $s14 = "NtSetSecurityObject"
        $s15 = "GetFileAttributesW"
        $s16 = "GetSystemTimeAsFileTime"
        $s17 = "ZwSetValueKey"
        $s18 = "OpenProcessToken"
        $s19 = "GetProcessHeap"
        $s20 = "SizeofResource"
condition:
    uint16(0) == 0x5a4d and filesize < 47KB and
    4 of them
}
    
