rule afcedbaedccfbafcfaddaff_exe {
strings:
        $s1 = "invalid distance code"
        $s2 = "IsWindowVisible"
        $s3 = "GetShortPathNameW"
        $s4 = "PathAddBackslashW"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleW"
        $s7 = "RemoveDirectoryW"
        $s8 = "Integer overflow"
        $s9 = "DispatchMessageW"
        $s10 = "GetCurrentDirectoryW"
        $s11 = "InitializeCriticalSection"
        $s12 = "TranslateAcceleratorW"
        $s13 = "Misaligned data access"
        $s14 = "GetCurrentThreadId"
        $s15 = "SHBrowseForFolderW"
        $s16 = "EnableWindow"
        $s17 = "SetWindowPos"
        $s18 = "Division by zero "
        $s19 = "invalid window size"
        $s20 = "InitCommonControlsEx"
condition:
    uint16(0) == 0x5a4d and filesize < 136KB and
    4 of them
}
    
