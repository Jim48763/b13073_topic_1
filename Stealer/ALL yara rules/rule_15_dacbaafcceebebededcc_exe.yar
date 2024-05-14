rule dacbaafcceebebededcc_exe {
strings:
        $s1 = "SetConsoleCtrlHandler"
        $s2 = "RemoveDirectoryW"
        $s3 = "UnregisterClassW"
        $s4 = "DispatchMessageW"
        $s5 = "TerminateProcess"
        $s6 = "Integer overflow"
        $s7 = "GetModuleHandleW"
        $s8 = "GetCurrentDirectoryW"
        $s9 = "TranslateAcceleratorW"
        $s10 = "incorrect length check"
        $s11 = "Misaligned data access"
        $s12 = "SHBrowseForFolderW"
        $s13 = "EnableWindow"
        $s14 = "Division by zero "
        $s15 = "invalid window size"
        $s16 = "RtlGetVersion"
        $s17 = "InitCommonControlsEx"
        $s18 = "SetWindowLongW"
        $s19 = "need dictionary"
        $s20 = "invalid distances set"
condition:
    uint16(0) == 0x5a4d and filesize < 97KB and
    4 of them
}
    
