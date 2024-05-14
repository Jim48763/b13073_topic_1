rule Trojan_MrsMajor__exe {
strings:
        $s1 = "invalid distance code"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "IsWindowVisible"
        $s5 = "FileDescription"
        $s6 = "PathAddBackslashW"
        $s7 = "RemoveDirectoryW"
        $s8 = "UnregisterClassW"
        $s9 = "TerminateProcess"
        $s10 = "GetModuleHandleW"
        $s11 = "Integer overflow"
        $s12 = "DispatchMessageW"
        $s13 = "GetCurrentDirectoryW"
        $s14 = "TranslateAcceleratorW"
        $s15 = "Misaligned data access"
        $s16 = "GetCurrentThreadId"
        $s17 = "SHBrowseForFolderW"
        $s18 = "EnableWindow"
        $s19 = "Division by zero "
        $s20 = "invalid window size"
condition:
    uint16(0) == 0x5a4d and filesize < 386KB and
    4 of them
}
    
