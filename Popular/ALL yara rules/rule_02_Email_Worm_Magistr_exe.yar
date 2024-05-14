rule Email_Worm_Magistr_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "msctls_progress32"
        $s3 = "GetEnvironmentStrings"
        $s4 = "RegSetValueExA"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "Switzerland"
        $s8 = "LC_MONETARY"
        $s9 = "english-jamaica"
        $s10 = "FileDescription"
        $s11 = "UpgrdHlpSatellite"
        $s12 = "spanish-venezuela"
        $s13 = "PN Upgrade Helper"
        $s14 = "TerminateProcess"
        $s15 = "GetModuleHandleA"
        $s16 = "DispatchMessageA"
        $s17 = "Symbol not found"
        $s18 = "RemoveDirectoryA"
        $s19 = "GetCurrentDirectoryA"
        $s20 = "InitializeCriticalSection"
condition:
    uint16(0) == 0x5a4d and filesize < 112KB and
    4 of them
}
    
