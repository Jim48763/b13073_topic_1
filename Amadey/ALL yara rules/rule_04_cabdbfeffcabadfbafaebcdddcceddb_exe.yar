rule cabdbfeffcabadfbafaebcdddcceddb_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = ")iiig_b``\"%%\"1[>>"
        $s3 = "RegSetValueExA"
        $s4 = "ProductName"
        $s5 = "eqU-OdL';A0"
        $s6 = "VarFileInfo"
        $s7 = "FileDescription"
        $s8 = "DeviceIoControl"
        $s9 = "DestroyPropertySheetPage"
        $s10 = "TerminateProcess"
        $s11 = "GetModuleHandleW"
        $s12 = "UnregisterHotKey"
        $s13 = "EnterCriticalSection"
        $s14 = "UnhookWindowsHookEx"
        $s15 = "+&wvs4`\\G?f"
        $s16 = "GetTickCount"
        $s17 = "SetupCloseLog"
        $s18 = "CorExitProcess"
        $s19 = "SetHandleCount"
        $s20 = "CertStrToNameA"
condition:
    uint16(0) == 0x5a4d and filesize < 469KB and
    4 of them
}
    
