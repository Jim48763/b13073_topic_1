rule cfecdaecbadbfbeccdbdbcffa_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "TerminateProcess"
        $s3 = "What guarantees?"
        $s4 = "QBIDPService"
        $s5 = "infopath.exe"
        $s6 = "GetTickCount"
        $s7 = "GetSystemInfo"
        $s8 = "MapViewOfFile"
        $s9 = "Opera Software"
        $s10 = "ControlService"
        $s11 = "ocautoupds.exe"
        $s12 = "OpenSCManagerA"
        $s13 = "RmStartSession"
        $s14 = "SetFileAttributesW"
        $s15 = "GetDriveTypeW"
        $s16 = "GetProcessHeap"
        $s17 = "IsWow64Process"
        $s18 = "isqlplussvc.exe"
        $s19 = "thunderbird.exe"
        $s20 = "IsProcessorFeaturePresent"
condition:
    uint16(0) == 0x5a4d and filesize < 35KB and
    4 of them
}
    
