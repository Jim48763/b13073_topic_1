rule fbdefddfabeecbfdcfbebacebc_exe {
strings:
        $s1 = "Modification Time"
        $s2 = "`vector destructor iterator'"
        $s3 = "Never open contact sheets"
        $s4 = "invalid string position"
        $s5 = "ProductName"
        $s6 = "PdhOpenLogA"
        $s7 = "EnumObjects"
        $s8 = "VarFileInfo"
        $s9 = "`local vftable'"
        $s10 = "RasDeleteEntryW"
        $s11 = "FileDescription"
        $s12 = "NetShareGetInfo"
        $s13 = "SetFilePointerEx"
        $s14 = "TerminateProcess"
        $s15 = "GetModuleHandleW"
        $s16 = "DispatchMessageA"
        $s17 = "TcOpenInterfaceW"
        $s18 = "into dated folder only"
        $s19 = "EventWriteTransfer"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 325KB and
    4 of them
}
    
