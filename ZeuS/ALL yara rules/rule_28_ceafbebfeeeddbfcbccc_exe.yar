rule ceafbebfeeeddbfcbccc_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "`vector destructor iterator'"
        $s3 = "Directory not empty"
        $s4 = "Runtime Error!"
        $s5 = "invalid string position"
        $s6 = "No child processes"
        $s7 = "ProductName"
        $s8 = "LC_MONETARY"
        $s9 = "VarFileInfo"
        $s10 = "DeviceIoControl"
        $s11 = "english-jamaica"
        $s12 = "`local vftable'"
        $s13 = "FileDescription"
        $s14 = "GetThreadLocale"
        $s15 = "IsWindowVisible"
        $s16 = "Masters ITC Tools"
        $s17 = "spanish-venezuela"
        $s18 = "chinese-singapore"
        $s19 = "TerminateProcess"
        $s20 = "GetModuleHandleW"
condition:
    uint16(0) == 0x5a4d and filesize < 399KB and
    4 of them
}
    
