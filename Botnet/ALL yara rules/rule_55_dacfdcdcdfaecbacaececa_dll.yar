rule dacfdcdcdfaecbacaececa_dll {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "`vector destructor iterator'"
        $s5 = "RegSetValueExW"
        $s6 = "invalid string position"
        $s7 = "LC_MONETARY"
        $s8 = "ProductName"
        $s9 = "VarFileInfo"
        $s10 = "FileDescription"
        $s11 = "english-jamaica"
        $s12 = "`local vftable'"
        $s13 = "spanish-venezuela"
        $s14 = "TerminateProcess"
        $s15 = "SetFilePointerEx"
        $s16 = "EnterCriticalSection"
        $s17 = "GetCurrentDirectoryW"
        $s18 = "UpdateWindow"
        $s19 = "south-africa"
        $s20 = "FindFirstFileExW"
condition:
    uint16(0) == 0x5a4d and filesize < 604KB and
    4 of them
}
    
