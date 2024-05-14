rule ebbadeebcefbddacecddcaab_dll {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "cross device link"
        $s4 = "CreateThreadpoolTimer"
        $s5 = "`vector destructor iterator'"
        $s6 = "SetDefaultDllDirectories"
        $s7 = "executable format error"
        $s8 = "result out of range"
        $s9 = "directory not empty"
        $s10 = "RegSetValueExA"
        $s11 = "invalid string position"
        $s12 = "ios_base::failbit set"
        $s13 = "operation canceled"
        $s14 = "LC_MONETARY"
        $s15 = "ProductName"
        $s16 = "VarFileInfo"
        $s17 = "FileDescription"
        $s18 = "english-jamaica"
        $s19 = "`local vftable'"
        $s20 = "spanish-venezuela"
condition:
    uint16(0) == 0x5a4d and filesize < 221KB and
    4 of them
}
    
