rule abddcaffdabeddbafacabfd_dll {
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
        $s10 = "invalid string position"
        $s11 = "ios_base::failbit set"
        $s12 = "operation canceled"
        $s13 = "LC_MONETARY"
        $s14 = "ProductName"
        $s15 = "VarFileInfo"
        $s16 = "FileDescription"
        $s17 = "english-jamaica"
        $s18 = "`local vftable'"
        $s19 = "spanish-venezuela"
        $s20 = "TerminateProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 214KB and
    4 of them
}
    
