rule aadebafbcefbfffebcdaddad_exe {
strings:
        $s1 = "cross device link"
        $s2 = "english-caribbean"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "`vector destructor iterator'"
        $s5 = "executable format error"
        $s6 = "directory not empty"
        $s7 = "result out of range"
        $s8 = "invalid string position"
        $s9 = "operation canceled"
        $s10 = "LC_MONETARY"
        $s11 = "english-jamaica"
        $s12 = "`local vftable'"
        $s13 = "spanish-venezuela"
        $s14 = "chinese-singapore"
        $s15 = "Result matrix is "
        $s16 = "SetFilePointerEx"
        $s17 = "ContextStackSize"
        $s18 = "TerminateProcess"
        $s19 = "GetModuleHandleW"
        $s20 = "destination address required"
condition:
    uint16(0) == 0x5a4d and filesize < 315KB and
    4 of them
}
    
