rule dddfdbbffeebdfbfcdecadbfacece_exe {
strings:
        $s1 = "cross device link"
        $s2 = "CreateThreadpoolTimer"
        $s3 = "executable format error"
        $s4 = "result out of range"
        $s5 = "directory not empty"
        $s6 = "invalid string position"
        $s7 = "operation canceled"
        $s8 = "LC_MONETARY"
        $s9 = "`local vftable'"
        $s10 = "spanish-venezuela"
        $s11 = "Result matrix is "
        $s12 = "ContextStackSize"
        $s13 = "SetFilePointerEx"
        $s14 = "TerminateProcess"
        $s15 = "GetModuleHandleW"
        $s16 = "destination address required"
        $s17 = "SetEndOfFile"
        $s18 = "south-africa"
        $s19 = "resource deadlock would occur"
        $s20 = "device or resource busy"
condition:
    uint16(0) == 0x5a4d and filesize < 315KB and
    4 of them
}
    