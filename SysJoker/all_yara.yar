import pe
rule ffddcdcfdaedadccfecc_exe {
strings:
        $s1 = "bad function call"
        $s2 = "cross device link"
        $s3 = "english-caribbean"
        $s4 = "CreateThreadpoolTimer"
        $s5 = "`vector destructor iterator'"
        $s6 = "executable format error"
        $s7 = "directory not empty"
        $s8 = "result out of range"
        $s9 = "h([0-9a-fA-F])"
        $s10 = "invalid string position"
        $s11 = "operation canceled"
        $s12 = "ProductName"
        $s13 = "LC_MONETARY"
        $s14 = "VarFileInfo"
        $s15 = "english-jamaica"
        $s16 = "`local vftable'"
        $s17 = "FileDescription"
        $s18 = "spanish-venezuela"
        $s19 = "Intel Corporation"
        $s20 = "chinese-singapore"
condition:
    uint16(0) == 0x5a4d and filesize < 397KB and
    4 of them
}
    
rule dffbeeafbebfeeeceefeeacafc_dll {
strings:
        $s1 = "cross device link"
        $s2 = "english-caribbean"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "`vector destructor iterator'"
        $s5 = "executable format error"
        $s6 = "directory not empty"
        $s7 = "result out of range"
        $s8 = "operation canceled"
        $s9 = "ProductName"
        $s10 = "LC_MONETARY"
        $s11 = "VarFileInfo"
        $s12 = "english-jamaica"
        $s13 = "`local vftable'"
        $s14 = "FileDescription"
        $s15 = "spanish-venezuela"
        $s16 = "chinese-singapore"
        $s17 = "SetFilePointerEx"
        $s18 = "TerminateProcess"
        $s19 = "GetModuleHandleW"
        $s20 = "destination address required"
condition:
    uint16(0) == 0x5a4d and filesize < 192KB and
    4 of them
}
    