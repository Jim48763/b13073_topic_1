rule ecfcbbefbbfebfdaebfdeeba_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "cross device link"
        $s4 = "english-caribbean"
        $s5 = "SetDefaultDllDirectories"
        $s6 = "GetSystemPowerStatus"
        $s7 = "executable format error"
        $s8 = "result out of range"
        $s9 = "directory not empty"
        $s10 = "invalid string position"
        $s11 = "operation canceled"
        $s12 = "[O)U1XDx(bF"
        $s13 = "mdWo.}^Z!]~"
        $s14 = "VarFileInfo"
        $s15 = "LC_MONETARY"
        $s16 = "^`.KD#zaTHC"
        $s17 = "english-jamaica"
        $s18 = "`local vftable'"
        $s19 = "spanish-venezuela"
        $s20 = "GetModuleHandleA"
condition:
    uint16(0) == 0x5a4d and filesize < 785KB and
    4 of them
}
    
