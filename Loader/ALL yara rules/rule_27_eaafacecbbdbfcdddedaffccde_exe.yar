rule eaafacecbbdbfcdddedaffccde_exe {
strings:
        $s1 = "Calc Theory"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "PN.eZKB:i#~"
        $s5 = "FileDescription"
        $s6 = "__vbaStrCopy"
        $s7 = "__vbaLenBstr"
        $s8 = "arbejdsvgring"
        $s9 = "__vbaLateIdCallLd"
        $s10 = "HYPOKEIMENOMETRY"
        $s11 = "_adj_fdivr_m32"
        $s12 = "OUTWHIRLED"
        $s13 = "ABJOINT.exe"
        $s14 = "infructuose"
        $s15 = "Functionated"
        $s16 = "__vbaVarTstLt"
        $s17 = "OriginalFilename"
        $s18 = "Nonterritorial5"
        $s19 = "kloakarbejderes"
        $s20 = "Laurbrkranses7"
condition:
    uint16(0) == 0x5a4d and filesize < 73KB and
    4 of them
}
    
