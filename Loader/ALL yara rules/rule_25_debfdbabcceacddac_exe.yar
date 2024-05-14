rule debfdbabcceacddac_exe {
strings:
        $s1 = "Flertalsbeslutningernes4"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "Aftgtsydelserne8"
        $s5 = "__vbaStrCopy"
        $s6 = "counterblows"
        $s7 = "__vbaLenBstr"
        $s8 = "__vbaFileOpen"
        $s9 = "__vbaLateIdCallLd"
        $s10 = "Steroidprparats7"
        $s11 = "_adj_fdivr_m32"
        $s12 = "Mesopotamia5"
        $s13 = "Scoptically8"
        $s14 = "phlebotomise"
        $s15 = "__vbaVarTstLt"
        $s16 = "__vbaLateIdSt"
        $s17 = "Anticipatable"
        $s18 = "Sydvestenvind1"
        $s19 = "OriginalFilename"
        $s20 = "SUPERSESQUITERTIAL"
condition:
    uint16(0) == 0x5a4d and filesize < 97KB and
    4 of them
}
    
