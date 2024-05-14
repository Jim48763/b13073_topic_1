rule ebeaeadaaecbdebaaeeacbff_exe {
strings:
        $s1 = "Indtgtskildernes6"
        $s2 = "quicksilvering"
        $s3 = "Variantfunktioner5"
        $s4 = "DgE@MOF3/`8"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "Ortopdiske3"
        $s8 = "Salgsfremmende7"
        $s9 = "Tilforladeligt7"
        $s10 = "Klimaforandringer"
        $s11 = "PANTEBREVSHANDELS"
        $s12 = "Archoplasma8"
        $s13 = "Omvurderings"
        $s14 = "W'5lU`$lV.(y"
        $s15 = "SUBEPIDERMAL"
        $s16 = "SOCIALGRUPPES"
        $s17 = "!!xD.iL3\\KrT"
        $s18 = "Kogepunktets3"
        $s19 = "Zinkkografiet"
        $s20 = "__vbaVarTstNe"
condition:
    uint16(0) == 0x5a4d and filesize < 285KB and
    4 of them
}
    
