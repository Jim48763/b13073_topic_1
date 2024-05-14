rule bfcafcbfcecfadccdab_exe {
strings:
        $s1 = "Capsulized7"
        $s2 = "ProductName"
        $s3 = "c&D(3T+5I;E"
        $s4 = "VarFileInfo"
        $s5 = "FileDescription"
        $s6 = "Leucopyrite7"
        $s7 = "Proceedings8"
        $s8 = "Pozostalych2"
        $s9 = "Prevailment8"
        $s10 = "Eastliberty2"
        $s11 = "Dihexagonal2"
        $s12 = "Mensuralist0"
        $s13 = "Stackencloud"
        $s14 = "Anisometrope8"
        $s15 = "Reticularian7"
        $s16 = "MethCallEngine"
        $s17 = "SizeofResource"
        $s18 = "5]t%)gFJ\""
        $s19 = "+.&g-fR3oG"
        $s20 = "EUPzwDI?`F"
condition:
    uint16(0) == 0x5a4d and filesize < 517KB and
    4 of them
}
    
