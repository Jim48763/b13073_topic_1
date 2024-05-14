rule cfaacfcddddcbddeeffdefaeeaccddfd_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExW"
        $s5 = "Q\"9k7Ns}OZ"
        $s6 = "=~_@x|VG64N"
        $s7 = "_qh>85\")}["
        $s8 = "LyfT95(7S:i"
        $s9 = "El L8QOeXj~"
        $s10 = "L1}fkQcTD6j"
        $s11 = "WxHa/o7~Pr>"
        $s12 = "7nvB:)F*qG8"
        $s13 = "#A|'vJ\"e-g"
        $s14 = "%Do^:bv&KNx"
        $s15 = "6c)`%5<E!hP"
        $s16 = ")|X[`jW*/#U"
        $s17 = "@.b6k[$\"Ez"
        $s18 = "3E}Ni*kV[&u"
        $s19 = "V H'PBI4Nwr"
        $s20 = "30=Ll;>8kWG"
condition:
    uint16(0) == 0x5a4d and filesize < 10244KB and
    4 of them
}
    
