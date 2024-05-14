rule bacffcbebbfffcedbefbabbefedbf_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "J@f(\"bGpm4?\\"
        $s5 = "RegSetValueExA"
        $s6 = "-UQWhuwk8dK"
        $s7 = "Kz8R?.=<QYr"
        $s8 = "VdY#Iro)>};"
        $s9 = ".iIFM|?$3+X"
        $s10 = "1@nr8QV(*j,"
        $s11 = "1?LiX-l\"Du"
        $s12 = "_*oXq]3Ivz;"
        $s13 = "MZyoWv%n{b~"
        $s14 = "!t|_B%^v*pX"
        $s15 = "*X]+R8v5640"
        $s16 = "Rq}9{G[84dK"
        $s17 = "qV$0C42ZX&j"
        $s18 = "z(R|j8`#AtT"
        $s19 = "VarFileInfo"
        $s20 = "dm>~*o3&[Nv"
condition:
    uint16(0) == 0x5a4d and filesize < 6537KB and
    4 of them
}
    
