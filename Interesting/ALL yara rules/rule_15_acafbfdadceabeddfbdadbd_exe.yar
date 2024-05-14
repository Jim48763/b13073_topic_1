rule acafbfdadceabeddfbdadbd_exe {
strings:
        $s1 = "dwKVj)^a*\""
        $s2 = "&XpisyGlA\""
        $s3 = "9;7fJ0joOFn"
        $s4 = "+6QYFja.'uv"
        $s5 = "b9skNa8@K*2"
        $s6 = "/jEMl;xz9vm"
        $s7 = "a9edw&q^|P8"
        $s8 = "+PH>32'\"g%"
        $s9 = "QZBSxL]oVc_"
        $s10 = "{e\".@9[,4+"
        $s11 = "\"~Ng_Zn#Wh"
        $s12 = "{b\"ilqgvc&"
        $s13 = "R8}^p8e7Q[sq"
        $s14 = "zutk*nn60{MH"
        $s15 = ":`[/^KBUc\\'"
        $s16 = "3,\"/\"^U$G4j"
        $s17 = "VirtualProtect"
        $s18 = "T`3u1)Dl@="
        $s19 = "~-s/!nDY v"
        $s20 = "+8LT{E!9b="
condition:
    uint16(0) == 0x5a4d and filesize < 2074KB and
    4 of them
}
    
