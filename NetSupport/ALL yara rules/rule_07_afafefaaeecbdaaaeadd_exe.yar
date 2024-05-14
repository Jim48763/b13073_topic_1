rule afafefaaeecbdaaaeadd_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "MT-C 894520"
        $s3 = "g3?7fcGD1h;"
        $s4 = "N>=y1BZ\"@O"
        $s5 = "Z_}uL1[tpSm"
        $s6 = "c>]Y%?DGBnU"
        $s7 = "Ok}Uob;1e&<"
        $s8 = ")$67yk?wnpF"
        $s9 = "!8h,jW0C2:)"
        $s10 = "FoldStringW"
        $s11 = "Yf<IR!si|:."
        $s12 = "R\"f&5,-@Ch"
        $s13 = "*796jt~[;le"
        $s14 = "i.8-xTtX$f@"
        $s15 = "`u#)\"XVq:f"
        $s16 = "|< 5T]@x^IG"
        $s17 = "lJR.\"aWvbe"
        $s18 = "BuF_\"URw#C"
        $s19 = "]/(1q8>a*#K"
        $s20 = "@TFscq[(P2;"
condition:
    uint16(0) == 0x5a4d and filesize < 3554KB and
    4 of them
}
    
