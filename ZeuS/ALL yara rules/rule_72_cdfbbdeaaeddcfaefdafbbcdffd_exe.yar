rule cdfbbdeaaeddcfaefdafbbcdffd_exe {
strings:
        $s1 = "GA\\FOBukm\\xufjg"
        $s2 = ".\" \"<$7$A'\\$W$]\"a'i/"
        $s3 = "Rodpnav#qj$goo"
        $s4 = "=<B?k=u3r=~9y6"
        $s5 = "@BT'FJGOA$kkkt"
        $s6 = "MtPos10Tukgatt"
        $s7 = "RegSetValueExW"
        $s8 = "Cbp]lahl[k`dls"
        $s9 = "%~khlwh(dhicoe"
        $s10 = "j#kh`jjvnwpbir"
        $s11 = "AAA-^ULFBFAA96/*CAEB&"
        $s12 = "%vbuvctz*:aobibocu"
        $s13 = "dgiignsmmi,<tfvtkv"
        $s14 = "k{iltvtx2vxetc{ak|"
        $s15 = "Ghjpajs)Laiipl>)#a"
        $s16 = "RI#XCgLr[wV"
        $s17 = "Vz\"ame#,6G"
        $s18 = "ZHLGW'|pc`b"
        $s19 = "T`bj{f|6-+V"
        $s20 = "&Bpjr{G(KLm"
condition:
    uint16(0) == 0x5a4d and filesize < 1565KB and
    4 of them
}
    