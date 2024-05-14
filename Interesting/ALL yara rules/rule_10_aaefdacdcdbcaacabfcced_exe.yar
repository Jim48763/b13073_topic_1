rule aaefdacdcdbcaacabfcced_exe {
strings:
        $s1 = "White Office Logo"
        $s2 = "QpTAU^T_SwS}TTV3Y"
        $s3 = "TU PC FUE INFECTADA!!"
        $s4 = "24GM`fnqjkd`d^d^``fk{"
        $s5 = "11ABOOZY__``____`___ZZQQFF;;00\"\""
        $s6 = "{{oooovv|{xxhhPP<<55<<EEDD33"
        $s7 = "||utiiZZII:9..((''(())(($$"
        $s8 = "**56??FFJIIIEE==23''"
        $s9 = ",+66=>@A@@<<55..'' "
        $s10 = "$41904400-BE18-11D3-A28B-00104BD35090"
        $s11 = "  ''00;;DDJKMMMMJIDD==55++"
        $s12 = "65BAAAFGJKCD*+"
        $s13 = "*)54<<AAAB;;21,,&&"
        $s14 = "WordScreamerWindow"
        $s15 = "STAThreadAttribute"
        $s16 = "Q(8(c1M1?***4\"!\""
        $s17 = "&&66DDOOVW\\\\aaggoowx"
        $s18 = "Q9W4X0n+SEa"
        $s19 = "A%8=;U2w*W&"
        $s20 = "O|D?H%K!QC["
condition:
    uint16(0) == 0x5a4d and filesize < 8313KB and
    4 of them
}
    
