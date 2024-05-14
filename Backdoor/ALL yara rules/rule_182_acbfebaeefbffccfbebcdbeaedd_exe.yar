rule acbfebaeefbffccfbebcdbeaedd_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExA"
        $s5 = "Xos?v=E6\"5"
        $s6 = "ce8rG^dZDn>"
        $s7 = "(2GIF+c}rfL"
        $s8 = "!\"roWp;&{'"
        $s9 = "8Ttp\")BA+e"
        $s10 = "8'7lUi^5Z#."
        $s11 = "u9dHy\"U[Db"
        $s12 = "H}O,VnI?_zh"
        $s13 = "o|%N(1@yie8"
        $s14 = "u<C4KX;f&rV"
        $s15 = "?ihE1FLg(R$"
        $s16 = ".<,'JRqEWD}"
        $s17 = "Pq.C3YBsM+F"
        $s18 = "k:H.ip$>[DY"
        $s19 = "1?LiX-l\"Du"
        $s20 = ".\"6^Lsc+mU"
condition:
    uint16(0) == 0x5a4d and filesize < 7081KB and
    4 of them
}
    
