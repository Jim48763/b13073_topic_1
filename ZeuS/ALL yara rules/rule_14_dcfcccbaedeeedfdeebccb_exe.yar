rule dcfcccbaedeeedfdeebccb_exe {
strings:
        $s1 = "mbE\"c&ga$-"
        $s2 = "ProductName"
        $s3 = "E\"X<$=;#}5"
        $s4 = "&,'LCGJAN@/"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "PoC%Bpui!ix3"
        $s8 = "7#2+/@)60e/1"
        $s9 = "PrivateBuild"
        $s10 = "qlfuqfv`vFI[ZFB"
        $s11 = "VirtualProtect"
        $s12 = "LegalTrademarks"
        $s13 = "Build Date"
        $s14 = "?FATBYWXQ&"
        $s15 = "S`anw9HhAr"
        $s16 = "(bg)lN9WR0"
        $s17 = "P,qu;'di0v"
        $s18 = "C<DlSt6kBA"
        $s19 = "$9:?)/(&'1"
        $s20 = "9RkK8V\"eo"
condition:
    uint16(0) == 0x5a4d and filesize < 261KB and
    4 of them
}
    
