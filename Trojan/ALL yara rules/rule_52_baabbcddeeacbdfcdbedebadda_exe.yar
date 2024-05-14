rule baabbcddeeacbdfcdbedebadda_exe {
strings:
        $s1 = "j0T3hGHp\"J"
        $s2 = "ChromeXMp2n"
        $s3 = "Softw`He\\LM"
        $s4 = "fgaZy7V=Xo"
        $s5 = "K32JBG0<8t"
        $s6 = "8\"($@\"0/"
        $s7 = "#WaSenX A"
        $s8 = "Qu YyHV8h"
        $s9 = "y$yf})}gg."
        $s10 = "7yCkLxsT"
        $s11 = "D?lCu:7/"
        $s12 = "P>wv?dey"
        $s13 = "2345789:"
        $s14 = "HpfsEgn+"
        $s15 = "M2oHqmf/"
        $s16 = "OFw6S;be"
        $s17 = "6sA9weL["
        $s18 = "$%()*+01"
        $s19 = "2 mruCXL"
        $s20 = "B5q3k8vU"
condition:
    uint16(0) == 0x5a4d and filesize < 97KB and
    4 of them
}
    
