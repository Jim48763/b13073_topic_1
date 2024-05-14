rule cbafcfcacdaefeffbaeedbfb_exe {
strings:
        $s1 = "S4j:cAe<N6T"
        $s2 = "ProductName"
        $s3 = "sX&|ad$0%m("
        $s4 = "VarFileInfo"
        $s5 = "Dmy\"Rl+%NO"
        $s6 = "\"_`Na(/FS~"
        $s7 = "FileDescription"
        $s8 = "Microsoft Corp."
        $s9 = "snMy&,kBy/a?"
        $s10 = "ion I7farmaG"
        $s11 = "|1Q\"4CdBP`d"
        $s12 = "%,13LMNdddeheehgekgeeeheddddNMH31/%"
        $s13 = "LegalTrademarks"
        $s14 = "fTHJ4OeLVt"
        $s15 = "+QUJ5oz,^m"
        $s16 = "Shb<%+npT,"
        $s17 = "+F:^dz`/W_"
        $s18 = "#|K'YnP7ZV"
        $s19 = "Hkwd87@u.,"
        $s20 = "We 't(@79?"
condition:
    uint16(0) == 0x5a4d and filesize < 943KB and
    4 of them
}
    
