rule affcbcebbabedfedaacbcbbabe_com {
strings:
        $s1 = "        [TeMpEsT -94]"
        $s2 = "!? ?\""
condition:
    uint16(0) == 0x5a4d and filesize < 6KB and
    8 of them
}
    
