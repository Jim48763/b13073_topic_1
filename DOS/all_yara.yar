import pe
rule dcfeccaaeeeedefbebaefcaae_com {
strings:
        $s1 = " /\\/\\/    "
        $s2 = "!< u#"
condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    all of them
}
    
rule bcefabfcddeeafedecf_com {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    all of them
}
    
rule cbbbecafdcfeeeacfcbdbdbdcedfa_com {
strings:
        $s1 = " Have a nice day,"
        $s2 = "$Goodbye."
        $s3 = "t\"< t"
condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    4 of them
}
    
rule bdbbeecfefccbbeddcebafaefd_com {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    all of them
}
    
rule bcacbcefffbbbaabedfbdbd_com {
strings:
        $s1 = "!Turbo Kukac 9.9      $"
condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    all of them
}
    
rule bfdebbacebdecbdafcfafa_com {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    all of them
}
    
rule bcddffadeabfbbccaffafccbd_com {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    all of them
}
    
rule affcbcebbabedfedaacbcbbabe_com {
strings:
        $s1 = "        [TeMpEsT -94]"
        $s2 = "!? ?\""
condition:
    uint16(0) == 0x5a4d and filesize < 6KB and
    8 of them
}
    
rule dcbcdafaebeebeaeefaadfffbeda_com {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    all of them
}
    