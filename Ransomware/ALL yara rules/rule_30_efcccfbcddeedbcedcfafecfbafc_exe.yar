rule efcccfbcddeedbcedcfafecfbafc_exe {
strings:
        $s1 = "$,5=FNV_grz"
        $s2 = "&-5=EOW_fnv"
        $s3 = "%.6>FOW_gox"
        $s4 = "'/7?GOW^fnx"
        $s5 = "'/:BJS[cks{"
        $s6 = "(2:BIQYaipx"
        $s7 = "'2:CKS[clt|"
        $s8 = "(08AIQYbjr{"
        $s9 = "%.7@IRZckt}"
        $s10 = "&.6?GOW`hpx"
        $s11 = "#,5>GPYbjs|"
        $s12 = "(07@GOW`how"
        $s13 = "#+4<EMV^irz"
        $s14 = "29AIQX`gov~"
        $s15 = "%.6?GOX`ir{"
        $s16 = "!*3;DOW`js|"
        $s17 = "!)2;DMU^gpy"
        $s18 = "!)08@GOW_fn"
        $s19 = "$-6>GPYajs{"
        $s20 = "$,5=FNW`hqy"
condition:
    uint16(0) == 0x5a4d and filesize < 546KB and
    4 of them
}
    
