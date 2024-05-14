rule efedecceaebaabdcfdaacedbf_exe {
strings:
        $s1 = "6U,GK4\"Y/R"
        $s2 = "eTGvs8B`6Kf"
        $s3 = "3&7qmaI|FYp"
        $s4 = "Pv?d5F-|KeS"
        $s5 = "i$|CPGumlYy"
        $s6 = "vG.:Oxpg[)"
        $s7 = "xnOF~QJu]T"
        $s8 = "/`}wvJ%Mz?"
        $s9 = "@SCYIhLG8'"
        $s10 = "GU<LI?SBCCm"
        $s11 = "Administrator"
        $s12 = "5^<'^c\"`K"
        $s13 = "Cyy07G$-%_"
        $s14 = " 765-2068)"
        $s15 = "5c-W .? mO"
        $s16 = "DocOptions"
        $s17 = "A[~F-8j*\\"
        $s18 = "BIN0001.OLE"
        $s19 = "Root Entry"
        $s20 = "\"[#m:s\"W"
condition:
    uint16(0) == 0x5a4d and filesize < 575KB and
    4 of them
}
    
