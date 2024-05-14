rule ebefeaccbabfadcbbebbeee_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "D(GV2~0VV4C-o]"
        $s3 = "^\"oA+Q0i\\(qD"
        $s4 = "U0C_/@&oR4T"
        $s5 = "|6U*DV5[0oC"
        $s6 = "E_@2B-c^60D"
        $s7 = "7eP3B!.V>UD"
        $s8 = "Q#ew)G*]3Fk"
        $s9 = "3Fc0a]\"Q6d"
        $s10 = "B-nGfc'rV#^"
        $s11 = "v>Y0WZ(T+w@"
        $s12 = "B+pV4D=A3f1"
        $s13 = "Go7tA%]4i3F"
        $s14 = "d3F0DKV4^!l"
        $s15 = "0DGV2}+dF*U"
        $s16 = "nG#B4rZ5Udx"
        $s17 = "EGV2f!r@/_*"
        $s18 = "Q)e`2B-nTFx"
        $s19 = "3Fw!t`?C0e^"
        $s20 = "D%tF50DC\\(D6o_"
condition:
    uint16(0) == 0x5a4d and filesize < 157KB and
    4 of them
}
    
