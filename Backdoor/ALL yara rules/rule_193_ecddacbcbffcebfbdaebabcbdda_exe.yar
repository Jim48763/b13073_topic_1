rule ecddacbcbffcebfbdaebabcbdda_exe {
strings:
        $s1 = "E82200000068A44E0EEC50E84300000083C408FF742404FFD0FF74240850E83000000083C408C3565531C0648B70308B760C8B761C8B6E088B7E208B3638471875F3803F6B7407803F4B7402EB"
        $s2 = ",wdQSsUQ?QrRM/"
        $s3 = ",|R[C/-LKM)"
        $s4 = "7Z4|Q<H'G62"
        $s5 = "T`Y\"p6Z)&C"
        $s6 = "^<(4d]LS=s'"
        $s7 = "1H5G$)74pw&"
        $s8 = "K%ST/NI G3Y"
        $s9 = "yc Q+[={*_<"
        $s10 = "LOs2#3H:b!7"
        $s11 = "}rS1WO'_4P2"
        $s12 = "R$iS8C?}%EM"
        $s13 = "zI$<dnk'l1r"
        $s14 = "_$(,g3~QULW"
        $s15 = "UB6!50L?\"4"
        $s16 = "m{TRzY:QU#4"
        $s17 = "S$L6.oPGFA&"
        $s18 = "p_s,P<LrEY;"
        $s19 = "G*R)X/I+F(L"
        $s20 = "\"@>|=P6A[a"
condition:
    uint16(0) == 0x5a4d and filesize < 177KB and
    4 of them
}
    
