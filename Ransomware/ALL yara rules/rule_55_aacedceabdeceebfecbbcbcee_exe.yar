rule aacedceabdeceebfecbbcbcee_exe {
strings:
        $s1 = "N_$,3~@'w\""
        $s2 = "S0@}?*\"hO$"
        $s3 = "_0E&+S{<n6U"
        $s4 = ">6-Vr#}0p.,"
        $s5 = "O(I*<6?wP:A"
        $s6 = "l[AtVE?,+7x"
        $s7 = "!-Fy=D[EK9'"
        $s8 = "]n>&!rkO32 "
        $s9 = "!$x\"C)vLw{"
        $s10 = "~WHLx'+pFY."
        $s11 = "~8@>AQ1,$fD"
        $s12 = "z/NGi)\"aTy"
        $s13 = "GetModuleHandleA"
        $s14 = "pS|vx\"Q|(Pg"
        $s15 = "G&_2LN8^oHoQ"
        $s16 = "2+FJDw>F3YsK"
        $s17 = "6bhAS1,$A[Hc"
        $s18 = "AO(!-r\\:2Gg"
        $s19 = "jC5ran@jSZ}p"
        $s20 = "z#cW`.wW:KO2"
condition:
    uint16(0) == 0x5a4d and filesize < 5811KB and
    4 of them
}
    
