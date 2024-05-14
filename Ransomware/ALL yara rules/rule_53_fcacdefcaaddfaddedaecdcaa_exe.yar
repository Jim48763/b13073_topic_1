rule fcacdefcaaddfaddedaecdcaa_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "Certificate Policies"
        $s3 = "CryptReleaseContext"
        $s4 = "Runtime Error!"
        $s5 = "invalid string position"
        $s6 = "GetConsoleOutputCP"
        $s7 = "id-kp-timeStamping"
        $s8 = "N_$,3~@'w\""
        $s9 = "S0@}?*\"hO$"
        $s10 = "_0E&+S{<n6U"
        $s11 = ".hljs-code,"
        $s12 = "?456789:;<="
        $s13 = ">6-Vr#}0p.,"
        $s14 = "O(I*<6?wP:A"
        $s15 = "l[AtVE?,+7x"
        $s16 = "!-Fy=D[EK9'"
        $s17 = "]n>&!rkO32 "
        $s18 = "!$x\"C)vLw{"
        $s19 = "~WHLx'+pFY."
        $s20 = "Rjl68H%w 97"
condition:
    uint16(0) == 0x5a4d and filesize < 9544KB and
    4 of them
}
    
