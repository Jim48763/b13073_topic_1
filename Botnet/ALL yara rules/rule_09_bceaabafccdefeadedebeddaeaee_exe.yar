rule bceaabafccdefeadedebeddaeaee_exe {
strings:
        $s1 = "L$cNu7+1XiE"
        $s2 = "%{d,Ky AI`-"
        $s3 = "J-2LZ|8~0K:"
        $s4 = "5'$E2&e/fgT"
        $s5 = "ikVj1ED*#w0"
        $s6 = "+0.uFO9*&J}"
        $s7 = "o_2h}+T4rED"
        $s8 = "I8so|wniFf'"
        $s9 = "J$uRcHwqX3D"
        $s10 = "hAeIs u?R{@"
        $s11 = "k@c iq9x}?)"
        $s12 = "Zhs`$z&\"K@"
        $s13 = "X-MnWo|gA0l"
        $s14 = "[USER32.8dl"
        $s15 = "w&* K`o7NP="
        $s16 = "oIokpcQ}\"<M"
        $s17 = "80^OoIXL&\\k"
        $s18 = "\\ZeL9vYz?4J"
        $s19 = "aX]!L:^4K2^W"
        $s20 = "xg\"ec=zgX~L"
condition:
    uint16(0) == 0x5a4d and filesize < 4648KB and
    4 of them
}
    
