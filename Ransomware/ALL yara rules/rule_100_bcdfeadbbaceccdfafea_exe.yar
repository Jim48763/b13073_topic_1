rule bcdfeadbbaceccdfafea_exe {
strings:
        $s1 = "ExitProcess"
        $s2 = "KERNEL32.dll"
        $s3 = "!OiPKgw"
        $s4 = "NjMG|P^"
        $s5 = "La6DTBl"
        $s6 = "0`.data"
        $s7 = "]d2)|="
        $s8 = ".idata"
        $s9 = "Qd?R}d"
        $s10 = "m,5'R"
        $s11 = "4~^>5"
        $s12 = "38Esk"
        $s13 = "?WHpx"
        $s14 = "D!7T*"
        $s15 = "N.As9"
        $s16 = "8a:Dy"
        $s17 = ".text"
condition:
    uint16(0) == 0x5a4d and filesize < 9KB and
    4 of them
}
    
