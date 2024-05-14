rule adaceedefeeaaebcadfbfcbfcb_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "KERNEL32.dll"
        $s3 = "VirtualQuery"
        $s4 = "GetProcAddress"
        $s5 = "VirtualAlloc"
        $s6 = "LoadLibraryA"
        $s7 = "y/I5& 'Zj"
        $s8 = "9yParGw<)"
        $s9 = "02181=1K1Q1W1_1i1o1"
        $s10 = "<OHr\\4Gn"
        $s11 = "bS9Ej#kFF"
        $s12 = "|p=\"aZ/"
        $s13 = "lstrcmpA"
        $s14 = ">8XMN!sr"
        $s15 = "L*Y]X@~d"
        $s16 = "f\"k!/i:"
        $s17 = "$xro_^l3"
        $s18 = "-N6%aK/;"
        $s19 = " .nUo#aP"
        $s20 = "2'262E2L2z2"
condition:
    uint16(0) == 0x5a4d and filesize < 63KB and
    4 of them
}
    
