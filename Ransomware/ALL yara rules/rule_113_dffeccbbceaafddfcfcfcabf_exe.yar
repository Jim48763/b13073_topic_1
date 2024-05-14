rule dffeccbbceaafddfcfcfcabf_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "].GYjtIL;L4"
        $s3 = "KERNEL32.dll"
        $s4 = "VirtualQuery"
        $s5 = "GetProcAddress"
        $s6 = "VirtualAlloc"
        $s7 = "1UYK}R\\jf"
        $s8 = "LoadLibraryA"
        $s9 = "Br639`_ba"
        $s10 = "02181=1K1Q1W1_1i1o1"
        $s11 = "5`pcFPi4"
        $s12 = "lstrcmpA"
        $s13 = "{WK*n#vA"
        $s14 = "Mr\"JTf}"
        $s15 = "RPgG0!\""
        $s16 = "eAxEv /w"
        $s17 = "*h;}&z5["
        $s18 = "2'262E2L2z2"
        $s19 = "i#NORRM6"
        $s20 = ">lf\\y&)"
condition:
    uint16(0) == 0x5a4d and filesize < 63KB and
    4 of them
}
    
