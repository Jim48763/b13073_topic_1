rule effdaccfcbabbbcbacbeacd_exe {
strings:
        $s1 = "B|)b`pWUzw"
        $s2 = "nE~4a:pftb"
        $s3 = "ExitProcess"
        $s4 = "KERNEL32.dll"
        $s5 = "o?CSd=[y[W"
        $s6 = "SetErrorMode"
        $s7 = "Z78&75+Co"
        $s8 = "Vi`c66E\\"
        $s9 = "ozhylPZU"
        $s10 = "yJ\"3,wU"
        $s11 = ")/an7< r"
        $s12 = "2mT]*yRM"
        $s13 = "RBlE#o1Q"
        $s14 = ".NoTLVPN"
        $s15 = "r~<\\ @Y"
        $s16 = "Nd:'HM)"
        $s17 = "7%vU^ZY"
        $s18 = "\";P%Ym"
        $s19 = "Qi+<]:8"
        $s20 = "-#lY+Ck"
condition:
    uint16(0) == 0x5a4d and filesize < 70KB and
    4 of them
}
    
