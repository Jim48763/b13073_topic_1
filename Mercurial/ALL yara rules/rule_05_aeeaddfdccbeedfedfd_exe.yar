rule aeeaddfdccbeedfedfd_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = ":$:,:4:<:D:L:T:\\:d:l:t:|: ;$;4;8;@;X;h;l;|;"
        $s3 = "$RENAMEDLG:IDCANCEL"
        $s4 = "q24\"hBK9.O"
        $s5 = "W=|Xtgk9sjc"
        $s6 = ",ns^gaci/+U"
        $s7 = "I9w\"@!M8'y"
        $s8 = "[HpUD3#W`Xg"
        $s9 = "d$N8m;{`W2a"
        $s10 = ".Kd2og'|eb>"
        $s11 = "FjT ^}P-Icf"
        $s12 = "9itgy)*v2ua"
        $s13 = "H$j\"e,+E=&"
        $s14 = "Nz-^l_?v9w7"
        $s15 = "#rAzpNBi\"h"
        $s16 = "R\"X;YW+dcs"
        $s17 = "w+(a{Y|lq[$"
        $s18 = "]fhvFTD24PV"
        $s19 = "IRN?Lgo1EFi"
        $s20 = "tF\"'ZE2vXU"
condition:
    uint16(0) == 0x5a4d and filesize < 8199KB and
    4 of them
}
    
