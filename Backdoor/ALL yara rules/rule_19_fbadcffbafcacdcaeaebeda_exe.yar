rule fbadcffbafcacdcaeaebeda_exe {
strings:
        $s1 = "<-mil1_eofq"
        $s2 = "Gns*fMm`bkw"
        $s3 = "\\App 0chRme.exe"
        $s4 = "SOFTWARE\\Mp"
        $s5 = "w H\\:CZju@J"
        $s6 = "OLEAUT32.dll"
        $s7 = "Z/x\"qW#e/0."
        $s8 = "CryptUnprotectData"
        $s9 = "InitCommonControlsEx"
        $s10 = "VirtualProtect"
        $s11 = "@&H'P)X*#G"
        $s12 = "6LH3IvFhxA"
        $s13 = "a\"N{t=PC2"
        $s14 = "xTbAjh=#/<"
        $s15 = "fPWoQkxbun"
        $s16 = "0p%x:<CLB/"
        $s17 = "Ht?3a/P+`f"
        $s18 = "@%HB$~IJue"
        $s19 = "+\"GuatFeW"
        $s20 = "[NDzS5_=cf"
condition:
    uint16(0) == 0x5a4d and filesize < 360KB and
    4 of them
}
    
