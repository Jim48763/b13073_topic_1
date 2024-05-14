rule efcdaabefafcbfcdacbabbf_exe {
strings:
        $s1 = "Gns*fMm`bkw"
        $s2 = "<-mil1_eofq"
        $s3 = "\\App 0chRme.exe"
        $s4 = "Z/x\"qW#e/0."
        $s5 = "SOFTWARE\\Mp"
        $s6 = "OLEAUT32.dll"
        $s7 = "w H\\:CZju@J"
        $s8 = "CryptUnprotectData"
        $s9 = "InitCommonControlsEx"
        $s10 = "    </security>"
        $s11 = "VirtualProtect"
        $s12 = "0p%x:<CLB/"
        $s13 = "[NDzS5_=cf"
        $s14 = "fPWoQkxbun"
        $s15 = "xTbAjh=#/<"
        $s16 = "@%HB$~IJue"
        $s17 = "@&H'P)X*#G"
        $s18 = "Ht?3a/P+`f"
        $s19 = "oP+OLjWeuQ"
        $s20 = "O]i<?xml T"
condition:
    uint16(0) == 0x5a4d and filesize < 360KB and
    4 of them
}
    
