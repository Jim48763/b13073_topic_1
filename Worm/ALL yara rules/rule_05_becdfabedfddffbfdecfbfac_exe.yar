rule becdfabedfddffbfdecfbfac_exe {
strings:
        $s1 = " ]@S7=H\"U\"J QJH"
        $s2 = "\\RY=&ER$;ENj$eYu"
        $s3 = "?WRR1_W(5c(8a,&&c"
        $s4 = "FVN82\":,aNWPN"
        $s5 = "74THEREFENW{dY"
        $s6 = "\"yyrwy{TDC3&'"
        $s7 = "v><?8+(l='&"
        $s8 = "2a!06c H+p>"
        $s9 = "i{D}JZF_N>G"
        $s10 = "Gaoiqfe~xDU"
        $s11 = "cMhA|Ydg}+Q"
        $s12 = ">`zr/ya8U@|"
        $s13 = "te 6+$\"{>?"
        $s14 = "kxVvHMT_L.U"
        $s15 = "?|U[{D]=&.9"
        $s16 = "hjnXsdrGcmE"
        $s17 = "czAMICG!iya"
        $s18 = "I\"h/kEyobt"
        $s19 = "0V9@-~'d+k#"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 225KB and
    4 of them
}
    
