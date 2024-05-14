rule faacebadfacbfdecfddbfeaafd_exe {
strings:
        $s1 = "hn\"(pI]5J8"
        $s2 = ".GM$gvG[E;^r"
        $s3 = "VirtualProtect"
        $s4 = "LgC7H|4!1O"
        $s5 = "i=w$KSlYv/"
        $s6 = "+m}kHS,1C0"
        $s7 = "I>\" 7+5zC"
        $s8 = "NpdV+U<*YO"
        $s9 = "/_mUM&ehQC"
        $s10 = "=u(8t3 OxA"
        $s11 = "mMX4]vA[tZ"
        $s12 = "dP:r|Uk~0["
        $s13 = "9T6;%/wvrP"
        $s14 = ":Bg[1i*8w4"
        $s15 = "/L?5^S4c#j"
        $s16 = "-8lihXsJuf"
        $s17 = "W=$v0oUqdn"
        $s18 = "J8snpnk1w9["
        $s19 = "ExitProcess"
        $s20 = "GetProcAddress"
condition:
    uint16(0) == 0x5a4d and filesize < 769KB and
    4 of them
}
    
