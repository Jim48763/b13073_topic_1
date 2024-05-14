rule cbedceabecefcacbefddebc_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "/HS]<~h_>v#"
        $s5 = "|~lIJj0\"[2"
        $s6 = "d[ KS4l*)zL"
        $s7 = "Y;Ct~\"I*Vq"
        $s8 = "]2g.NrUuOnP"
        $s9 = "J`pl%N~V*-s"
        $s10 = "m:b5YC-9KXr"
        $s11 = "_tgukIe!2OF"
        $s12 = "(Frz_n2>#a7"
        $s13 = "-uCsYD=H%0N"
        $s14 = "n]P9:XG2~;r"
        $s15 = "}`50TSfI[Us"
        $s16 = "jEW=e-wM\"'"
        $s17 = "7U2KS\"-6 H"
        $s18 = "!l<~GVM/QXC"
        $s19 = "$[:^MhRbTO-"
        $s20 = "zF4gAi96f_J"
condition:
    uint16(0) == 0x5a4d and filesize < 3964KB and
    4 of them
}
    
