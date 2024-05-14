rule abcaafecffddcecfaaeafdfeed_exe {
strings:
        $s1 = "XozyxwGXX9^VP+"
        $s2 = "Cg4Kf0yffnqxGM"
        $s3 = "hblNvptzAUK"
        $s4 = "7t}#-+0.$(v"
        $s5 = "EJfZO8lvtb@"
        $s6 = "Y/>ZluwI9n&"
        $s7 = "\"(YUSRxlW/"
        $s8 = "/wU)%#G s+4"
        $s9 = "YiVHRqCjE(4"
        $s10 = "<C@]jOB\"&s"
        $s11 = "rqKzRhadEbo"
        $s12 = "-$X4Ek9@qMF"
        $s13 = "2zplZuNHPjq"
        $s14 = "MTkYWB/R1p4"
        $s15 = "1XEqWxRA4Bv"
        $s16 = "&/[|)P!?Ua0"
        $s17 = "VrP$u5fOIqC"
        $s18 = "s~wjb4E0mPx"
        $s19 = "`wrCO+dNv8B"
        $s20 = "&HsBXwKfVv9"
condition:
    uint16(0) == 0x5a4d and filesize < 1235KB and
    4 of them
}
    
