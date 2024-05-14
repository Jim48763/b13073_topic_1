rule fcaeecbffdaabaeebdaeaebf_exe {
strings:
        $s1 = "H)s8lf[kP`z"
        $s2 = "u=]UG0/E3p"
        $s3 = "w<(||PI=1#6"
        $s4 = "7?2UGpO76Q"
        $s5 = "rDU0'AD0}>H"
        $s6 = "4$n&t).(4*n("
        $s7 = "9Lj\"\\#/|"
        $s8 = "cL)M^O)M^O)!~L)"
        $s9 = "(D*c\"?nM"
        $s10 = ">&WpO:',F"
        $s11 = "=gD-%vMu7"
        $s12 = "PADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADD"
        $s13 = "nL)AnL)mnL)?nL)!nL)%~L)"
        $s14 = "?5UG0O766"
        $s15 = "ak_}'8ey'"
        $s16 = "(TE(-4/Wh"
        $s17 = "D/r\"p;p["
        $s18 = "DtnB|#%\\"
        $s19 = "\\DH7{@O!"
        $s20 = "CgXS%kr4k"
condition:
    uint16(0) == 0x5a4d and filesize < 225KB and
    4 of them
}
    
