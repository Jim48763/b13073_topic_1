rule ceedabafebbcfdccfbfabeeacce_exe {
strings:
        $s1 = "InitCommonControlsEx."
        $s2 = "Kampel 1151)0'"
        $s3 = "ES[each sid"
        $s4 = "#Hotkeys%?_"
        $s5 = ",. Invalid;"
        $s6 = "ProductName"
        $s7 = "`/}iewport%"
        $s8 = "VarFileInfo"
        $s9 = "ght)c jfplu"
        $s10 = "FileDescription"
        $s11 = "n C=%6.2f and A"
        $s12 = "=SafeArrayPtrOf!e"
        $s13 = "Initial Guesses:"
        $s14 = "IE(AL(\"%s\",4),\""
        $s15 = "kd8GABuffer'"
        $s16 = "sbHorizontal"
        $s17 = "THTMLPicture"
        $s18 = "yIn7ase of0s"
        $s19 = "90$ NDropdr`"
        $s20 = "butesAExitCo"
condition:
    uint16(0) == 0x5a4d and filesize < 623KB and
    4 of them
}
    
