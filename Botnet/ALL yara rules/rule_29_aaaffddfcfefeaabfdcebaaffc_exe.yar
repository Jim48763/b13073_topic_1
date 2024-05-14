rule aaaffddfcfefeaabfdcebaaffc_exe {
strings:
        $s1 = "em.Collvttions.Gv"
        $s2 = "%s\\Mozilla\\Profiles"
        $s3 = "exusFile\\ftpsite.ini"
        $s4 = "Google360Browser\\Browser"
        $s5 = "ser Data\\Default\\Web"
        $s6 = "j%Xjs[j\\Zj._jpYju^jrf"
        $s7 = "Plugins\\FTP\\Hosts"
        $s8 = "ZwResumeThread"
        $s9 = "RuntimeHelpers"
        $s10 = "awrfsux.Proper"
        $s11 = "Google\\Chrommodo\\Dragon"
        $s12 = "STAThreadAttribute"
        $s13 = "dwCopyW}ags"
        $s14 = "@CEGHJNPSTW"
        $s15 = "Titan Browe"
        $s16 = "_CorExeMain"
        $s17 = "iEupkzVawco"
        $s18 = "Syste~?Linq"
        $s19 = "_ams <NEe?T"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 293KB and
    4 of them
}
    
