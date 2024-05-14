rule caccbbbbbcefbdacddebedcaadf_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "Directory not empty"
        $s3 = "unittest._log)"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "No child processes"
        $s6 = "4d\"?%(O5jP"
        $s7 = "MCfFx'LKXi5"
        $s8 = "2ao?(xvDt7g"
        $s9 = "f>D]dPJo.N!"
        $s10 = "V]0qCxSTbur"
        $s11 = "W67VSvyh^~1"
        $s12 = "{IBj-?Z'crk"
        $s13 = "lvf%PJwd;r("
        $s14 = "MEZ679_)-tH"
        $s15 = "*VO;^E<}Zfq"
        $s16 = "AyvYU_1&E[u"
        $s17 = "Hf8\"x=-rp<"
        $s18 = "F#bgn?MwN|%"
        $s19 = "hMdsl(Rp~&t"
        $s20 = "eM>4,2O}(#n"
condition:
    uint16(0) == 0x5a4d and filesize < 7098KB and
    4 of them
}
    
