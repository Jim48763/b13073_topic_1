rule ebafebcefecbaafcdfc_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "Directory not empty"
        $s3 = "unittest._log)"
        $s4 = "requests.__version__)"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "No child processes"
        $s7 = "4d\"?%(O5jP"
        $s8 = "d}!(xKBvE&3"
        $s9 = "&4dCu/YoJM0"
        $s10 = "MCfFx'LKXi5"
        $s11 = "UA8o!Gr&0LW"
        $s12 = "2ao?(xvDt7g"
        $s13 = "f>D]dPJo.N!"
        $s14 = "V]0qCxSTbur"
        $s15 = "{IBj-?Z'crk"
        $s16 = "lvf%PJwd;r("
        $s17 = "K0VnB6F`G Z"
        $s18 = "MEZ679_)-tH"
        $s19 = "*VO;^E<}Zfq"
        $s20 = "AyvYU_1&E[u"
condition:
    uint16(0) == 0x5a4d and filesize < 8033KB and
    4 of them
}
    
