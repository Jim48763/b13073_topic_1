rule cdfdeaeafbecbcdacaabeee_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "Directory not empty"
        $s3 = "unittest._log)"
        $s4 = "requests.__version__)"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "No child processes"
        $s7 = "4d\"?%(O5jP"
        $s8 = "d}!(xKBvE&3"
        $s9 = "MCfFx'LKXi5"
        $s10 = "UA8o!Gr&0LW"
        $s11 = "2ao?(xvDt7g"
        $s12 = "f>D]dPJo.N!"
        $s13 = "V]0qCxSTbur"
        $s14 = "Az&}ICXtq:r"
        $s15 = "{IBj-?Z'crk"
        $s16 = "lvf%PJwd;r("
        $s17 = "MEZ679_)-tH"
        $s18 = "*VO;^E<}Zfq"
        $s19 = "AyvYU_1&E[u"
        $s20 = "Hf8\"x=-rp<"
condition:
    uint16(0) == 0x5a4d and filesize < 7206KB and
    4 of them
}
    
