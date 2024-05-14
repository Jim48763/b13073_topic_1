import pe
rule badececbdeeafcddebec_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "s$728242<2:262>2129\"NT"
        $s3 = "Directory not empty"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "requests.__version__)"
        $s6 = "No child processes"
        $s7 = "F#bgn?MwN|%"
        $s8 = "!,'=/\"k%{j"
        $s9 = "5?69gM_{mb|"
        $s10 = "9Kk.g!/|_ry"
        $s11 = "2ao?(xvDt7g"
        $s12 = "qYS~5u<ps0A"
        $s13 = "eM>4,2O}(#n"
        $s14 = "lEcMF6KQN4W"
        $s15 = "3K0Y?D7!Qu "
        $s16 = "s\"r5UF:qT`"
        $s17 = "*O:+cBA[$? "
        $s18 = "3z0M~jH])_="
        $s19 = "<'^wVf{rk}C"
        $s20 = "Zv/Hj.nlu\""
condition:
    uint16(0) == 0x5a4d and filesize < 12956KB and
    4 of them
}
    