rule abdbeddcdcacbcacbaecbbefbda_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "s$728242<2:262>2129\"NT"
        $s3 = "Directory not empty"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "requests.__version__)"
        $s6 = "GetConsoleOutputCP"
        $s7 = "No child processes"
        $s8 = "operation canceled"
        $s9 = "Tcl_GetVar2"
        $s10 = "F#bgn?MwN|%"
        $s11 = "2ao?(xvDt7g"
        $s12 = "x_OJz\"P}7+"
        $s13 = "OIqUz)g`{wj"
        $s14 = "qYS~5u<ps0A"
        $s15 = "E1qI0JM.z&#"
        $s16 = "L?;lfIU}y#e"
        $s17 = "eM>4,2O}(#n"
        $s18 = "'0%Uk7z&^!1"
        $s19 = "lEcMF6KQN4W"
        $s20 = "* ny()LIP$@"
condition:
    uint16(0) == 0x5a4d and filesize < 16892KB and
    4 of them
}
    
