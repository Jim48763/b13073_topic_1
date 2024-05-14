rule cfcefddeaaddaddaaaabbfcba_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "bsqyqEqUquqMqmq]q}1[\"+"
        $s3 = "Directory not empty"
        $s4 = "unittest._log)"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "No child processes"
        $s7 = "h')5:L_XM?;"
        $s8 = "A=m%of]\">C"
        $s9 = "E9R>Gx\"Qe^"
        $s10 = "2ao?(xvDt7g"
        $s11 = "V]0qCxSTbur"
        $s12 = "W67VSvyh^~1"
        $s13 = "nF[3'X2oLud"
        $s14 = " )LN%EIqr:9"
        $s15 = "z>V{,`\"^P8"
        $s16 = "XmDI!G3w2>4"
        $s17 = "`'v1(KpOC6["
        $s18 = "MEZ679_)-tH"
        $s19 = "s6qJ9[8FN\""
        $s20 = "6J!R=Xk,5$N"
condition:
    uint16(0) == 0x5a4d and filesize < 6707KB and
    4 of them
}
    
