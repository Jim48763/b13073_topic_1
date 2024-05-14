rule cfbfbfffacacdeeecdae_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "?< <0<(<8<$<4<,<<<\"<2<*<:<&<6<.<><!<1<)<9<%<5<-<=<#<3<+<;<'<7</<?"
        $s3 = "C@()4$444,4<4\"424*4:4&494%454-4=4#434+4;4'474/4?"
        $s4 = "Directory not empty"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "GetConsoleOutputCP"
        $s7 = "No child processes"
        $s8 = "operation canceled"
        $s9 = "Tcl_GetVar2"
        $s10 = "UanB7*ZyY-?"
        $s11 = "9Kk.g!/|_ry"
        $s12 = "kwN.lfp/4Td"
        $s13 = "Zf\"zpyhF D"
        $s14 = "^bINcSXUaj;"
        $s15 = "oKyi]EuI%=7"
        $s16 = "s5O>{r\"<iQ"
        $s17 = "9m-N6\"C5:A"
        $s18 = "}D\"sK.h 40"
        $s19 = "BLVJ mEdU^T"
        $s20 = "BC=FNbyTsdH"
condition:
    uint16(0) == 0x5a4d and filesize < 12216KB and
    4 of them
}
    
