rule dbbefddaddaccacfaeac_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "AuthenticationMode"
        $s4 = "DesignerGeneratedAttribute"
        $s5 = "TiR?9\"ZAMg"
        $s6 = "-OMy\"r8(K^"
        $s7 = "My.Computer"
        $s8 = "0r9IZ3\"U*l"
        $s9 = "bLeftBishop"
        $s10 = "op_Equality"
        $s11 = "MsgBoxStyle"
        $s12 = "_CorExeMain"
        $s13 = "unitToPlace"
        $s14 = "ComputeHash"
        $s15 = "jv_y'PKw.$g"
        $s16 = "ProductName"
        $s17 = "UB!&_s-=G/q"
        $s18 = "VarFileInfo"
        $s19 = "k\"EjONfrJ."
        $s20 = ">)pgoA@nIVY"
condition:
    uint16(0) == 0x5a4d and filesize < 810KB and
    4 of them
}
    
