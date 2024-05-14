rule eeefddaeecbcdcccedefdaffefd_exe {
strings:
        $s1 = "IdnAllDataATtVVrN"
        $s2 = "get_ProductPrivatePart"
        $s3 = "RuntimeHelpers"
        $s4 = "$this.GridSize"
        $s5 = "EnumerateFiles"
        $s6 = "FlagsAttribute"
        $s7 = "GetSubKeyNames"
        $s8 = "RuntimeFieldHandle"
        $s9 = "RLJGJSBAPX2RPP62aA"
        $s10 = "_CNMnRIvFaK"
        $s11 = "_tOKjzQEgxq"
        $s12 = "_zswnpyPYSo"
        $s13 = "_JzhBSucfmY"
        $s14 = "_sCVSgJrEXU"
        $s15 = "_jgXDaZrPqW"
        $s16 = "ProductName"
        $s17 = "_CorExeMain"
        $s18 = "ComputeHash"
        $s19 = "_SqVTteCDAs"
        $s20 = "*n>+2)V\"_c"
condition:
    uint16(0) == 0x5a4d and filesize < 362KB and
    4 of them
}
    
