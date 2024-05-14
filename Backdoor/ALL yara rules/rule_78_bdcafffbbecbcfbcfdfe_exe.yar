rule bdcafffbbecbcfbcfdfe_exe {
strings:
        $s1 = "e4d5dd60-3018-4f85-9971-8d1f87448178"
        $s2 = "get_TypeHandle"
        $s3 = "RuntimeHelpers"
        $s4 = "dbDDDAebAadbfDEBcfBFACEeF"
        $s5 = "ProductName"
        $s6 = "op_Equality"
        $s7 = "MsgBoxStyle"
        $s8 = "VarFileInfo"
        $s9 = "_CorExeMain"
        $s10 = "___EbBeACabeAceAdbebdDFfaedfBAd"
        $s11 = "FileDescription"
        $s12 = "get_IsConstructor"
        $s13 = "Microsoft Corporation"
        $s14 = "___bBfAcfFCdeBFcfcaBEafFfbcbfeAd"
        $s15 = "get_DateTimeFormat"
        $s16 = "___FCecADbEffcAfEACeCfcFBaAfDD"
        $s17 = "IAsyncResult"
        $s18 = "MsgBoxResult"
        $s19 = "___bFAdEcFfeeeaBD"
        $s20 = "dDBEefbEbEEDcefFCaBAdEAb"
condition:
    uint16(0) == 0x5a4d and filesize < 160KB and
    4 of them
}
    
