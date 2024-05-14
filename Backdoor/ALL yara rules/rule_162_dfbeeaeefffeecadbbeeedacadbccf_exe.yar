rule dfbeeaeefffeecadbbeeedacadbccf_exe {
strings:
        $s1 = "ProductName"
        $s2 = "LoadStringA"
        $s3 = "VarFileInfo"
        $s4 = "3EMDHN12:I4"
        $s5 = "5<^7=3g0.4E"
        $s6 = "FileDescription"
        $s7 = "34AC>KA;>:1?48CAE"
        $s8 = "GetShortPathNameA"
        $s9 = "3>0FC:8;KFFL;8<A"
        $s10 = "RemoveDirectoryA"
        $s11 = ":48IDOI1F=E:5"
        $s12 = ":?79:C=03IB=59"
        $s13 = "GetDeviceCaps"
        $s14 = "r`ozv>oRich{v>o"
        $s15 = "CompareFileTime"
        $s16 = "LegalTrademarks"
        $s17 = "kpfCv[caD#"
        $s18 = "_WFqu-52NI"
        $s19 = ",)6u+t|R8X"
        $s20 = "Copyright "
condition:
    uint16(0) == 0x5a4d and filesize < 169KB and
    4 of them
}
    
