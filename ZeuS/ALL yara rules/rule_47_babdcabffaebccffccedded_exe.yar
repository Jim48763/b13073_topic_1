rule babdcabffaebccffccedded_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "cmdPrevious"
        $s4 = "ib>_:atHP#W"
        $s5 = "FileDescription"
        $s6 = "q^^UV_PP_`;abcc\\cP"
        $s7 = "KJKUyh^ysz2{B"
        $s8 = "MethCallEngine"
        $s9 = ":)Gw5aJ.4{"
        $s10 = "SDQJ51tTmd"
        $s11 = "Xr_'0BGg`$"
        $s12 = "adoPrimaryRS"
        $s13 = "DllFunctionCall"
        $s14 = "Enter the coeffecient"
        $s15 = "OriginalFilename"
        $s16 = "GetFileName1"
        $s17 = ".:8;<;=>?@"
        $s18 = "picStatBox"
        $s19 = "VBInternal"
        $s20 = "Expression"
condition:
    uint16(0) == 0x5a4d and filesize < 184KB and
    4 of them
}
    
