rule fcfcaddaabfeccfebebaffcea_exe {
strings:
        $s1 = "VirtualAllocEx"
        $s2 = "STAThreadAttribute"
        $s3 = "op_Equality"
        $s4 = "_CorExeMain"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "sC}-QUnhP+T"
        $s8 = "FileDescription"
        $s9 = "timestamp.intel.com"
        $s10 = "dKCnOxbbW7xx0xVWp5x"
        $s11 = "WriteProcessMemory"
        $s12 = "Synchronized"
        $s13 = "Ij, \"o.118t"
        $s14 = "AutoScaleMode"
        $s15 = "GeneratedCodeAttribute"
        $s16 = "CallSiteBinder"
        $s17 = "Santa Clara1\"0 "
        $s18 = "System.Security"
        $s19 = "defaultInstance"
        $s20 = "ReferenceEquals"
condition:
    uint16(0) == 0x5a4d and filesize < 767KB and
    4 of them
}
    
