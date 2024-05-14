rule fcfcaddaabfeccfebebaffcea_exe {
strings:
        $s1 = "VirtualAllocEx"
        $s2 = "STAThreadAttribute"
        $s3 = "sC}-QUnhP+T"
        $s4 = "op_Equality"
        $s5 = "_CorExeMain"
        $s6 = "VarFileInfo"
        $s7 = "ProductName"
        $s8 = "FileDescription"
        $s9 = "dKCnOxbbW7xx0xVWp5x"
        $s10 = "AssemblyTitleAttribute"
        $s11 = "WriteProcessMemory"
        $s12 = "Ij, \"o.118t"
        $s13 = "Synchronized"
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
    
