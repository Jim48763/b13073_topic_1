rule dfdddcccdebcbcdaaceffbcaa_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "DefColWidth"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleW"
        $s6 = "MSDataGridLib.DataGrid"
        $s7 = "WriteProcessMemory"
        $s8 = "nlL0YyV'~\\_"
        $s9 = "MSDATGRD.OCX"
        $s10 = "MSDataGridLib"
        $s11 = "Process32First"
        $s12 = "lkihygbvcf"
        $s13 = ".JZeXE}2h,"
        $s14 = "*F\"E<w/[M"
        $s15 = "RightToLeft"
        $s16 = "cmbOperator"
        $s17 = "kernel32.DLL"
        $s18 = "ayastbesilbhelw"
        $s19 = "DllFunctionCall"
        $s20 = "RtlMoveMemory"
condition:
    uint16(0) == 0x5a4d and filesize < 209KB and
    4 of them
}
    
