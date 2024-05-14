rule bcbbffddebacbfeefbcaaeab_exe {
strings:
        $s1 = "        Posteriormente, la clave se cifr"
        $s2 = "Decrypt.Properties.Resources.resources"
        $s3 = "MO COMPRAR BITCOINS"
        $s4 = "RuntimeHelpers"
        $s5 = "STAThreadAttribute"
        $s6 = "GetProcessesByName"
        $s7 = "RuntimeFieldHandle"
        $s8 = "System.Linq"
        $s9 = "ProductName"
        $s10 = "VarFileInfo"
        $s11 = "_CorExeMain"
        $s12 = "ComputeHash"
        $s13 = "op_Equality"
        $s14 = "bito o transferencia bancaria"
        $s15 = "set_WindowState"
        $s16 = "set_MinimizeBox"
        $s17 = "FileDescription"
        $s18 = "get_MachineName"
        $s19 = "set_SizeGripStyle"
        $s20 = "<Form1_Load>m__0"
condition:
    uint16(0) == 0x5a4d and filesize < 561KB and
    4 of them
}
    
