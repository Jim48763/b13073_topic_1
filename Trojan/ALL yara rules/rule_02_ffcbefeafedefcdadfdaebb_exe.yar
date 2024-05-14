rule ffcbefeafedefcdadfdaebb_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = ".?WX>S <w=L"
        $s3 = "G0%EHPD7pkK"
        $s4 = "ProductName"
        $s5 = "_CorExeMain"
        $s6 = "[CNXQ1\"'L$"
        $s7 = "op_Equality"
        $s8 = "lZUNFe!3/8H"
        $s9 = "f>N]Ybyd;As"
        $s10 = "boardHeight"
        $s11 = "VarFileInfo"
        $s12 = "NT\"=C(A@5t"
        $s13 = "+,4C:cp6?#["
        $s14 = "FileDescription"
        $s15 = "Node_X_Coordinate"
        $s16 = " damage points to"
        $s17 = "InitializeComponent"
        $s18 = "I'm going to move here "
        $s19 = "Dictionary`2"
        $s20 = "Synchronized"
condition:
    uint16(0) == 0x5a4d and filesize < 930KB and
    4 of them
}
    
