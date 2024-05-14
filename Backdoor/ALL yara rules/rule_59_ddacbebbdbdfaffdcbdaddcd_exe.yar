rule ddacbebbdbdfaffdcbdaddcd_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "System.Linq"
        $s3 = "op_Equality"
        $s4 = "_CorExeMain"
        $s5 = "H(3?T$;.K#+"
        $s6 = "H(6W4B#>X8G"
        $s7 = "ProductName"
        $s8 = "VarFileInfo"
        $s9 = "gravePanelWhite"
        $s10 = "set_MinimizeBox"
        $s11 = "FileDescription"
        $s12 = "AddPieceToGrave"
        $s13 = "gameLayoutPanel"
        $s14 = "InitializeComponent"
        $s15 = "Synchronized"
        $s16 = "set_TabIndex"
        $s17 = "ZLnRn[vY8~w'"
        $s18 = "IAsyncResult"
        $s19 = "#B#>K,L\"<1F"
        $s20 = "^;Z:R*A ;Y/E"
condition:
    uint16(0) == 0x5a4d and filesize < 354KB and
    4 of them
}
    
