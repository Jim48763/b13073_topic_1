rule befcfebebfcdecebdfaffbccc_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "remove_PayRent"
        $s3 = "settings/upgrade/rent"
        $s4 = "getPossibleActions"
        $s5 = "STAThreadAttribute"
        $s6 = "[39u~>R_Kh)"
        $s7 = "pictureBox1"
        $s8 = "OnThisGroup"
        $s9 = "op_Equality"
        $s10 = "_CorExeMain"
        $s11 = "VarFileInfo"
        $s12 = "ProductName"
        $s13 = "XmlNodeList"
        $s14 = "DefaultMemberAttribute"
        $s15 = "set_WindowState"
        $s16 = "FileDescription"
        $s17 = "get_PositionField"
        $s18 = "TableLayoutPanel"
        $s19 = "Card_UseFreeJail"
        $s20 = "get_CreditHouses"
condition:
    uint16(0) == 0x5a4d and filesize < 417KB and
    4 of them
}
    
