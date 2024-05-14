rule ffdacfccbdbefeeacadddbbbcf_exe {
strings:
        $s1 = "Empty email field"
        $s2 = "$this.MinimumSize"
        $s3 = "Enrolled Students"
        $s4 = "textLastName.Location"
        $s5 = "set_OverwritePrompt"
        $s6 = "Insufficient student data"
        $s7 = "set_TransparencyKey"
        $s8 = "inputLayout.ColumnCount"
        $s9 = "RefreshSection"
        $s10 = "RuntimeHelpers"
        $s11 = ">>textLastName.Parent"
        $s12 = "MenuItemCollection"
        $s13 = "STAThreadAttribute"
        $s14 = "LastIndexOf"
        $s15 = "op_Equality"
        $s16 = "_CorExeMain"
        $s17 = "Gkh_KeyDown"
        $s18 = "Ticker Rows"
        $s19 = "get_Fuchsia"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 566KB and
    4 of them
}
    
