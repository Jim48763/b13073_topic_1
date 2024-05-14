rule ddbacfeadffadeadecfcfce_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "WM_MDIICONARRANGE"
        $s3 = "All_Users_Startup"
        $s4 = "DescriptionAttribute"
        $s5 = "CWP_SKIPTRANSPARENT"
        $s6 = "ComboBoxStyles"
        $s7 = "FlagsAttribute"
        $s8 = "set_SizingGrip"
        $s9 = "GetHeaderOrFooterInfo"
        $s10 = "DrawStringPosition"
        $s11 = "SS_REALSIZECONTROL"
        $s12 = "STAThreadAttribute"
        $s13 = "pSearchDown"
        $s14 = "ProductName"
        $s15 = "W3fj4c`X;Jb"
        $s16 = "_CorExeMain"
        $s17 = "ComputeHash"
        $s18 = "Fi&nd what:"
        $s19 = "Adobe Inc.0"
        $s20 = "LastIndexOf"
condition:
    uint16(0) == 0x5a4d and filesize < 641KB and
    4 of them
}
    
