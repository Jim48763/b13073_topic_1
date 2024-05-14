rule abeffedabaaaaaafebfffc_exe {
strings:
        $s1 = "CreateSubItemNode"
        $s2 = "set_SelectedImageIndex"
        $s3 = "RuntimeHelpers"
        $s4 = "RuntimeFieldHandle"
        $s5 = "STAThreadAttribute"
        $s6 = "ProductName"
        $s7 = "_CorExeMain"
        $s8 = "get_Crimson"
        $s9 = "4BzqLmI*~ce"
        $s10 = "VarFileInfo"
        $s11 = "get_Company"
        $s12 = "set_ShowRootLines"
        $s13 = "GetWrappedEntity"
        $s14 = "Espresso (Large)"
        $s15 = "InitializeComponent"
        $s16 = "X0B48PBPY54U4UG747H5UX"
        $s17 = "get_FlatAppearance"
        $s18 = "Synchronized"
        $s19 = "GraphicsUnit"
        $s20 = "set_TabIndex"
condition:
    uint16(0) == 0x5a4d and filesize < 323KB and
    4 of them
}
    
