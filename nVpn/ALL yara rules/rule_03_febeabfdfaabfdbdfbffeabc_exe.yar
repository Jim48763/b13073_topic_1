rule febeabfdfaabfdbdfbffeabc_exe {
strings:
        $s1 = "ysYjjUzz]vvS^^kaa"
        $s2 = "underlineTopToolStrip"
        $s3 = "Do you want to save?"
        $s4 = "logoPictureBox"
        $s5 = "STAThreadAttribute"
        $s6 = "ProductName"
        $s7 = "get_Company"
        $s8 = "_CorExeMain"
        $s9 = "=r^D<6Ely3."
        $s10 = "VarFileInfo"
        $s11 = "2GoLfEpBn\""
        $s12 = "Version {0}"
        $s13 = "Open Text Files"
        $s14 = "set_MinimizeBox"
        $s15 = "saveTopToolStrip"
        $s16 = "set_ShortcutKeys"
        $s17 = "add_SelectedIndexChanged"
        $s18 = "AssemblyTitleAttribute"
        $s19 = "get_FlatAppearance"
        $s20 = "GraphicsUnit"
condition:
    uint16(0) == 0x5a4d and filesize < 685KB and
    4 of them
}
    
