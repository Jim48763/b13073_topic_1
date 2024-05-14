rule bacbdebfcaeebaacfbccacaceebaea_exe {
strings:
        $s1 = "ysYjjUzz]vvS^^kaa"
        $s2 = "underlineTopToolStrip"
        $s3 = "Do you want to save?"
        $s4 = "textBoxDescription"
        $s5 = "STAThreadAttribute"
        $s6 = "op_Equality"
        $s7 = "_CorExeMain"
        $s8 = "Version {0}"
        $s9 = "2lf,>mgqM;B"
        $s10 = "get_Company"
        $s11 = "First Name:"
        $s12 = "VarFileInfo"
        $s13 = "DFB.ko]'ce1"
        $s14 = "set_MinimizeBox"
        $s15 = "Open Text Files"
        $s16 = "tableLayoutPanel1"
        $s17 = "set_ShortcutKeys"
        $s18 = "add_SelectedIndexChanged"
        $s19 = "get_FlatAppearance"
        $s20 = "set_ReadOnly"
condition:
    uint16(0) == 0x5a4d and filesize < 500KB and
    4 of them
}
    
