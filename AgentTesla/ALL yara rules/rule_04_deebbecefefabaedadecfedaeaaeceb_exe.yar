rule deebbecefefabaedadecfedaeaaeceb_exe {
strings:
        $s1 = "ysYjjUzz]vvS^^kaa"
        $s2 = "underlineTopToolStrip"
        $s3 = "Do you want to save?"
        $s4 = "textBoxDescription"
        $s5 = "STAThreadAttribute"
        $s6 = "eAH24O1>CpF"
        $s7 = "op_Equality"
        $s8 = "_CorExeMain"
        $s9 = "mZF*D{PB%!+"
        $s10 = "Version {0}"
        $s11 = "get_Company"
        $s12 = ",Ve{f6\"+ws"
        $s13 = "l\"{n<&qx/G"
        $s14 = "First Name:"
        $s15 = "VarFileInfo"
        $s16 = "set_MinimizeBox"
        $s17 = "Open Text Files"
        $s18 = "tableLayoutPanel1"
        $s19 = "set_ShortcutKeys"
        $s20 = "add_SelectedIndexChanged"
condition:
    uint16(0) == 0x5a4d and filesize < 504KB and
    4 of them
}
    
