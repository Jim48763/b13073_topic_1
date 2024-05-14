rule ecdeccfeeeabedefefffe_exe {
strings:
        $s1 = "get_ControlDarkDark"
        $s2 = "ConsolePokerGame.Classes"
        $s3 = "RuntimeHelpers"
        $s4 = "RuntimeFieldHandle"
        $s5 = "STAThreadAttribute"
        $s6 = "\"Exit3Ok?6"
        $s7 = "~tUvI%#\"=Q"
        $s8 = "_CorExeMain"
        $s9 = "ComputeHash"
        $s10 = "U]0Z3t=+^'<"
        $s11 = "ProductName"
        $s12 = "1:Z?Iw<d|G#"
        $s13 = "VarFileInfo"
        $s14 = "{?4 /YzCalF"
        $s15 = "get_Columns"
        $s16 = "\"AV{rtN8C,"
        $s17 = "op_Equality"
        $s18 = "FileDescription"
        $s19 = "DealTurnOrRiver"
        $s20 = "FlushFinalBlock"
condition:
    uint16(0) == 0x5a4d and filesize < 2375KB and
    4 of them
}
    
