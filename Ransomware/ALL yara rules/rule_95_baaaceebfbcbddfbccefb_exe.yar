rule baaaceebfbcbddfbccefb_exe {
strings:
        $s1 = "  <!-- Wskazuje, "
        $s2 = "AmongUsHorrorEdition"
        $s3 = "RuntimeHelpers"
        $s4 = "STAThreadAttribute"
        $s5 = "RuntimeFieldHandle"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "_CorExeMain"
        $s9 = "ComputeHash"
        $s10 = "pictureBox1"
        $s11 = "op_Equality"
        $s12 = "set_WindowState"
        $s13 = "set_MinimizeBox"
        $s14 = "FileDescription"
        $s15 = "get_ProcessName"
        $s16 = "set_AutoSizeMode"
        $s17 = "The key is correct"
        $s18 = "GraphicsUnit"
        $s19 = "set_TabIndex"
        $s20 = "Synchronized"
condition:
    uint16(0) == 0x5a4d and filesize < 352KB and
    4 of them
}
    
