rule feecdbcdcbaffceebbdabafcccec_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "ProductName"
        $s3 = "_CorExeMain"
        $s4 = "VarFileInfo"
        $s5 = "FileDescription"
        $s6 = "ContextMenuStrip"
        $s7 = "AssemblyTitleAttribute"
        $s8 = "set_TabIndex"
        $s9 = "Synchronized"
        $s10 = "DialogResult"
        $s11 = "set_Encoding"
        $s12 = "System.Resources"
        $s13 = "AutoScaleMode"
        $s14 = "DirectoryInfo"
        $s15 = "PerformLayout"
        $s16 = "StringBuilder"
        $s17 = "GeneratedCodeAttribute"
        $s18 = "ObjectCollection"
        $s19 = "defaultInstance"
        $s20 = "ReferenceEquals"
condition:
    uint16(0) == 0x5a4d and filesize < 499KB and
    4 of them
}
    
