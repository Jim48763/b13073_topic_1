rule bacbcfdefadddffdbbbddddffcded_exe {
strings:
        $s1 = "Picasa Updater"
        $s2 = "STAThreadAttribute"
        $s3 = "ProductName"
        $s4 = "_CorExeMain"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "Synchronized"
        $s8 = "PerformClick"
        $s9 = "set_TabIndex"
        $s10 = "System.Resources"
        $s11 = "PerformLayout"
        $s12 = "GeneratedCodeAttribute"
        $s13 = "ResourceManager"
        $s14 = "CultureInfo"
        $s15 = "IDisposable"
        $s16 = "Google Inc."
        $s17 = "set_Opacity"
        $s18 = "set_Enabled"
        $s19 = "set_Location"
        $s20 = "EventHandler"
condition:
    uint16(0) == 0x5a4d and filesize < 573KB and
    4 of them
}
    
