rule eddbaceebbcbfeabccacbeeb_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "ProductName"
        $s3 = "31.lSfgApat"
        $s4 = "_CorExeMain"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "eyPermissionChec"
        $s8 = "set_TabIndex"
        $s9 = "DialogResult"
        $s10 = "Synchronized"
        $s11 = "System.Resources"
        $s12 = "Invalid grade"
        $s13 = "AutoScaleMode"
        $s14 = "MethodInvoker"
        $s15 = "c06CLZZ5aNduN"
        $s16 = "GeneratedCodeAttribute"
        $s17 = "ObjectCollection"
        $s18 = "defaultInstance"
        $s19 = "ReferenceEquals"
        $s20 = "ResourceManager"
condition:
    uint16(0) == 0x5a4d and filesize < 1186KB and
    4 of them
}
    
