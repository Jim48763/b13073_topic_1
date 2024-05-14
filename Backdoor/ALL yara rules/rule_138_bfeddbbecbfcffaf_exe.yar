rule bfeddbbecbfcffaf_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "ProductName"
        $s3 = "XmlNodeList"
        $s4 = "VarFileInfo"
        $s5 = "_CorExeMain"
        $s6 = ":NOn ]\"VgP"
        $s7 = "FileDescription"
        $s8 = "Microsoft Corporation"
        $s9 = "Synchronized"
        $s10 = "ICredentials"
        $s11 = "set_TabIndex"
        $s12 = "RegexOptions"
        $s13 = "Dictionary`2"
        $s14 = "{[M%--ZH?&iT"
        $s15 = "System.Resources"
        $s16 = "AutoScaleMode"
        $s17 = "StringBuilder"
        $s18 = "GeneratedCodeAttribute"
        $s19 = "GetResponseStream"
        $s20 = "set_HideSelection"
condition:
    uint16(0) == 0x5a4d and filesize < 237KB and
    4 of them
}
    
