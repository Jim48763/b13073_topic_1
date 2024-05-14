rule bafddbdebfbcbddbebdbd_exe {
strings:
        $s1 = "m_f17b67d641664fc9adb7db3c6dbdc334"
        $s2 = "STAThreadAttribute"
        $s3 = "System.Linq"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "_CorExeMain"
        $s7 = "op_Equality"
        $s8 = "FileDescription"
        $s9 = "m_fbe4b507654441f8b4126e717f4e7e15"
        $s10 = "Microsoft Corporation"
        $s11 = "Synchronized"
        $s12 = "m_Repository"
        $s13 = "System.Resources"
        $s14 = "GeneratedCodeAttribute"
        $s15 = "    </security>"
        $s16 = "defaultInstance"
        $s17 = "DebuggingModes"
        $s18 = "ResourceManager"
        $s19 = "LegalTrademarks"
        $s20 = "DebuggableAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 58KB and
    4 of them
}
    
