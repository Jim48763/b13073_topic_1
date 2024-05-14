rule dcfffbdceffbdfbdbeeeadfbdedbe_exe {
strings:
        $s1 = "get_algeria_32972"
        $s2 = "Music.Expressions"
        $s3 = "ParserBridgeStatus"
        $s4 = "STAThreadAttribute"
        $s5 = "_CorExeMain"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "ResolveEventArgs"
        $s10 = "m_c4b4329b0a8042c6a0232c16292c3492"
        $s11 = "Geqrtxo.Properties"
        $s12 = "Synchronized"
        $s13 = "set_TabIndex"
        $s14 = "brazil_32937"
        $s15 = "bhutan_32931"
        $s16 = "CloneProduct"
        $s17 = "bouvet_33156"
        $s18 = "angola_32914"
        $s19 = "System.Resources"
        $s20 = "    </metadata></svg>"
condition:
    uint16(0) == 0x5a4d and filesize < 1194KB and
    4 of them
}
    
