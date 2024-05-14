rule bbddeaeedccafcedaacdeafcfd_exe {
strings:
        $s1 = "get_algeria_32972"
        $s2 = "m_42dec28da3dc4080aecae30d922c1322"
        $s3 = "m_421110128c054a20980cd1992c994af5"
        $s4 = "STAThreadAttribute"
        $s5 = "_CorExeMain"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "ValidateFactory"
        $s10 = "ResolveEventArgs"
        $s11 = "Synchronized"
        $s12 = "set_TabIndex"
        $s13 = "brazil_32937"
        $s14 = "bhutan_32931"
        $s15 = "bouvet_33156"
        $s16 = "angola_32914"
        $s17 = "System.Resources"
        $s18 = "    </metadata></svg>"
        $s19 = "AutoScaleMode"
        $s20 = "PerformLayout"
condition:
    uint16(0) == 0x5a4d and filesize < 1219KB and
    4 of them
}
    