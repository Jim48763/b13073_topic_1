rule ceffcdfeeccfdbdadacd_exe {
strings:
        $s1 = "Yxunktfdycfjfo"
        $s2 = "STAThreadAttribute"
        $s3 = "ProductName"
        $s4 = "_CorExeMain"
        $s5 = "op_Equality"
        $s6 = "VarFileInfo"
        $s7 = "Cjcwsgtohxe"
        $s8 = "FileDescription"
        $s9 = "kged^][ZWVSS"
        $s10 = "Synchronized"
        $s11 = "set_TabIndex"
        $s12 = "System.Resources"
        $s13 = "PerformLayout"
        $s14 = "MethodInvoker"
        $s15 = "    </application>"
        $s16 = "GeneratedCodeAttribute"
        $s17 = "R:0/+*(&&\"\"!"
        $s18 = "Dsfwwerjqqkpen"
        $s19 = "defaultInstance"
        $s20 = "    </security>"
condition:
    uint16(0) == 0x5a4d and filesize < 1787KB and
    4 of them
}
    
