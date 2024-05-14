rule eecffedefddddacdfefaeeefefbaee_exe {
strings:
        $s1 = "CreateNamespaceAttribute"
        $s2 = "fn/;6uEh\"5\\D"
        $s3 = "RuntimeHelpers"
        $s4 = "AuthenticationMode"
        $s5 = "STAThreadAttribute"
        $s6 = "DesignerGeneratedAttribute"
        $s7 = "ComputeHash"
        $s8 = "System.Linq"
        $s9 = "tm\"#~e 1%N"
        $s10 = "MsgBoxStyle"
        $s11 = "ORL2&Y-v|lB"
        $s12 = "n!a<&6kIC-U"
        $s13 = "b*gFzHXMGTO"
        $s14 = "og<T%rkL?2l"
        $s15 = "ej.^1$m|=+b"
        $s16 = "op_Equality"
        $s17 = "VarFileInfo"
        $s18 = "1_Us*5i&aq2"
        $s19 = "LyO-ZId@#]4"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 4801KB and
    4 of them
}
    
