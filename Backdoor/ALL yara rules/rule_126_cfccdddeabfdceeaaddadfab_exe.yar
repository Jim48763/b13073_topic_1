rule cfccdddeabfdceeaaddadfab_exe {
strings:
        $s1 = "ProductName"
        $s2 = "kJx1Qo4dLZA"
        $s3 = "VarFileInfo"
        $s4 = "_CorExeMain"
        $s5 = "vMz0KJHunLU"
        $s6 = "FileDescription"
        $s7 = "GetExportedTypes"
        $s8 = "DebuggerHiddenAttribute"
        $s9 = "fMF7Lm4QP6kQ"
        $s10 = "Dictionary`2"
        $s11 = "Durbanville1"
        $s12 = "get_CurrentThread"
        $s13 = "System.Resources"
        $s14 = "StringBuilder"
        $s15 = "RrjlEZA6urobE"
        $s16 = "EZahDgtrS1SEo"
        $s17 = "get_ManagedThreadId"
        $s18 = "GeneratedCodeAttribute"
        $s19 = "ReferenceEquals"
        $s20 = "Western Cape1"
condition:
    uint16(0) == 0x5a4d and filesize < 952KB and
    4 of them
}
    
