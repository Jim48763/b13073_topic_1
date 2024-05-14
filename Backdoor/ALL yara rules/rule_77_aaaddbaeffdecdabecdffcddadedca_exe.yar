rule aaaddbaeffdecdabecdffcddadedca_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "ComputeHash"
        $s3 = "System.Linq"
        $s4 = "_CorExeMain"
        $s5 = "zWswVDGHzuU=___"
        $s6 = "IsWhiteSpace"
        $s7 = "IlcException"
        $s8 = "get_StartInfo"
        $s9 = "GetObjectValue"
        $s10 = "InitializeArray"
        $s11 = "set_UseShellExecute"
        $s12 = "StringSplitOptions"
        $s13 = "IDisposable"
        $s14 = "get_Unicode"
        $s15 = "IEnumerator"
        $s16 = "ReadAllLines"
        $s17 = "DataGridCell"
        $s18 = "set_Arguments"
        $s19 = "set_FileName"
        $s20 = "CreateDecryptor"
condition:
    uint16(0) == 0x5a4d and filesize < 230KB and
    4 of them
}
    
