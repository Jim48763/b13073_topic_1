rule cefeedddacefdebbddaa_exe {
strings:
        $s1 = "get_Enumerable"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "ProductName"
        $s5 = "My.Computer"
        $s6 = "System.Linq"
        $s7 = "MsgBoxStyle"
        $s8 = "VarFileInfo"
        $s9 = "_CorExeMain"
        $s10 = "ThreadStaticAttribute"
        $s11 = "get_IsCompleted"
        $s12 = "FileDescription"
        $s13 = "IFormatProvider"
        $s14 = "GetResponseToSign"
        $s15 = "GetChildPosition"
        $s16 = "AddMessageFilter"
        $s17 = "DebuggerHiddenAttribute"
        $s18 = "CryptographyHelper"
        $s19 = "Synchronized"
        $s20 = "CngAlgorithm"
condition:
    uint16(0) == 0x5a4d and filesize < 100KB and
    4 of them
}
    
