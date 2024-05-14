rule ceecdfcbdecacaebcfcbab_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "GetSubKeyNames"
        $s3 = "<Getip>b__13_0"
        $s4 = "RuntimeHelpers"
        $s5 = "GetProcessesByName"
        $s6 = "get_ProcessorCount"
        $s7 = "ReadFromEmbeddedResources"
        $s8 = "LastIndexOf"
        $s9 = "op_Equality"
        $s10 = "EmailSendTo"
        $s11 = "_CorExeMain"
        $s12 = "XmlNodeList"
        $s13 = "ComputeHash"
        $s14 = ",'e AWl\"tN"
        $s15 = "ProductName"
        $s16 = "GroupCollection"
        $s17 = "SerializeObject"
        $s18 = "OperativeSystem"
        $s19 = "FileDescription"
        $s20 = "SendingInterval"
condition:
    uint16(0) == 0x5a4d and filesize < 553KB and
    4 of them
}
    
