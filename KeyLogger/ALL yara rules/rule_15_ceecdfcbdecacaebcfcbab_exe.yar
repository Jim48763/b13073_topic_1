rule ceecdfcbdecacaebcfcbab_exe {
strings:
        $s1 = "ManagementBaseObject"
        $s2 = "FlagsAttribute"
        $s3 = "<Getip>b__13_0"
        $s4 = "GetSubKeyNames"
        $s5 = "RuntimeHelpers"
        $s6 = "GetProcessesByName"
        $s7 = "DownloaderFilename"
        $s8 = "get_ProcessorCount"
        $s9 = "ReadFromEmbeddedResources"
        $s10 = ",'e AWl\"tN"
        $s11 = "ComputeHash"
        $s12 = "EmailSendTo"
        $s13 = "GetWindowDC"
        $s14 = "dwMaxLength"
        $s15 = "LastIndexOf"
        $s16 = "_CorExeMain"
        $s17 = "ProductName"
        $s18 = "XmlNodeList"
        $s19 = "SerializeObject"
        $s20 = "FlushFinalBlock"
condition:
    uint16(0) == 0x5a4d and filesize < 553KB and
    4 of them
}
    
