rule bfbfdbbbbbffcbdddafaedbb_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "ManagementBaseObject"
        $s3 = "RuntimeHelpers"
        $s4 = "<Getip>b__13_0"
        $s5 = "GetSubKeyNames"
        $s6 = "FlagsAttribute"
        $s7 = "RuntimeFieldHandle"
        $s8 = "DownloaderFilename"
        $s9 = "get_ProcessorCount"
        $s10 = "ReadFromEmbeddedResources"
        $s11 = "System.Linq"
        $s12 = "ProductName"
        $s13 = "EmailSendTo"
        $s14 = "_CorExeMain"
        $s15 = "ComputeHash"
        $s16 = "dwMaxLength"
        $s17 = "LastIndexOf"
        $s18 = "XmlNodeList"
        $s19 = "VarFileInfo"
        $s20 = "OperativeSystem"
condition:
    uint16(0) == 0x5a4d and filesize < 519KB and
    4 of them
}
    
