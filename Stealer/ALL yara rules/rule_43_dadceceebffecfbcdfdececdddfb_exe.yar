rule dadceceebffecfbcdfdececdddfb_exe {
strings:
        $s1 = "ResolveTypeHandle"
        $s2 = "get_IsTerminating"
        $s3 = "GCNotificationStatus"
        $s4 = "RuntimeHelpers"
        $s5 = "SendingReportStep1"
        $s6 = "RuntimeFieldHandle"
        $s7 = "STAThreadAttribute"
        $s8 = "get_ProcessorCount"
        $s9 = "$Copyright "
        $s10 = "@u|-?$!Eax'"
        $s11 = "_CorExeMain"
        $s12 = "ComputeHash"
        $s13 = ".XU!*#+o2\""
        $s14 = "u!Uc7md1':j"
        $s15 = "ProductName"
        $s16 = "\"M%k6S]#7n"
        $s17 = "VarFileInfo"
        $s18 = "LastIndexOf"
        $s19 = "XmlNodeList"
        $s20 = "*WD4w@u7nS1"
condition:
    uint16(0) == 0x5a4d and filesize < 1315KB and
    4 of them
}
    
