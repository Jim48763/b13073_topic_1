rule cbabaaeaffaeddeffafbdabaafbfc_exe {
strings:
        $s1 = "ManagementBaseObject"
        $s2 = "RuntimeHelpers"
        $s3 = "Runtime Error!"
        $s4 = "GetSubKeyNames"
        $s5 = "get_ProcessorArchitecture"
        $s6 = "Stream cannot seek"
        $s7 = "RuntimeFieldHandle"
        $s8 = "STAThreadAttribute"
        $s9 = "ProductName"
        $s10 = "ComputeHash"
        $s11 = "LastIndexOf"
        $s12 = "ConvertBack"
        $s13 = "get_MachineName"
        $s14 = "FileDescription"
        $s15 = "IFormatProvider"
        $s16 = "get_ProcessName"
        $s17 = "PhysicalAddress"
        $s18 = "FlushFinalBlock"
        $s19 = "OrderByDescending"
        $s20 = "ResolveEventArgs"
condition:
    uint16(0) == 0x5a4d and filesize < 237KB and
    4 of them
}
    