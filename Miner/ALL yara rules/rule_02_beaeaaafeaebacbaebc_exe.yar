rule beaeaaafeaebacbaebc_exe {
strings:
        $s1 = "007A56C60CB686C542C5A63F4806094A4F9494B7"
        $s2 = "BrowserExtension7"
        $s3 = "pszImplementation"
        $s4 = "GetWindowsVersion"
        $s5 = "CommandLineUpdate"
        $s6 = "LEnvironmentogiEnvironmentn DatEnvironmenta"
        $s7 = "ManagementBaseObject"
        $s8 = "EnumerateDirectories"
        $s9 = "RuntimeHelpers"
        $s10 = "GetSubKeyNames"
        $s11 = "ReadFileAsText"
        $s12 = "set_HolderName"
        $s13 = "RuntimeFieldHandle"
        $s14 = "GetProcessesByName"
        $s15 = "ScanResultT"
        $s16 = "System.Linq"
        $s17 = "ProductName"
        $s18 = "DecryptBlob"
        $s19 = "GetScanArgs"
        $s20 = "profilePath"
condition:
    uint16(0) == 0x5a4d and filesize < 118KB and
    4 of them
}
    
