rule cbbbdfceecfcadeaeaebafd_exe {
strings:
        $s1 = "7C9294BE6200FF78DBFFD78FF8899846A7C82760"
        $s2 = "007A56C60CB686C542C5A63F4806094A4F9494B7"
        $s3 = "pszImplementation"
        $s4 = "GetWindowsVersion"
        $s5 = "Happy.g.resources"
        $s6 = "CommandLineUpdate"
        $s7 = "numberNegativePattern"
        $s8 = "ManagementBaseObject"
        $s9 = "EnumerateDirectories"
        $s10 = "UJ33JoJL3byfayOv3ZE"
        $s11 = "RuntimeHelpers"
        $s12 = "GetSubKeyNames"
        $s13 = "get_NameOfFile"
        $s14 = "FlagsAttribute"
        $s15 = "set_HolderName"
        $s16 = "$this.GridSize"
        $s17 = "RuntimeFieldHandle"
        $s18 = "GetProcessesByName"
        $s19 = "ScanResultT"
        $s20 = "System.Linq"
condition:
    uint16(0) == 0x5a4d and filesize < 267KB and
    4 of them
}
    
