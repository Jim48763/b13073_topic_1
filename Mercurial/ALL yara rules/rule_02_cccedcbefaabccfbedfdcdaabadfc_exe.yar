rule cccedcbefaabccfbedfdcdaabadfc_exe {
strings:
        $s1 = "pszImplementation"
        $s2 = "ManagementBaseObject"
        $s3 = "RuntimeHelpers"
        $s4 = "MarshalAsAttribute"
        $s5 = "RuntimeFieldHandle"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "PixelFormat"
        $s9 = "FileDescription"
        $s10 = "Drive {0}\\ - {1}"
        $s11 = "GetDirectoryName"
        $s12 = "GetConsoleWindow"
        $s13 = "System.Net.Http.Headers"
        $s14 = "get_CurrentDirectory"
        $s15 = "DataProtectionScope"
        $s16 = "$$method0x6000041-1"
        $s17 = "RegexOptions"
        $s18 = "Dictionary`2"
        $s19 = "/flat/48.png"
        $s20 = "DialogResult"
condition:
    uint16(0) == 0x5a4d and filesize < 47KB and
    4 of them
}
    
