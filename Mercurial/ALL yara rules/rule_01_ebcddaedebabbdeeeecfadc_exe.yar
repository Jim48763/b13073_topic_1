rule ebcddaedebabbdeeeecfadc_exe {
strings:
        $s1 = "pszImplementation"
        $s2 = "ManagementBaseObject"
        $s3 = "Failed to load 404."
        $s4 = "RuntimeHelpers"
        $s5 = "MarshalAsAttribute"
        $s6 = "RuntimeFieldHandle"
        $s7 = "VarFileInfo"
        $s8 = "_CorExeMain"
        $s9 = "PixelFormat"
        $s10 = "FileDescription"
        $s11 = "Drive {0}\\ - {1}"
        $s12 = "GetDirectoryName"
        $s13 = "GetConsoleWindow"
        $s14 = "RblxCookieLogger"
        $s15 = "System.Net.Http.Headers"
        $s16 = "get_CurrentDirectory"
        $s17 = "DataProtectionScope"
        $s18 = "$$method0x6000041-1"
        $s19 = "RegexOptions"
        $s20 = "Dictionary`2"
condition:
    uint16(0) == 0x5a4d and filesize < 47KB and
    4 of them
}
    
