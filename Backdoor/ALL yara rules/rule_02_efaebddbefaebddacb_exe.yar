rule efaebddbefaebddacb_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "_CorExeMain"
        $s5 = "IXmlStorage"
        $s6 = "FileDescription"
        $s7 = "AddMessageFilter"
        $s8 = "Microsoft Corporation"
        $s9 = "GetResponseStream"
        $s10 = " Visual Studio"
        $s11 = "    </security>"
        $s12 = "get_StartInfo"
        $s13 = "GetObjectValue"
        $s14 = "set_UseShellExecute"
        $s15 = "StringSplitOptions"
        $s16 = "XmlNodeType"
        $s17 = "IDisposable"
        $s18 = "</assembly>"
        $s19 = "StringReader"
        $s20 = "set_Arguments"
condition:
    uint16(0) == 0x5a4d and filesize < 183KB and
    4 of them
}
    
