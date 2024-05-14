rule eebeeebfbadefaebefbcaaccbaa_exe {
strings:
        $s1 = "SystemNetMailMessagex"
        $s2 = "_CorExeMain"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "lpApplicationName"
        $s6 = "PointerToRawData"
        $s7 = "IAsyncResult"
        $s8 = "ContextFlags"
        $s9 = "lpCommandLine"
        $s10 = "StringBuilder"
        $s11 = "lpStartupInfo"
        $s12 = "SecurityAction"
        $s13 = "VirtualAddress"
        $s14 = "MetroSetUIFormsMetroSetFormn"
        $s15 = "System.Security"
        $s16 = "lpEnvironment"
        $s17 = "SizeOfRawData"
        $s18 = "SizeOfHeaders"
        $s19 = "DebuggingModes"
        $s20 = "dwFillAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 23KB and
    4 of them
}
    
