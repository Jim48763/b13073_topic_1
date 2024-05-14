rule ceeedbeafffdfaddbdbebfcbaf_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "_CorExeMain"
        $s3 = "FileDescription"
        $s4 = "    </security>"
        $s5 = "set_UseShellExecute"
        $s6 = "IDisposable"
        $s7 = "</assembly>"
        $s8 = "DownloadFile"
        $s9 = "get_Location"
        $s10 = "set_Arguments"
        $s11 = "OriginalFilename"
        $s12 = "set_FileName"
        $s13 = "VS_VERSION_INFO"
        $s14 = "GetTempPath"
        $s15 = "mscoree.dll"
        $s16 = "Translation"
        $s17 = "FileVersion"
        $s18 = "InternalName"
        $s19 = "Environment"
        $s20 = "System.IO"
condition:
    uint16(0) == 0x5a4d and filesize < 9KB and
    4 of them
}
    
