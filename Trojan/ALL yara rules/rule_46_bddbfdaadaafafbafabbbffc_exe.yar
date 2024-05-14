rule bddbfdaadaafafbafabbbffc_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "_CorExeMain"
        $s3 = "ProductName"
        $s4 = "FileDescription"
        $s5 = "GetFolderPath"
        $s6 = "SpecialFolder"
        $s7 = "StructLayoutAttribute"
        $s8 = "GetFullExeRunner"
        $s9 = "LayoutKind"
        $s10 = "set_UseShellExecute"
        $s11 = "IDisposable"
        $s12 = "DESCRIPTION"
        $s13 = "</assembly>"
        $s14 = "get_Location"
        $s15 = "OutBuild.exe"
        $s16 = "RunFromAdmin"
        $s17 = "WriteAllBytes"
        $s18 = "chcp 866 >NUL"
        $s19 = "    <security>"
        $s20 = "OriginalFilename"
condition:
    uint16(0) == 0x5a4d and filesize < 6713KB and
    4 of them
}
    
