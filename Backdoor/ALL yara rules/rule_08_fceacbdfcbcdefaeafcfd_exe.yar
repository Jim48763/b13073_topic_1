rule fceacbdfcbcdefaeafcfd_exe {
strings:
        $s1 = "AutoPropertyValue"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "ProductName"
        $s5 = "My.Computer"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "ThreadStaticAttribute"
        $s9 = "FlushFinalBlock"
        $s10 = "FileDescription"
        $s11 = "GetConsoleWindow"
        $s12 = "\\MyTemp\\Torrent.exe"
        $s13 = "Synchronized"
        $s14 = "System.Resources"
        $s15 = "GeneratedCodeAttribute"
        $s16 = "NewLateBinding"
        $s17 = "ReferenceEquals"
        $s18 = "Dispose__Instance__"
        $s19 = "MyWebServices"
        $s20 = "get_FileSystem"
condition:
    uint16(0) == 0x5a4d and filesize < 20KB and
    4 of them
}
    
