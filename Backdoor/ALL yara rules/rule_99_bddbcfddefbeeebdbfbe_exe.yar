rule bddbcfddefbeeebdbfbe_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "My.Computer"
        $s4 = "SocketFlags"
        $s5 = "_CorExeMain"
        $s6 = "ThreadStaticAttribute"
        $s7 = "get_MachineName"
        $s8 = "FileDescription"
        $s9 = "Add Plugin ERROR"
        $s10 = "DebuggerHiddenAttribute"
        $s11 = "ComputerInfo"
        $s12 = "Updating To "
        $s13 = "get_LastWriteTime"
        $s14 = "DirectoryInfo"
        $s15 = "StringBuilder"
        $s16 = "GetWindowText"
        $s17 = "CompareMethod"
        $s18 = "GetFolderPath"
        $s19 = "SpecialFolder"
        $s20 = "GeneratedCodeAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 35KB and
    4 of them
}
    
