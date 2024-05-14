rule fefefdbbddcececafdeaabafefddabcaeec_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "ProductName"
        $s3 = "_CorExeMain"
        $s4 = "get_MachineName"
        $s5 = "FileDescription"
        $s6 = "GetDirectoryName"
        $s7 = "BackgroundWorker"
        $s8 = "DirectorySeparatorChar"
        $s9 = "InitializeComponent"
        $s10 = "System.Net.Security"
        $s11 = "DecompressToDirectory"
        $s12 = "Synchronized"
        $s13 = "IAsyncResult"
        $s14 = "set_ShowIcon"
        $s15 = "System.Resources"
        $s16 = "DirectoryInfo"
        $s17 = "if-none-match"
        $s18 = "GeneratedCodeAttribute"
        $s19 = "application/json"
        $s20 = "defaultInstance"
condition:
    uint16(0) == 0x5a4d and filesize < 34KB and
    4 of them
}
    
