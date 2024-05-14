rule fccabecbebcdeecadbcafdecaddbb_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "Newtonsoft.Json.dll"
        $s3 = "\\root\\SecurityCenter2"
        $s4 = "RuntimeHelpers"
        $s5 = "Clients\\StartMenuInternet\\"
        $s6 = "GetProcessesByName"
        $s7 = "AuthenticationMode"
        $s8 = "lpVolumeNameBuffer"
        $s9 = "STAThreadAttribute"
        $s10 = "DesignerGeneratedAttribute"
        $s11 = "ProductName"
        $s12 = "LastIndexOf"
        $s13 = "ComputeHash"
        $s14 = "My.Computer"
        $s15 = "NewWatchdog"
        $s16 = "SocketFlags"
        $s17 = "op_Equality"
        $s18 = "PluginBytes"
        $s19 = "_CorExeMain"
        $s20 = "ThreadStaticAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 88KB and
    4 of them
}
    
