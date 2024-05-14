rule cbdfaacafecbfedeefecfccaedce_exe {
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
        $s14 = "v3.5 Public"
        $s15 = "My.Computer"
        $s16 = "NewWatchdog"
        $s17 = "SocketFlags"
        $s18 = "op_Equality"
        $s19 = "PluginBytes"
        $s20 = "_CorExeMain"
condition:
    uint16(0) == 0x5a4d and filesize < 90KB and
    4 of them
}
    
