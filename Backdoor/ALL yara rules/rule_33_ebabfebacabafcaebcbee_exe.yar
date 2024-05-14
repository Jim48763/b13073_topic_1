rule ebabfebacabafcaebcbee_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "\\root\\SecurityCenter2"
        $s3 = "RuntimeHelpers"
        $s4 = "Clients\\StartMenuInternet\\"
        $s5 = "GetProcessesByName"
        $s6 = "lpVolumeNameBuffer"
        $s7 = "STAThreadAttribute"
        $s8 = "AuthenticationMode"
        $s9 = "DesignerGeneratedAttribute"
        $s10 = "LastIndexOf"
        $s11 = "My.Computer"
        $s12 = "op_Equality"
        $s13 = "PluginBytes"
        $s14 = "_CorExeMain"
        $s15 = "AES_Decrypt"
        $s16 = "ComputeHash"
        $s17 = "ProductName"
        $s18 = "NewWatchdog"
        $s19 = "SocketFlags"
        $s20 = "ThreadStaticAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 104KB and
    4 of them
}
    
