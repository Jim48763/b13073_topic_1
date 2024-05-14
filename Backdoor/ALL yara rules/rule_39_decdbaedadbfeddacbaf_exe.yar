rule decdbaedadbfeddacbaf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "Clients\\StartMenuInternet\\"
        $s3 = "AuthenticationMode"
        $s4 = "lpVolumeNameBuffer"
        $s5 = "STAThreadAttribute"
        $s6 = "DesignerGeneratedAttribute"
        $s7 = "ProductName"
        $s8 = "FalseString"
        $s9 = "LastIndexOf"
        $s10 = "ComputeHash"
        $s11 = "My.Computer"
        $s12 = "PluginBytes"
        $s13 = "_CorExeMain"
        $s14 = "ThreadStaticAttribute"
        $s15 = "FlushFinalBlock"
        $s16 = "ProgramList.txt"
        $s17 = "/upload.php?id="
        $s18 = "nVolumeNameSize"
        $s19 = "set_MinimizeBox"
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 38KB and
    4 of them
}
    
