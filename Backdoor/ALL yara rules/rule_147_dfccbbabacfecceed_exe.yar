rule dfccbbabacfecceed_exe {
strings:
        $s1 = "ES_DISPLAY_REQUIRED"
        $s2 = "RuntimeHelpers"
        $s3 = "MarshalAsAttribute"
        $s4 = "RuntimeFieldHandle"
        $s5 = "STAThreadAttribute"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "SocketFlags"
        $s9 = "get_MachineName"
        $s10 = "FileDescription"
        $s11 = "Lime.Packets"
        $s12 = "programMutex"
        $s13 = "ComputerInfo"
        $s14 = "root\\SecurityCenter"
        $s15 = "StringBuilder"
        $s16 = "CompareMethod"
        $s17 = "PacketHandler"
        $s18 = "AddressFamily"
        $s19 = "TimerCallback"
        $s20 = "GetWindowText"
condition:
    uint16(0) == 0x5a4d and filesize < 29KB and
    4 of them
}
    
