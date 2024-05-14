rule cfadeafddaacbeabedcbcfddfec_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "RuntimeHelpers"
        $s3 = "set_ReceiveBufferSize"
        $s4 = "lpVolumeNameBuffer"
        $s5 = "STAThreadAttribute"
        $s6 = "PixelFormat"
        $s7 = "ComputeHash"
        $s8 = "SocketFlags"
        $s9 = "op_Equality"
        $s10 = "_CorExeMain"
        $s11 = "get_MachineName"
        $s12 = "nVolumeNameSize"
        $s13 = "get_ServicePack"
        $s14 = "get_ProcessName"
        $s15 = "lpFileSystemFlags"
        $s16 = "karinepidh.ddns.net"
        $s17 = "get_Keyboard"
        $s18 = "ComputerInfo"
        $s19 = "Updating To "
        $s20 = "get_LastWriteTime"
condition:
    uint16(0) == 0x5a4d and filesize < 28KB and
    4 of them
}
    
