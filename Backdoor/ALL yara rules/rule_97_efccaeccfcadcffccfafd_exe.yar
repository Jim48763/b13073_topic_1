rule efccaeccfcadcffccfafd_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "RuntimeHelpers"
        $s3 = "set_ReceiveBufferSize"
        $s4 = "MarshalAsAttribute"
        $s5 = "lpVolumeNameBuffer"
        $s6 = "STAThreadAttribute"
        $s7 = "PixelFormat"
        $s8 = "ComputeHash"
        $s9 = "SocketFlags"
        $s10 = "op_Equality"
        $s11 = "_CorExeMain"
        $s12 = "get_MachineName"
        $s13 = "nVolumeNameSize"
        $s14 = "get_ServicePack"
        $s15 = "FileDescription"
        $s16 = "get_ProcessName"
        $s17 = "lpFileSystemFlags"
        $s18 = "ComputerInfo"
        $s19 = "Updating To "
        $s20 = "get_LastWriteTime"
condition:
    uint16(0) == 0x5a4d and filesize < 37KB and
    4 of them
}
    
