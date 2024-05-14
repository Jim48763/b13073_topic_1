rule daacaddbcacebccbbd_exe {
strings:
        $s1 = "Not enought space on "
        $s2 = "FileSystemAccessRule"
        $s3 = "executing error code: "
        $s4 = "RuntimeHelpers"
        $s5 = "GetProcessesByName"
        $s6 = "MozillaWindowClass"
        $s7 = "STAThreadAttribute"
        $s8 = "smethod_168"
        $s9 = "System.Linq"
        $s10 = "op_Equality"
        $s11 = "EnoughSpace"
        $s12 = "_CorExeMain"
        $s13 = "ComputeHash"
        $s14 = "BuildPacket"
        $s15 = "vlCb!FID1BK"
        $s16 = "ProductName"
        $s17 = "SocketFlags"
        $s18 = "IsWindowVisible"
        $s19 = "get_VolumeLabel"
        $s20 = "GetLastInputInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 197KB and
    4 of them
}
    
