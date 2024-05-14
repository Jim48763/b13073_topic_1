rule dcdbcccdfcafbfdc_exe {
strings:
        $s1 = "HSHELL_APPCOMMAND"
        $s2 = "Not enought space on "
        $s3 = "WaitForServerMessage"
        $s4 = "get_BytesTransferred"
        $s5 = "ReceiveServerAfkSystem"
        $s6 = "executing error code: "
        $s7 = "ElapsedEventHandler"
        $s8 = "RuntimeHelpers"
        $s9 = "SocketArgsPool"
        $s10 = "SPI_GETSCREENSAVERRUNNING"
        $s11 = "set_ReceiveBufferSize"
        $s12 = "GetProcessesByName"
        $s13 = "MozillaWindowClass"
        $s14 = "STAThreadAttribute"
        $s15 = "FromMinutes"
        $s16 = "System.Linq"
        $s17 = "op_Equality"
        $s18 = "_CorExeMain"
        $s19 = "ComputeHash"
        $s20 = "BuildPacket"
condition:
    uint16(0) == 0x5a4d and filesize < 85KB and
    4 of them
}
    
