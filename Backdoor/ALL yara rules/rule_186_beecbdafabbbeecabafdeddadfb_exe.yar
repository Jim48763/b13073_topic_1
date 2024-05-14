rule beecbdafabbbeecabafdeddadfb_exe {
strings:
        $s1 = "set_SevenOrHigher"
        $s2 = "GetKeyboardLayout"
        $s3 = "set_MonikerString"
        $s4 = "Chrome Copyright "
        $s5 = "get_IsTerminating"
        $s6 = "GetWebcamResponse"
        $s7 = "MakeGenericMethod"
        $s8 = "IPInterfaceProperties"
        $s9 = "System.ServiceProcess"
        $s10 = "Key can not be empty."
        $s11 = "Listening for connection ..."
        $s12 = "keyboardStateNative"
        $s13 = "TaskManagerParentAddress"
        $s14 = "get_UnicastAddresses"
        $s15 = "DeletePath I/O error"
        $s16 = "FileSystemAccessRule"
        $s17 = "remove_DataAvailable"
        $s18 = "DictionarySerializer"
        $s19 = "GetDrives No drives"
        $s20 = "ElapsedEventHandler"
condition:
    uint16(0) == 0x5a4d and filesize < 539KB and
    4 of them
}
    
