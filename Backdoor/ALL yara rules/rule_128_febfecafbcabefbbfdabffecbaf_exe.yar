rule febfecafbcabefbbfdabffecbaf_exe {
strings:
        $s1 = "set_SevenOrHigher"
        $s2 = "GetKeyboardLayout"
        $s3 = "set_MonikerString"
        $s4 = "get_IsTerminating"
        $s5 = "GetWebcamResponse"
        $s6 = "set_usernameField"
        $s7 = "MakeGenericMethod"
        $s8 = "IPInterfaceProperties"
        $s9 = "Key can not be empty."
        $s10 = "GetSystemInfoResponse"
        $s11 = "keyboardStateNative"
        $s12 = "get_UnicastAddresses"
        $s13 = "DeletePath I/O error"
        $s14 = "DictionarySerializer"
        $s15 = "GetDrives No drives"
        $s16 = "ElapsedEventHandler"
        $s17 = "TemporalCompression"
        $s18 = "GetSubKeyNames"
        $s19 = "FlagsAttribute"
        $s20 = "Executed File!"
condition:
    uint16(0) == 0x5a4d and filesize < 353KB and
    4 of them
}
    
