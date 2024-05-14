rule cbeabafabadcabdabadefabac_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "GetSystemPowerStatus"
        $s3 = "Runtime Error!"
        $s4 = "invalid string position"
        $s5 = "ProductName"
        $s6 = "\"1'%4!z7L:"
        $s7 = "#2 +%4!y6L9"
        $s8 = "VarFileInfo"
        $s9 = "v!xD~sU)-7("
        $s10 = "\"7F_-EjXVO"
        $s11 = "&6#*%3 m4K8"
        $s12 = "`local vftable'"
        $s13 = "FileDescription"
        $s14 = "phoneGetStatusA"
        $s15 = "SetDIBitsToDevice"
        $s16 = "DispatchMessageA"
        $s17 = "TerminateProcess"
        $s18 = "GetModuleHandleA"
        $s19 = "GetCurrentThreadId"
        $s20 = "PrivateBuild"
condition:
    uint16(0) == 0x5a4d and filesize < 253KB and
    4 of them
}
    
