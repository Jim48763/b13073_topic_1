rule eebddeebafccbaedaeaebe_exe {
strings:
        $s1 = "==333///>7..++::<<<<,,,,,,,88888------***-."
        $s2 = "ES_DISPLAY_REQUIRED"
        $s3 = "\\root\\SecurityCenter2"
        $s4 = "EnterDebugMode"
        $s5 = "RuntimeHelpers"
        $s6 = "^z2333//////////74+666666665<,))*****@&&B"
        $s7 = "set_ReceiveBufferSize"
        $s8 = "GetProcessesByName"
        $s9 = "STAThreadAttribute"
        $s10 = "My.Computer"
        $s11 = "_CorExeMain"
        $s12 = "ComputeHash"
        $s13 = "PixelFormat"
        $s14 = "SocketFlags"
        $s15 = "ThreadStaticAttribute"
        $s16 = "get_MachineName"
        $s17 = ":Zone.Identifier"
        $s18 = "DebuggerHiddenAttribute"
        $s19 = "SystemIdleTimerReset"
        $s20 = "ICredentials"
condition:
    uint16(0) == 0x5a4d and filesize < 369KB and
    4 of them
}
    
