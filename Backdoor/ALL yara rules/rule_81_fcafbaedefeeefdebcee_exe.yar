rule fcafbaedefeeefdebcee_exe {
strings:
        $s1 = "ManagementBaseObject"
        $s2 = "ES_DISPLAY_REQUIRED"
        $s3 = "\\root\\SecurityCenter2"
        $s4 = "EnterDebugMode"
        $s5 = "RuntimeHelpers"
        $s6 = "set_ReceiveBufferSize"
        $s7 = "GetProcessesByName"
        $s8 = "STAThreadAttribute"
        $s9 = "PixelFormat"
        $s10 = "ComputeHash"
        $s11 = "My.Computer"
        $s12 = "SocketFlags"
        $s13 = "_CorExeMain"
        $s14 = "ThreadStaticAttribute"
        $s15 = "get_MachineName"
        $s16 = "_Lambda$__R13-2"
        $s17 = ":Zone.Identifier"
        $s18 = "DebuggerHiddenAttribute"
        $s19 = "SystemIdleTimerReset"
        $s20 = "ICredentials"
condition:
    uint16(0) == 0x5a4d and filesize < 33KB and
    4 of them
}
    
