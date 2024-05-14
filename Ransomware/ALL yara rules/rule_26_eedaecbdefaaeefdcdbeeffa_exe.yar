rule eedaecbdefaaeefdcdbeeffa_exe {
strings:
        $s1 = "fdlauncher.exe"
        $s2 = "VMwareHostd"
        $s3 = "SQLAgent$TPSAMA"
        $s4 = "VeeamCatalogSvc"
        $s5 = "McAfeeFrameworkMcAfeeFramework"
        $s6 = "McAfeeFramework"
        $s7 = "MBEndpointAgent"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleW"
        $s10 = "mydesktopqos.exe"
        $s11 = "audioendpointbuilder"
        $s12 = "EnterCriticalSection"
        $s13 = "SetCurrentDirectoryW"
        $s14 = "=========== post FINDFILES 1 end"
        $s15 = "GetCurrentThreadId"
        $s16 = "CreateCompatibleDC"
        $s17 = "QBIDPService"
        $s18 = "MSSQL$ECWDB2"
        $s19 = "GetLocalTime"
        $s20 = "FA_Scheduler"
condition:
    uint16(0) == 0x5a4d and filesize < 156KB and
    4 of them
}
    
