rule babadeceabefedcdabebfecf_exe {
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
        $s11 = "GetComputerNameA"
        $s12 = "audioendpointbuilder"
        $s13 = "EnterCriticalSection"
        $s14 = "SetCurrentDirectoryW"
        $s15 = "=========== post FINDFILES 1 end"
        $s16 = "GetCurrentThreadId"
        $s17 = "CreateCompatibleDC"
        $s18 = "QBIDPService"
        $s19 = "MSSQL$ECWDB2"
        $s20 = "GetLocalTime"
condition:
    uint16(0) == 0x5a4d and filesize < 160KB and
    4 of them
}
    
