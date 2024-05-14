rule feadddeddaeebdfcabdbbddbaaa_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "GetConsoleProcessList"
        $s3 = "GetConsoleOutputCP"
        $s4 = "VarFileInfo"
        $s5 = "GetComputerNameW"
        $s6 = "TerminateProcess"
        $s7 = "JDF:DOOOK>;:@PN5"
        $s8 = "GetModuleHandleW"
        $s9 = "GetCurrentThreadId"
        $s10 = "GetTickCount"
        $s11 = "bomgveoci.iwa"
        $s12 = "C:\\xetel.pdb"
        $s13 = "VpTTRQPPMHHLHLHSw,"
        $s14 = "SetHandleCount"
        $s15 = "ProjectVersion"
        $s16 = "GetSystemTimeAsFileTime"
        $s17 = "InterlockedDecrement"
        $s18 = "GetConsoleTitleW"
        $s19 = ")',857\"75 107"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 356KB and
    4 of them
}
    
