rule cddbcafeacfcfffcee_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "SetConsoleCtrlHandler"
        $s3 = "4+-]S3whjW#"
        $s4 = "A4_vm'W{r7e"
        $s5 = "VarFileInfo"
        $s6 = "fohipuxejizokow"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "@GetSecondVice@0"
        $s10 = "EnterCriticalSection"
        $s11 = "WriteProcessMemory"
        $s12 = "Jarawud xopi"
        $s13 = "GetTickCount"
        $s14 = "~{X\"ydXKY(c"
        $s15 = "aDFq,F8?OE,-l"
        $s16 = "WaitCommEvent"
        $s17 = "AttachConsole"
        $s18 = "VerifyVersionInfoW"
        $s19 = "Votohoyidi raxiyaxog"
        $s20 = "CorExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 737KB and
    4 of them
}
    
