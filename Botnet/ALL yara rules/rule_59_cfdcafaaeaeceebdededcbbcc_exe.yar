rule cfdcafaaeaeceebdededcbbcc_exe {
strings:
        $s1 = "SetConsoleCtrlHandler"
        $s2 = "z87{j+%5`46"
        $s3 = "<?74E.yDFfX"
        $s4 = "(:j+%5`AkmT"
        $s5 = "DllGetClassObject"
        $s6 = "TerminateProcess"
        $s7 = "MergeFontPackage"
        $s8 = "GetComputerNameA"
        $s9 = "GetModuleHandleA"
        $s10 = "EnterCriticalSection"
        $s11 = "]}-1a1N%{&ou"
        $s12 = "GetLocalTime"
        $s13 = "OL_s?5g88640"
        $s14 = "GetTickCount"
        $s15 = "AJTrY$<4<7h["
        $s16 = "GetThreadContext"
        $s17 = "SetConsoleCursorPosition"
        $s18 = "6lsNC%j+%5`$$"
        $s19 = "F:\\kobus.pdb"
        $s20 = "SuspendThread"
condition:
    uint16(0) == 0x5a4d and filesize < 332KB and
    4 of them
}
    
