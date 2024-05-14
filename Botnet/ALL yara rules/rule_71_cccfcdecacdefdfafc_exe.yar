rule cccfcdecacdefdfafc_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "`vector destructor iterator'"
        $s3 = "GetSystemPowerStatus"
        $s4 = "CreateIoCompletionPort"
        $s5 = "<file unknown>"
        $s6 = "invalid string position"
        $s7 = "GetConsoleOutputCP"
        $s8 = "6+G{%#rDbm:"
        $s9 = "f`RSXv\":!m"
        $s10 = "`N&^c,s*Az:"
        $s11 = "VarFileInfo"
        $s12 = "JO]_8^mwXZs"
        $s13 = "q0=.'hx@-}]"
        $s14 = "`local vftable'"
        $s15 = "TerminateProcess"
        $s16 = "CreateJobObjectW"
        $s17 = "SetComputerNameA"
        $s18 = "GetModuleHandleW"
        $s19 = "GetConsoleSelectionInfo"
        $s20 = "EnterCriticalSection"
condition:
    uint16(0) == 0x5a4d and filesize < 823KB and
    4 of them
}
    
