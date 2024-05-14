rule cdbbdbfeacabcebdddfecaac_exe {
strings:
        $s1 = "_vsnprintf_helper"
        $s2 = "(ch != _T('\\0'))"
        $s3 = "GetEnvironmentStrings"
        $s4 = "4!   78/&74:'E6 66NI"
        $s5 = "<file unknown>"
        $s6 = "invalid string position"
        $s7 = "3!8'856 A?;4 !&455"
        $s8 = "GetConsoleOutputCP"
        $s9 = "_Locale != NULL"
        $s10 = "`local vftable'"
        $s11 = "Dialog Box: Modal"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "&  77>76M,:<6kpu"
        $s15 = "InitializeCriticalSection"
        $s16 = "(((_Src))) != NULL"
        $s17 = "GetCurrentThreadId"
        $s18 = "GetTickCount"
        $s19 = "Expression: "
        $s20 = ">N6;  7&XP9E"
condition:
    uint16(0) == 0x5a4d and filesize < 293KB and
    4 of them
}
    
