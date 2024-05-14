import pe
rule fbcaffbafadbedceaaecceba_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "Per Primitiva Vice Os"
        $s3 = "CreateIoCompletionPort"
        $s4 = "<dependency><dependentAssembly>"
        $s5 = ";!@EnstallEnd@!Rar!"
        $s6 = "112 North Curry Street1"
        $s7 = "utj\"j Pj:h0GA"
        $s8 = "gvceXcfUhq.com"
        $s9 = "_beginthreadex"
        $s10 = "Montrovorto Tia Ci Kabo"
        $s11 = "PD1/wL&pb\""
        $s12 = "F+P1oQ*5;$K"
        $s13 = "Vg!onr%cP(:"
        $s14 = "BeginPrompt"
        $s15 = "'x nL5;CT8_"
        $s16 = ":vBy=M|c3tI"
        $s17 = "{Lxvg0d~X*."
        $s18 = "VarFileInfo"
        $s19 = ".M}O]?!3I%d"
        $s20 = "MyDocuments"
condition:
    uint16(0) == 0x5a4d and filesize < 1819KB and
    4 of them
}
    
rule dfbcedaafcebbeeddebaaab_exe {
strings:
        $s1 = "Directory not empty"
        $s2 = "Runtime Error!"
        $s3 = "invalid string position"
        $s4 = "No child processes"
        $s5 = "9QM;F@TW\"$"
        $s6 = "LC_MONETARY"
        $s7 = "VarFileInfo"
        $s8 = "`local vftable'"
        $s9 = "spanish-venezuela"
        $s10 = "GetModuleHandleA"
        $s11 = "TerminateProcess"
        $s12 = "RemoveDirectoryW"
        $s13 = "Operation not permitted"
        $s14 = "GetCurrentThreadId"
        $s15 = "No locks available"
        $s16 = "SetEndOfFile"
        $s17 = "south-africa"
        $s18 = "Invalid seek"
        $s19 = "GetTickCount"
        $s20 = "IsValidLocale"
condition:
    uint16(0) == 0x5a4d and filesize < 310KB and
    4 of them
}
    
rule dbceffefdbdfccefdefba_exe {
strings:
        $s1 = "_vsnprintf_helper"
        $s2 = "(ch != _T('\\0'))"
        $s3 = "CreateIoCompletionPort"
        $s4 = "<file unknown>"
        $s5 = "Runtime Error!"
        $s6 = "VarFileInfo"
        $s7 = "SetVolumeLabelW"
        $s8 = "`local vftable'"
        $s9 = "TerminateProcess"
        $s10 = "GetModuleHandleW"
        $s11 = "GetCurrentDirectoryA"
        $s12 = "(((_Src))) != NULL"
        $s13 = "GetCurrentThreadId"
        $s14 = "Expression: "
        $s15 = "q.O|q]velI\""
        $s16 = ",LUzD8eJU+1c"
        $s17 = "GetTickCount"
        $s18 = "SetConsoleCursorPosition"
        $s19 = "(buf != NULL)"
        $s20 = "_write_nolock"
condition:
    uint16(0) == 0x5a4d and filesize < 366KB and
    4 of them
}
    
rule bbbeccfaedabdceaefeccbbdf_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "     name=\"wextract\""
        $s3 = "RegSetValueExA"
        $s4 = "LoadStringA"
        $s5 = "UDryIohQ\"2"
        $s6 = "M+Zu1!kIC\""
        $s7 = "&}DS,Tp_CnO"
        $s8 = "VarFileInfo"
        $s9 = "ProductName"
        $s10 = "FileDescription"
        $s11 = "GetShortPathNameA"
        $s12 = "Command.com /c %s"
        $s13 = "RemoveDirectoryA"
        $s14 = "DispatchMessageA"
        $s15 = "GetModuleHandleA"
        $s16 = "Temporary folder"
        $s17 = "GetCurrentDirectoryA"
        $s18 = "Do you want to continue?"
        $s19 = "GetCurrentThreadId"
        $s20 = "DecryptFileA"
condition:
    uint16(0) == 0x5a4d and filesize < 996KB and
    4 of them
}
    