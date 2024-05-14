rule badeeabafbfdecbfffcbddbaf_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "     name=\"wextract\""
        $s3 = "pJOo\"Ebn?."
        $s4 = "ProductName"
        $s5 = "u+Ek#LFe-{P"
        $s6 = "?aQM>\"l`I="
        $s7 = "LoadStringA"
        $s8 = "VarFileInfo"
        $s9 = "D+KzyW>@JMq"
        $s10 = "-6[MQWN iV#"
        $s11 = "FileDescription"
        $s12 = "Command.com /c %s"
        $s13 = "GetShortPathNameA"
        $s14 = "GetModuleHandleW"
        $s15 = "RemoveDirectoryA"
        $s16 = "TerminateProcess"
        $s17 = "Temporary folder"
        $s18 = "DispatchMessageA"
        $s19 = "SetCurrentDirectoryA"
        $s20 = "Microsoft Corporation"
condition:
    uint16(0) == 0x5a4d and filesize < 1312KB and
    4 of them
}
    
