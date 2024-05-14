rule eeeefbbebbfdeeacaeedaca_dll {
strings:
        $s1 = "Runtime Error!"
        $s2 = "SetConsoleCtrlHandler"
        $s3 = "SetConsoleOutputCP"
        $s4 = "LC_MONETARY"
        $s5 = "VarFileInfo"
        $s6 = "ProductName"
        $s7 = "xCa2I@&\"kV"
        $s8 = "mix.dll Saltice"
        $s9 = "FileDescription"
        $s10 = "`local vftable'"
        $s11 = "spanish-venezuela"
        $s12 = "ImageList_Create"
        $s13 = "GetModuleHandleA"
        $s14 = "TerminateProcess"
        $s15 = "south-africa"
        $s16 = "COMDLG32.dll"
        $s17 = " Govern with"
        $s18 = "GetTickCount"
        $s19 = "Necessary big"
        $s20 = "IsValidLocale"
condition:
    uint16(0) == 0x5a4d and filesize < 893KB and
    4 of them
}
    