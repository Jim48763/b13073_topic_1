rule bfdcebbefaceefafeecfcdffefdb_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "FreeUserPhysicalPages"
        $s3 = "CreateIoCompletionPort"
        $s4 = "<file unknown>"
        $s5 = "1A1F1K1'2,21262+324>4k4p4u4"
        $s6 = "GetConsoleOutputCP"
        $s7 = "@2/XQ'fZT(;"
        $s8 = "VarFileInfo"
        $s9 = " UwASv7hF_s"
        $s10 = "CopyFileExA"
        $s11 = "2-:o<QrLx9C"
        $s12 = "`local vftable'"
        $s13 = "Process32FirstW"
        $s14 = "SetVolumeLabelA"
        $s15 = "SetComputerNameW"
        $s16 = "GetModuleHandleA"
        $s17 = "TerminateProcess"
        $s18 = "GetCurrentDirectoryA"
        $s19 = "Bid der rijef tikaw"
        $s20 = "SetConsoleCursorInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 840KB and
    4 of them
}
    
