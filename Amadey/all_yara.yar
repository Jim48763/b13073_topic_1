import pe
rule cecdbdabbaefeceaeffbeea_exe {
strings:
        $s1 = "GetFileAttributesExA"
        $s2 = "<file unknown>"
        $s3 = "invalid string position"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "VarFileInfo"
        $s6 = "`local vftable'"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "invalid iterator range"
        $s10 = "EnterCriticalSection"
        $s11 = "GetConsoleCursorInfo"
        $s12 = "GetConsoleAliasesW"
        $s13 = "(((_Src))) != NULL"
        $s14 = "Expression: "
        $s15 = "SetEndOfFile"
        $s16 = "GetTickCount"
        $s17 = "sizeInBytes > retsize"
        $s18 = "g_controlfp_s"
        $s19 = "2 <= radix && radix <= 36"
        $s20 = "Unknown exception"
condition:
    uint16(0) == 0x5a4d and filesize < 342KB and
    4 of them
}
    
rule beadeaeccfccdbfcea_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "english-caribbean"
        $s3 = "invalid string position"
        $s4 = "GetConsoleOutputCP"
        $s5 = "LC_MONETARY"
        $s6 = "rnJZ, eDNw'"
        $s7 = "`local vftable'"
        $s8 = "english-jamaica"
        $s9 = "spanish-venezuela"
        $s10 = "chinese-singapore"
        $s11 = "TerminateProcess"
        $s12 = "GetModuleHandleW"
        $s13 = "EnterCriticalSection"
        $s14 = "GetCurrentDirectoryA"
        $s15 = "SetEndOfFile"
        $s16 = "SetLocalTime"
        $s17 = "south africa"
        $s18 = "GetTickCount"
        $s19 = "IsBadWritePtr"
        $s20 = "Unknown exception"
condition:
    uint16(0) == 0x5a4d and filesize < 237KB and
    4 of them
}
    
rule aababcecabbdebceaeabddacdadb_exe {
strings:
        $s1 = "Invalid filename."
        $s2 = "GetEnvironmentStrings"
        $s3 = "RegSetValueExA"
        $s4 = "CoRegisterMessageFilter"
        $s5 = "ProductName"
        $s6 = "LoadStringA"
        $s7 = "VarFileInfo"
        $s8 = "Link Source"
        $s9 = "FileDescription"
        $s10 = "GetThreadLocale"
        $s11 = ".?AVCClientDC@@"
        $s12 = "IsWindowVisible"
        $s13 = "TerminateProcess"
        $s14 = "UnregisterClassA"
        $s15 = "DispatchMessageA"
        $s16 = "GetModuleHandleA"
        $s17 = "EnterCriticalSection"
        $s18 = "Magnification Factor"
        $s19 = "z{}|wx{|uvy|uvx|uvx|tux|pqsd"
        $s20 = "mnqdrsv|stv|tux|uvy|vwy|yz||"
condition:
    uint16(0) == 0x5a4d and filesize < 441KB and
    4 of them
}
    
rule cabdbfeffcabadfbafaebcdddcceddb_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = ")iiig_b``\"%%\"1[>>"
        $s3 = "RegSetValueExA"
        $s4 = "ProductName"
        $s5 = "eqU-OdL';A0"
        $s6 = "VarFileInfo"
        $s7 = "FileDescription"
        $s8 = "DeviceIoControl"
        $s9 = "DestroyPropertySheetPage"
        $s10 = "TerminateProcess"
        $s11 = "GetModuleHandleW"
        $s12 = "UnregisterHotKey"
        $s13 = "EnterCriticalSection"
        $s14 = "UnhookWindowsHookEx"
        $s15 = "+&wvs4`\\G?f"
        $s16 = "GetTickCount"
        $s17 = "SetupCloseLog"
        $s18 = "CorExitProcess"
        $s19 = "SetHandleCount"
        $s20 = "CertStrToNameA"
condition:
    uint16(0) == 0x5a4d and filesize < 469KB and
    4 of them
}
    
rule bfdcebbeebebafbffffaaed_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "invalid string position"
        $s3 = "GetConsoleOutputCP"
        $s4 = "p|\"oy+4Ydg"
        $s5 = "`local vftable'"
        $s6 = "TerminateProcess"
        $s7 = "CreateJobObjectW"
        $s8 = "GetModuleHandleW"
        $s9 = "EnterCriticalSection"
        $s10 = "SetCurrentDirectoryA"
        $s11 = "SetEndOfFile"
        $s12 = "SetLocalTime"
        $s13 = "GetTickCount"
        $s14 = "Unknown exception"
        $s15 = "CallNamedPipeW"
        $s16 = "SetHandleCount"
        $s17 = "`udt returning'"
        $s18 = "Greater Manchester1"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "InterlockedDecrement"
condition:
    uint16(0) == 0x5a4d and filesize < 203KB and
    4 of them
}
    
rule baaaeabdaebeceebaedfbc_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "ProductName"
        $s5 = ")7`SvJ1+yQC"
        $s6 = "%.R=vX2d!bF"
        $s7 = "VarFileInfo"
        $s8 = "Us6h(]PDK|A"
        $s9 = "FileDescription"
        $s10 = "DialogBoxParamA"
        $s11 = "GetShortPathNameA"
        $s12 = "RemoveDirectoryA"
        $s13 = "DispatchMessageA"
        $s14 = "GetModuleHandleA"
        $s15 = "SHBrowseForFolderA"
        $s16 = "EnableWindow"
        $s17 = "GetTickCount"
        $s18 = "RegEnumValueA"
        $s19 = "IIDFromString"
        $s20 = "SysListView32"
condition:
    uint16(0) == 0x5a4d and filesize < 241KB and
    4 of them
}
    
rule dbaefdbdcfbcbcbacfdbfadddab_exe {
strings:
        $s1 = "`local vftable'"
        $s2 = "GetComputerNameA"
        $s3 = "GetModuleHandleW"
        $s4 = "TerminateProcess"
        $s5 = "EnterCriticalSection"
        $s6 = "GetCurrentThreadId"
        $s7 = "SetEndOfFile"
        $s8 = "GetTickCount"
        $s9 = "GetSystemInfo"
        $s10 = "Unknown exception"
        $s11 = "SetHandleCount"
        $s12 = "`udt returning'"
        $s13 = "GetSystemTimeAsFileTime"
        $s14 = "InterlockedDecrement"
        $s15 = "GetProcessHeap"
        $s16 = "IsProcessorFeaturePresent"
        $s17 = "GetCurrentProcess"
        $s18 = "GetSystemMetrics"
        $s19 = "CreateDirectoryA"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 72KB and
    4 of them
}
    