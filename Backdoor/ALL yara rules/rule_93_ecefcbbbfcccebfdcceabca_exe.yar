rule ecefcbbbfcccebfdcceabca_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "Directory not empty"
        $s3 = "No child processes"
        $s4 = "GetConsoleOutputCP"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "FileDescription"
        $s8 = "`local vftable'"
        $s9 = "TerminateProcess"
        $s10 = "ConsoleApp42.exe"
        $s11 = "GetModuleHandleW"
        $s12 = "Operation not permitted"
        $s13 = "EnterCriticalSection"
        $s14 = "No locks available"
        $s15 = "SetEndOfFile"
        $s16 = "Module32Next"
        $s17 = "Invalid seek"
        $s18 = "OLEAUT32.dll"
        $s19 = "GetTickCount"
        $s20 = "Improper link"
condition:
    uint16(0) == 0x5a4d and filesize < 188KB and
    4 of them
}
    
