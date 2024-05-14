import pe
rule accfdbbfecaddcaeedad_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "invalid string position"
        $s3 = "GetConsoleOutputCP"
        $s4 = "VarFileInfo"
        $s5 = "`local vftable'"
        $s6 = "TerminateProcess"
        $s7 = "GetModuleHandleW"
        $s8 = "GetCurrentThreadId"
        $s9 = "WriteProcessMemory"
        $s10 = "GetTickCount"
        $s11 = "AttachConsole"
        $s12 = "Unknown exception"
        $s13 = "SetHandleCount"
        $s14 = "CreateMailslotA"
        $s15 = "`udt returning'"
        $s16 = "SetTapePosition"
        $s17 = "GetFileAttributesW"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "InterlockedDecrement"
        $s20 = "GetConsoleTitleA"
condition:
    uint16(0) == 0x5a4d and filesize < 364KB and
    4 of them
}
    
rule cbdbacbebbedbedbcbcbd_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "invalid string position"
        $s3 = "SetConsoleCtrlHandler"
        $s4 = "GetConsoleOutputCP"
        $s5 = "VarFileInfo"
        $s6 = "`local vftable'"
        $s7 = "AFX_DIALOG_LAYOUT"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleW"
        $s10 = "InitializeCriticalSection"
        $s11 = "GetCurrentThreadId"
        $s12 = "WriteProcessMemory"
        $s13 = "GetTickCount"
        $s14 = "Unknown exception"
        $s15 = "SetHandleCount"
        $s16 = "CreateMailslotW"
        $s17 = "`udt returning'"
        $s18 = "SetTapePosition"
        $s19 = "GenerateConsoleCtrlEvent"
        $s20 = "GetSystemTimeAsFileTime"
condition:
    uint16(0) == 0x5a4d and filesize < 282KB and
    4 of them
}
    
rule dddfdbbffeebdfbfcdecadbfacece_exe {
strings:
        $s1 = "cross device link"
        $s2 = "CreateThreadpoolTimer"
        $s3 = "executable format error"
        $s4 = "result out of range"
        $s5 = "directory not empty"
        $s6 = "invalid string position"
        $s7 = "operation canceled"
        $s8 = "LC_MONETARY"
        $s9 = "`local vftable'"
        $s10 = "spanish-venezuela"
        $s11 = "Result matrix is "
        $s12 = "ContextStackSize"
        $s13 = "SetFilePointerEx"
        $s14 = "TerminateProcess"
        $s15 = "GetModuleHandleW"
        $s16 = "destination address required"
        $s17 = "SetEndOfFile"
        $s18 = "south-africa"
        $s19 = "resource deadlock would occur"
        $s20 = "device or resource busy"
condition:
    uint16(0) == 0x5a4d and filesize < 315KB and
    4 of them
}
    