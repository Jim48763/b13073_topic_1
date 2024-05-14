import pe
rule acbadcaadbdcfeafbeadbbfdcaf_dll {
strings:
        $s1 = "cross device link"
        $s2 = "CreateThreadpoolTimer"
        $s3 = "<dev:version></dev:version>"
        $s4 = "executable format error"
        $s5 = "result out of range"
        $s6 = "directory not empty"
        $s7 = "invalid string position"
        $s8 = "operation canceled"
        $s9 = "LC_MONETARY"
        $s10 = "VarFileInfo"
        $s11 = "ProductName"
        $s12 = "tdognmp; -e"
        $s13 = "sie:>c7l1mp"
        $s14 = "ity</maml:name>"
        $s15 = "FileDescription"
        $s16 = "`local vftable'"
        $s17 = "spanish-venezuela"
        $s18 = "rray'.&quot;.   "
        $s19 = "GetModuleHandleA"
        $s20 = "SetFilePointerEx"
condition:
    uint16(0) == 0x5a4d and filesize < 853KB and
    4 of them
}
    
rule bcbaeacfcecdbafadaadeecca_exe {
strings:
        $s1 = "german-luxembourg"
        $s2 = "spanish-guatemala"
        $s3 = "Runtime Error!"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "CopyFileExW"
        $s6 = "VirtualLock"
        $s7 = "LC_MONETARY"
        $s8 = "VarFileInfo"
        $s9 = "spanish-venezuela"
        $s10 = "GetComputerNameW"
        $s11 = "TerminateProcess"
        $s12 = "GetModuleHandleW"
        $s13 = "GetCurrentDirectoryW"
        $s14 = "WriteProfileStringW"
        $s15 = "SetConsoleCursorInfo"
        $s16 = "ContinueDebugEvent"
        $s17 = "south-africa"
        $s18 = "GetLocalTime"
        $s19 = "RYSZQ[PYVXOu"
        $s20 = "GetTickCount"
condition:
    uint16(0) == 0x5a4d and filesize < 181KB and
    4 of them
}
    
rule baffbbaefbcbfdbbdbaed_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "S-K=`5n&+\""
        $s3 = "VarFileInfo"
        $s4 = "bomgpiaruci.iwa"
        $s5 = "AFX_DIALOG_LAYOUT"
        $s6 = "Dad zupabozusojay"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "GetCurrentThreadId"
        $s10 = "SetEndOfFile"
        $s11 = "GetTickCount"
        $s12 = "SetHandleCount"
        $s13 = "GetSystemTimeAsFileTime"
        $s14 = "InterlockedDecrement"
        $s15 = "VirtualProtect"
        $s16 = "GetProcessHeap"
        $s17 = "^/,aj\"P>S"
        $s18 = "IsProcessorFeaturePresent"
        $s19 = "GetCurrentProcess"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 164KB and
    4 of them
}
    
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
    