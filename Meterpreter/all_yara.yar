import pe
rule deaaaebebfaacaaeef_exe {
strings:
        $s1 = "Too many open sockets"
        $s2 = "    -S              Do not show confidence estimators and warnings."
        $s3 = "    -z attributes   String to insert as td or th attributes"
        $s4 = "Directory not empty"
        $s5 = "The specified thread is detached"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "LOG: header received:"
        $s9 = "DeviceIoControl"
        $s10 = "FileDescription"
        $s11 = "Connection reset by peer"
        $s12 = "Non-2xx responses:      %d"
        $s13 = "TerminateProcess"
        $s14 = "Content-type: %s"
        $s15 = "InitializeCriticalSection"
        $s16 = "Too many processes"
        $s17 = "Address already in use"
        $s18 = " !\"#$%&'()*+,-./0123@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s19 = "Total:      %5I64d %5I64d%5I64d"
        $s20 = "    -n requests     Number of requests to perform"
condition:
    uint16(0) == 0x5a4d and filesize < 77KB and
    4 of them
}
    
rule bfdfdffcbccdfbbddeacaacffbdfad_ps {
strings:
        $s1 = "function lC {"
        $s2 = "Param ("
condition:
    uint16(0) == 0x5a4d and filesize < 10KB and
    4 of them
}
    
rule bfaadbfbdfbfdabecbfffbdaf_exe {
strings:
        $s1 = "Too many open sockets"
        $s2 = "    -S              Do not show confidence estimators and warnings."
        $s3 = "    -z attributes   String to insert as td or th attributes"
        $s4 = "Directory not empty"
        $s5 = "The specified thread is detached"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "LOG: header received:"
        $s9 = "DeviceIoControl"
        $s10 = "FileDescription"
        $s11 = "Connection reset by peer"
        $s12 = "Non-2xx responses:      %d"
        $s13 = "TerminateProcess"
        $s14 = "Content-type: %s"
        $s15 = "InitializeCriticalSection"
        $s16 = "Too many processes"
        $s17 = "Address already in use"
        $s18 = " !\"#$%&'()*+,-./0123@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s19 = "Total:      %5I64d %5I64d%5I64d"
        $s20 = "    -n requests     Number of requests to perform"
condition:
    uint16(0) == 0x5a4d and filesize < 77KB and
    4 of them
}
    
rule efedaeaacafdbdfbcebfcd_exe {
strings:
        $s1 = "Too many open sockets"
        $s2 = "    -S              Do not show confidence estimators and warnings."
        $s3 = "    -z attributes   String to insert as td or th attributes"
        $s4 = "Directory not empty"
        $s5 = "The specified thread is detached"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "LOG: header received:"
        $s9 = "DeviceIoControl"
        $s10 = "FileDescription"
        $s11 = "Connection reset by peer"
        $s12 = "Non-2xx responses:      %d"
        $s13 = "TerminateProcess"
        $s14 = "Content-type: %s"
        $s15 = "InitializeCriticalSection"
        $s16 = "Too many processes"
        $s17 = "Address already in use"
        $s18 = " !\"#$%&'()*+,-./0123@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s19 = "Total:      %5I64d %5I64d%5I64d"
        $s20 = "    -n requests     Number of requests to perform"
condition:
    uint16(0) == 0x5a4d and filesize < 77KB and
    4 of them
}
    
rule bbbbfcffdfcbdbcdeaeadec_exe {
strings:
        $s1 = "Too many open sockets"
        $s2 = "    -S              Do not show confidence estimators and warnings."
        $s3 = "    -z attributes   String to insert as td or th attributes"
        $s4 = "Directory not empty"
        $s5 = "The specified thread is detached"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "LOG: header received:"
        $s9 = "DeviceIoControl"
        $s10 = "FileDescription"
        $s11 = "Connection reset by peer"
        $s12 = "Non-2xx responses:      %d"
        $s13 = "TerminateProcess"
        $s14 = "Content-type: %s"
        $s15 = "InitializeCriticalSection"
        $s16 = "Too many processes"
        $s17 = "Address already in use"
        $s18 = " !\"#$%&'()*+,-./0123@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s19 = "Total:      %5I64d %5I64d%5I64d"
        $s20 = "    -n requests     Number of requests to perform"
condition:
    uint16(0) == 0x5a4d and filesize < 77KB and
    4 of them
}
    
rule dddeabdabfdcbbeceeddebdfe_exe {
strings:
        $s1 = "invalid string position"
        $s2 = "_crt_debugger_hook"
        $s3 = "GetModuleHandleW"
        $s4 = "Found resource 2 found"
        $s5 = "GetCurrentThreadId"
        $s6 = "_CrtSetCheckCount"
        $s7 = "_invoke_watson"
        $s8 = "The variable '"
        $s9 = "LoadLibraryExW"
        $s10 = "    </security>"
        $s11 = "Greater Manchester1"
        $s12 = "GetSystemTimeAsFileTime"
        $s13 = "RegOpenKeyExW"
        $s14 = "SizeofResource"
        $s15 = "GetProcessHeap"
        $s16 = "Salisbury1"
        $s17 = "Hglob is not nutll"
        $s18 = "IsProcessorFeaturePresent"
        $s19 = "user32.dllN"
        $s20 = "Project1.ex"
condition:
    uint16(0) == 0x5a4d and filesize < 78KB and
    4 of them
}
    
rule beeedcfcafbdeafbcebebadebad_exe {
strings:
        $s1 = "Too many open sockets"
        $s2 = "    -S              Do not show confidence estimators and warnings."
        $s3 = "    -z attributes   String to insert as td or th attributes"
        $s4 = "Directory not empty"
        $s5 = "The specified thread is detached"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "LOG: header received:"
        $s9 = "DeviceIoControl"
        $s10 = "FileDescription"
        $s11 = "Connection reset by peer"
        $s12 = "Non-2xx responses:      %d"
        $s13 = "TerminateProcess"
        $s14 = "Content-type: %s"
        $s15 = "InitializeCriticalSection"
        $s16 = "Too many processes"
        $s17 = "Address already in use"
        $s18 = " !\"#$%&'()*+,-./0123@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s19 = "Total:      %5I64d %5I64d%5I64d"
        $s20 = "    -n requests     Number of requests to perform"
condition:
    uint16(0) == 0x5a4d and filesize < 193KB and
    4 of them
}
    
rule edadebfcccaaaeabcccdffccb_exe {
strings:
        $s1 = "Too many open sockets"
        $s2 = "    -S              Do not show confidence estimators and warnings."
        $s3 = "    -z attributes   String to insert as td or th attributes"
        $s4 = "Directory not empty"
        $s5 = "The specified thread is detached"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "LOG: header received:"
        $s9 = "DeviceIoControl"
        $s10 = "FileDescription"
        $s11 = "Connection reset by peer"
        $s12 = "Non-2xx responses:      %d"
        $s13 = "TerminateProcess"
        $s14 = "Content-type: %s"
        $s15 = "InitializeCriticalSection"
        $s16 = "Too many processes"
        $s17 = "Address already in use"
        $s18 = " !\"#$%&'()*+,-./0123@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s19 = "Total:      %5I64d %5I64d%5I64d"
        $s20 = "    -n requests     Number of requests to perform"
condition:
    uint16(0) == 0x5a4d and filesize < 77KB and
    4 of them
}
    