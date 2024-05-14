rule dfaacddaadfdecfffecbeedcebaaffae_exe {
strings:
        $s1 = "RegSetValueExA"
        $s2 = "EExternalException"
        $s3 = "TActiveThreadArray"
        $s4 = "GetWindowDC"
        $s5 = "ProductName"
        $s6 = "LoadStringA"
        $s7 = "VarFileInfo"
        $s8 = "LquKdMwfnjU"
        $s9 = "9\"0%7#!hLV"
        $s10 = "FileDescription"
        $s11 = "GetKeyboardType"
        $s12 = "GetThreadLocale"
        $s13 = "Division by zero"
        $s14 = "DispatchMessageA"
        $s15 = "GetModuleHandleA"
        $s16 = "EnterCriticalSection"
        $s17 = "GetTextExtentPoint32A"
        $s18 = "GetCurrentThreadId"
        $s19 = "WindowFromDC"
        $s20 = "SetEndOfFile"
condition:
    uint16(0) == 0x5a4d and filesize < 467KB and
    4 of them
}
    
