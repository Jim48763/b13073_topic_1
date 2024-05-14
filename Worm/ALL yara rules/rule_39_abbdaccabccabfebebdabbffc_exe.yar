rule abbdaccabccabfebebdabbffc_exe {
strings:
        $s1 = "NtQueryAttributesFile"
        $s2 = "RegSetValueExW"
        $s3 = "LoadStringW"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "ERsISe\"L5Q"
        $s7 = "SystemPartition"
        $s8 = "win:Informational"
        $s9 = "TerminateProcess"
        $s10 = "GetModuleHandleA"
        $s11 = "Microsoft Corporation"
        $s12 = "\\EFI\\Microsoft\\Boot\\BCD"
        $s13 = "GetCurrentThreadId"
        $s14 = "        type=\"win32\"/>"
        $s15 = "RtlLengthSid"
        $s16 = "GetTickCount"
        $s17 = "OLEAUT32.dll"
        $s18 = "    </application>"
        $s19 = "__wgetmainargs"
        $s20 = "RtlAddAccessAllowedAceEx"
condition:
    uint16(0) == 0x5a4d and filesize < 161KB and
    4 of them
}
    
