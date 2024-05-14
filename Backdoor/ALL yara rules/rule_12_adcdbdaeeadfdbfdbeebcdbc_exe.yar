rule adcdbdaeeadfdbfdbeebcdbc_exe {
strings:
        $s1 = "DESKTOP_ENUMERATE"
        $s2 = "STARTUP_INFORMATION"
        $s3 = "VirtualAllocEx"
        $s4 = "DESKTOP_SWITCHDESKTOP"
        $s5 = "GetProcessesByName"
        $s6 = "ProductName"
        $s7 = "ComputeHash"
        $s8 = "op_Equality"
        $s9 = "ExclusionWD"
        $s10 = "_CorExeMain"
        $s11 = "FileDescription"
        $s12 = "ReadProcessMemory"
        $s13 = "GetConsoleWindow"
        $s14 = "DelegateResumeThread"
        $s15 = "DESKTOP_HOOKCONTROL"
        $s16 = "IAsyncResult"
        $s17 = "UTF8Encoding"
        $s18 = "DialogResult"
        $s19 = "Pandora hVNC"
        $s20 = "GetThreadContext"
condition:
    uint16(0) == 0x5a4d and filesize < 143KB and
    4 of them
}
    
