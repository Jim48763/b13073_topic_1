rule MEMZ_Destructive_exe {
strings:
        $s1 = "SecureBoot sucks."
        $s2 = "GetWindowDC"
        $s3 = "I WARNED YOU..."
        $s4 = "You are an idiot!"
        $s5 = "DispatchMessageW"
        $s6 = " - danooct1 2016"
        $s7 = "so use it as long as you can!"
        $s8 = "UnhookWindowsHookEx"
        $s9 = "GetCurrentThreadId"
        $s10 = "GET BETTER HAX NEXT TIME xD"
        $s11 = "SystemQuestion"
        $s12 = "CallNextHookEx"
        $s13 = "NtRaiseHardError"
        $s14 = "    </security>"
        $s15 = "OpenProcessToken"
        $s16 = "PlaySoundA"
        $s17 = "SystemHand"
        $s18 = "GetCurrentProcess"
        $s19 = "GetSystemMetrics"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 19KB and
    4 of them
}
    
