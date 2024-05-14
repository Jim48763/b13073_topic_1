rule MEMZ_exe {
strings:
        $s1 = "SecureBoot sucks."
        $s2 = "GetWindowDC"
        $s3 = "I WARNED YOU..."
        $s4 = "You are an idiot!"
        $s5 = "DispatchMessageA"
        $s6 = "so use it as long as you can!"
        $s7 = "UnhookWindowsHookEx"
        $s8 = "GetCurrentThreadId"
        $s9 = "GET BETTER HAX NEXT TIME xD"
        $s10 = "SystemQuestion"
        $s11 = "CallNextHookEx"
        $s12 = "NtRaiseHardError"
        $s13 = "    </security>"
        $s14 = "OpenProcessToken"
        $s15 = "Process32First"
        $s16 = "PlaySoundA"
        $s17 = "SystemHand"
        $s18 = "GetCurrentProcess"
        $s19 = "GetSystemMetrics"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 17KB and
    4 of them
}
    
