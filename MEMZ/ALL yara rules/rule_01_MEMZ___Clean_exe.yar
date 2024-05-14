rule MEMZ___Clean_exe {
strings:
        $s1 = "GetWindowDC"
        $s2 = "Screen glitches"
        $s3 = "GetModuleHandleW"
        $s4 = "DispatchMessageW"
        $s5 = "UnhookWindowsHookEx"
        $s6 = "GetCurrentThreadId"
        $s7 = "UpdateWindow"
        $s8 = "SystemQuestion"
        $s9 = "GetWindowLongW"
        $s10 = "FormatMessageW"
        $s11 = "CallNextHookEx"
        $s12 = "    </security>"
        $s13 = "IsDialogMessageW"
        $s14 = "Random error sounds"
        $s15 = "PlaySoundA"
        $s16 = "SystemHand"
        $s17 = "GetSystemMetrics"
        $s18 = "ExitProcess"
        $s19 = "</assembly>"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 17KB and
    4 of them
}
    
