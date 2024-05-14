import pe
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
    
rule MEMZ_bat {
strings:
        $s1 = "start \"\" %v%"
        $s2 = "@echo off"
condition:
    uint16(0) == 0x5a4d and filesize < 17KB and
    4 of them
}
    
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
    
rule WaffMEMZ___exe {
strings:
        $s1 = "SecureBoot sucks."
        $s2 = "GetWindowDC"
        $s3 = "I WARNED YOU..."
        $s4 = "You are an idiot!"
        $s5 = "GetModuleHandleW"
        $s6 = " - danooct1 2016"
        $s7 = "DispatchMessageW"
        $s8 = "printmanagement.msc"
        $s9 = "UnhookWindowsHookEx"
        $s10 = "GetCurrentThreadId"
        $s11 = "GET BETTER HAX NEXT TIME xD"
        $s12 = "SystemQuestion"
        $s13 = "CallNextHookEx"
        $s14 = "    </security>"
        $s15 = "http://e621.net"
        $s16 = "SystemHand"
        $s17 = "gpedit.msc"
        $s18 = "PlaySoundA"
        $s19 = "GetCurrentProcess"
        $s20 = "2 2$2(2,2024282<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2"
condition:
    uint16(0) == 0x5a4d and filesize < 28KB and
    4 of them
}
    