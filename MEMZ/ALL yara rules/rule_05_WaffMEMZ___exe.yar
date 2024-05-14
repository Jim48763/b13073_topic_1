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
    