rule fbfdbfafacacffdcfaefebaefcdedc_exe {
strings:
        $s1 = "g>jq>l{jklp>gqkl>xwr{m>|"
        $s2 = "CreateIoCompletionPort"
        $s3 = "CryptReleaseContext"
        $s4 = "IcmpCreateFile"
        $s5 = "invalid string position"
        $s6 = "LoadStringW"
        $s7 = "`local vftable'"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleW"
        $s10 = "SetFilePointerEx"
        $s11 = "kjqknzm0{f{2jv{|"
        $s12 = "EnterCriticalSection"
        $s13 = "rr>wpxq>|{rqi>6}qng>"
        $s14 = "pg>->xwr{m>XQL>XL[[>"
        $s15 = "433A5C50726F6772616D2046696C65732028783836295C4D6963726F736F66742053514C20536572766572"
        $s16 = "GetCurrentThreadId"
        $s17 = "{PATTERN_ID}"
        $s18 = "NetShareEnum"
        $s19 = "IcmpSendEcho"
        $s20 = "GetTickCount"
condition:
    uint16(0) == 0x5a4d and filesize < 144KB and
    4 of them
}
    
