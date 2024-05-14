rule bceedbfebdbeabcadbaefa_exe {
strings:
        $s1 = "EnterCriticalSection"
        $s2 = " !\"#$%&'()*+,-./0123@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        $s3 = "KERNEL32.dll"
        $s4 = "=j&&LZ66lA??~"
        $s5 = "GetProcAddress"
        $s6 = "CloseHandle"
        $s7 = "xxJo%%\\r..8$"
        $s8 = "&Lj&6lZ6?~A?"
        $s9 = "LoadLibraryA"
        $s10 = "GetLastError"
        $s11 = "m1:tC-}T-}"
        $s12 = "ReleaseMutex"
        $s13 = "CMa<5)2ow"
        $s14 = "f\"\"D~**T"
        $s15 = "o%%Jr..\\$"
        $s16 = "\"Df\"*T~*"
        $s17 = "x%Jo%.\\r."
        $s18 = "0H\\+q~&<"
        $s19 = "0xA74oD<0"
        $s20 = "MPHNPJuPd"
condition:
    uint16(0) == 0x5a4d and filesize < 97KB and
    4 of them
}
    
