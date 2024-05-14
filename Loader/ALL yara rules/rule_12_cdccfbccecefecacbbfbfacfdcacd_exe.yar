rule cdccfbccecefecacbbfbfacfdcacd_exe {
strings:
        $s1 = "VirtualAllocEx"
        $s2 = "UwoQwVwdwxvWrGrvHuuru"
        $s3 = "QwJhwFrqwh{wWkuhdg"
        $s4 = "?456789:;<="
        $s5 = "fun4it|sqtfirtizqj4"
        $s6 = "WriteProcessMemory"
        $s7 = "ZsijknsjiY~ujJwwtw"
        $s8 = "DigiCert1%0#"
        $s9 = "GetTickCount"
        $s10 = "SetThreadContext"
        $s11 = "Greater Manchester1"
        $s12 = "WyqHwjfyjZxjwYmwjfi"
        $s13 = "GetFileAttributesW"
        $s14 = "*FQQZXJWXUWTKNQJ*"
        $s15 = "GetDriveTypeA"
        $s16 = "GetProcessHeap"
        $s17 = "Kdc23icmQoc21f"
        $s18 = "QiwLjyUwthjizwjFiiwjxx"
        $s19 = "OguJhwSurfhgxuhDgguhvv"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 53KB and
    4 of them
}
    
