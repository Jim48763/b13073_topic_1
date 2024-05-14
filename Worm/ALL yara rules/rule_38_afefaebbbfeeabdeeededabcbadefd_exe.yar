rule afefaebbbfeeabdeeededabcbadefd_exe {
strings:
        $s1 = "%s: %s and %s are the same file"
        $s2 = "Unable to authenticate"
        $s3 = "CryptReleaseContext"
        $s4 = "RegSetValueExA"
        $s5 = "had^`ZLJOK?"
        $s6 = "DIRTHUMB;%s"
        $s7 = "{)B'ys.*KVc"
        $s8 = "WSAGetLastError"
        $s9 = "Resource shortage"
        $s10 = "%s\\iosystem.dll"
        $s11 = "GetComputerNameA"
        $s12 = "GetModuleHandleA"
        $s13 = "connect %host %port\\n"
        $s14 = "internal error in shorten_name"
        $s15 = "Bogus message code %d"
        $s16 = "Repeat key exchange"
        $s17 = "CreateCompatibleDC"
        $s18 = "too much data sent"
        $s19 = "sqlite3_open"
        $s20 = "mozcrt19.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 569KB and
    4 of them
}
    
