rule cfccaeeebdaaaeeacdefdfd_exe {
strings:
        $s1 = "%s: %s and %s are the same file"
        $s2 = "Unable to authenticate"
        $s3 = "CryptReleaseContext"
        $s4 = "RegSetValueExA"
        $s5 = "had^`ZLJOK?"
        $s6 = "DIRTHUMB;%s"
        $s7 = "(v+q#4\"KPY"
        $s8 = "DIoR`#[=QdO"
        $s9 = "WSAGetLastError"
        $s10 = "Resource shortage"
        $s11 = "%s\\iosystem.dll"
        $s12 = "GetComputerNameA"
        $s13 = "GetModuleHandleA"
        $s14 = "connect %host %port\\n"
        $s15 = "internal error in shorten_name"
        $s16 = "Bogus message code %d"
        $s17 = "Repeat key exchange"
        $s18 = "CreateCompatibleDC"
        $s19 = "too much data sent"
        $s20 = "sqlite3_open"
condition:
    uint16(0) == 0x5a4d and filesize < 575KB and
    4 of them
}
    
