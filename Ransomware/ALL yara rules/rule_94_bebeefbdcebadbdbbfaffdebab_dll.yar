rule bebeefbdcebadbdbbfaffdebab_dll {
strings:
        $s1 = "WNetAddConnection2W"
        $s2 = "CoInitializeEx"
        $s3 = "Process32FirstW"
        $s4 = "InternetCrackUrlA"
        $s5 = "GetShortPathNameW"
        $s6 = "GetModuleHandleA"
        $s7 = "SetFilePointerEx"
        $s8 = "DispatchMessageA"
        $s9 = "\\User Data\\Default\\Cache\\"
        $s10 = "OLEAUT32.dll"
        $s11 = "Encrypting: "
        $s12 = "NETAPI32.dll"
        $s13 = "very valuable for you"
        $s14 = "AnimateWindow"
        $s15 = "MapViewOfFile"
        $s16 = "a backup server"
        $s17 = "DeleteCriticalSection"
        $s18 = "InternetCloseHandle"
        $s19 = "SetFileAttributesW"
        $s20 = "GetDriveTypeW"
condition:
    uint16(0) == 0x5a4d and filesize < 381KB and
    4 of them
}
    
