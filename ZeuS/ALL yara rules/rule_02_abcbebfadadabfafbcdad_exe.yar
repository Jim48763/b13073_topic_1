rule abcbebfadadabfafbcdad_exe {
strings:
        $s1 = "MenuItemFromPoint"
        $s2 = "GetSystemPowerStatus"
        $s3 = "CertOpenSystemStoreW"
        $s4 = "CryptReleaseContext"
        $s5 = "CoInitializeEx"
        $s6 = "GetUserNameExW"
        $s7 = "it}aVno{qlO"
        $s8 = "Product: %s"
        $s9 = "Company: %s"
        $s10 = " 02531t?;-9"
        $s11 = ")Ohcuivkm~#"
        $s12 = "Process32FirstW"
        $s13 = "text/javascript"
        $s14 = "HttpEndRequestA"
        $s15 = "Accept-Encoding"
        $s16 = "QueryDosDeviceW"
        $s17 = "InternetCrackUrlA"
        $s18 = "ReadProcessMemory"
        $s19 = "SetThreadPriority"
        $s20 = "SetFilePointerEx"
condition:
    uint16(0) == 0x5a4d and filesize < 226KB and
    4 of them
}
    
