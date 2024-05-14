rule abccbdfedafacedadbddebb_exe {
strings:
        $s1 = "CryptReleaseContext"
        $s2 = "Win Server 2008 R2"
        $s3 = "?456789:;<="
        $s4 = "GetKeyboardType"
        $s5 = "DeviceIoControl"
        $s6 = "GetThreadLocale"
        $s7 = "GetModuleHandleA"
        $s8 = "GetConsoleWindow"
        $s9 = "SetFilePointerEx"
        $s10 = "GetComputerNameW"
        $s11 = "LsaGetLogonSessionData"
        $s12 = "InitializeCriticalSection"
        $s13 = "GetCurrentThreadId"
        $s14 = "GetTickCount"
        $s15 = "FPUMaskValue"
        $s16 = "InternetCloseHandle"
        $s17 = "LsaFreeReturnBuffer"
        $s18 = "GetFileAttributesW"
        $s19 = "5(60686>6D6L6R6X6_6i6,7Z7x7"
        $s20 = "CoTaskMemFree"
condition:
    uint16(0) == 0x5a4d and filesize < 145KB and
    4 of them
}
    
