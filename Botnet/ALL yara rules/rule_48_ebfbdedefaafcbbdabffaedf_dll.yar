rule ebfbdedefaafcbbdabffaedf_dll {
strings:
        $s1 = "GetTickCount"
        $s2 = "RtlGetVersion"
        $s3 = "WinHttpReceiveResponse"
        $s4 = "GetProcessHeap"
        $s5 = "ExitProcess"
        $s6 = "SHLWAPI.dll"
        $s7 = "WinHttpReadData"
        $s8 = "GetTempPathA"
        $s9 = "ADVAPI32.dll"
        $s10 = "GetProcAddress"
        $s11 = "DllRegisterServer"
        $s12 = "GetUserNameA"
        $s13 = "WinHttpConnect"
        $s14 = "WinHttpSetOption"
        $s15 = "USER32.dll"
        $s16 = "MSVCRT.dll"
        $s17 = "CloseHandle"
        $s18 = "WINHTTP.dll"
        $s19 = "LoadLibraryA"
        $s20 = "CreateFileA"
condition:
    uint16(0) == 0x5a4d and filesize < 15KB and
    4 of them
}
    
