rule efbafafdedfdbbcfedcefbe_exe {
strings:
        $s1 = "WinHttpReceiveResponse"
        $s2 = "VirtualProtect"
        $s3 = "GetProcessHeap"
        $s4 = "c:\\ProgramData"
        $s5 = "CreateDirectoryA"
        $s6 = "ExitProcess"
        $s7 = "WinHttpReadData"
        $s8 = "ADVAPI32.dll"
        $s9 = "KERNEL32.dll"
        $s10 = "GetUserNameA"
        $s11 = "VirtualAlloc"
        $s12 = "WinHttpConnect"
        $s13 = "WinHttpSetOption"
        $s14 = "USER32.dll"
        $s15 = "CloseHandle"
        $s16 = "WINHTTP.dll"
        $s17 = "CreateFileA"
        $s18 = "{%0.8X-%0.4X-%0.4X-%0.4X-%0.4X%0.8X}"
        $s19 = "WinHttpOpen"
        $s20 = "GetFileSize"
condition:
    uint16(0) == 0x5a4d and filesize < 13KB and
    4 of them
}
    
