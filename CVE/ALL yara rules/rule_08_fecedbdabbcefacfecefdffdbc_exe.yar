rule fecedbdabbcefacfecefdffdbc_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "SuspendThread"
        $s3 = "RegCreateKeyExW"
        $s4 = "0@.eh_fram"
        $s5 = "ATPQRSUVWH"
        $s6 = "GetCurrentThread"
        $s7 = "ADVAPI32.dll"
        $s8 = "KERNEL32.dll"
        $s9 = "ntoskrnl.exe"
        $s10 = "VirtualAlloc"
        $s11 = "ResumeThread"
        $s12 = "CreateProcessA"
        $s13 = "ZwCreateEvent"
        $s14 = "CloseHandle"
        $s15 = "_^][ZYXA\\A"
        $s16 = "CreateFileA"
        $s17 = "kernel32.dll"
        $s18 = "3Console\\Console"
        $s19 = "CreateThread"
        $s20 = "c:\\ok_0000"
condition:
    uint16(0) == 0x5a4d and filesize < 157KB and
    4 of them
}
    
