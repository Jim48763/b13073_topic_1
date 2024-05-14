rule eefadffdeabafdfcfafaebbbfd_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "SuspendThread"
        $s3 = "RegCreateKeyExW"
        $s4 = "0@.eh_fram"
        $s5 = "GetCurrentThread"
        $s6 = "ADVAPI32.dll"
        $s7 = "KERNEL32.dll"
        $s8 = "ntoskrnl.exe"
        $s9 = "VirtualAlloc"
        $s10 = "ResumeThread"
        $s11 = "CreateProcessA"
        $s12 = "ZwCreateEvent"
        $s13 = "CloseHandle"
        $s14 = "CreateFileA"
        $s15 = "kernel32.dll"
        $s16 = "3Console\\Console"
        $s17 = "CreateThread"
        $s18 = "c:\\ok_0000"
        $s19 = "RtlUnwind"
        $s20 = "WriteFile"
condition:
    uint16(0) == 0x5a4d and filesize < 156KB and
    4 of them
}
    
