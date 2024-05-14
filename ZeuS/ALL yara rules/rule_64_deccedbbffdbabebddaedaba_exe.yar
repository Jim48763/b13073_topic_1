rule deccedbbffdbabebddaedaba_exe {
strings:
        $s1 = "NtResumeThread"
        $s2 = "RtlLockHeap"
        $s3 = "ta0<lbSzXOn"
        $s4 = "GetModuleHandleA"
        $s5 = "VirtualProtect"
        $s6 = "R&<+ZcLsrI"
        $s7 = "ExitProcess"
        $s8 = "VirtualQuery"
        $s9 = "c:\\dump.exe"
        $s10 = "GetTempPathA"
        $s11 = "RtlZeroMemory"
        $s12 = "GetProcAddress"
        $s13 = "VirtualAlloc"
        $s14 = "user32.dll"
        $s15 = "jqz%L\\I1e"
        $s16 = "MessageBoxA"
        $s17 = "CloseHandle"
        $s18 = "LoadLibraryA"
        $s19 = "kernel32.dll"
        $s20 = "C:\\file.exe"
condition:
    uint16(0) == 0x5a4d and filesize < 321KB and
    4 of them
}
    
