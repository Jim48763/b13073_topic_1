rule cdebebcfadbeabbffacbbfdfaea_exe {
strings:
        $s1 = "GetThreadPriority"
        $s2 = "GetCurrentThread"
        $s3 = "KERNEL32.dll"
        $s4 = "GetProcAddress"
        $s5 = "DllRegisterServer"
        $s6 = "ResumeThread"
        $s7 = "VirtualAlloc"
        $s8 = "VirtualFree"
        $s9 = "TlsGetValue"
        $s10 = "LoadLibraryA"
        $s11 = "CreateFileA"
        $s12 = "GetSystemTime"
        $s13 = "CreateThread"
        $s14 = "D$$;D$0s*H"
        $s15 = "`.rdata"
        $s16 = "D$Hk@P"
        $s17 = "9D$pr"
        $s18 = "L$(H+"
        $s19 = "L$ 9H"
        $s20 = "D$ Hk"
condition:
    uint16(0) == 0x5a4d and filesize < 346KB and
    4 of them
}
    
