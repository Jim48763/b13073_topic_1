rule ecceafbcaedcfafecdaddb_exe {
strings:
        $s1 = "!_Reporting"
        $s2 = "GetModuleHandleA"
        $s3 = "z\\8=EYA.w ("
        $s4 = "wZDAM<8aG`"
        $s5 = "Y3r0L&OX~I"
        $s6 = "uD^_S6Cneg"
        $s7 = "Lv'diX#U)O"
        $s8 = "HeapDestroy"
        $s9 = "ExitProcess"
        $s10 = "KERNEL32.dll"
        $s11 = "GetProcAddress"
        $s12 = "BROxB|v?` "
        $s13 = "MSVCRT.dll"
        $s14 = "USER32.DLL"
        $s15 = "HeapReAlloc"
        $s16 = "MessageBoxA"
        $s17 = "CloseHandle"
        $s18 = "LoadLibraryA"
        $s19 = "CreateFileA"
        $s20 = "|SrCp}:;~"
condition:
    uint16(0) == 0x5a4d and filesize < 184KB and
    4 of them
}
    
