rule dbefeadeefdadacdfaeafdefcbe_exe {
strings:
        $s1 = "ReadProcessMemory"
        $s2 = "DllGetClassObject"
        $s3 = "ShellMessageBoxA"
        $s4 = "GetModuleHandleA"
        $s5 = "SHBrowseForFolderW"
        $s6 = "GetLocalTime"
        $s7 = "AuthzFreeContext"
        $s8 = "Ctl3dRegister"
        $s9 = "OpenJobObjectW"
        $s10 = "Q'+Vs9-<y@"
        $s11 = "CreateDirectoryW"
        $s12 = "SHGetMalloc"
        $s13 = "yuiopas.pdb"
        $s14 = "SHCreateShellItem"
        $s15 = "CreateSemaphoreA"
        $s16 = "GetProcAddress"
        $s17 = "CreateProcessA"
        $s18 = "ShellExecuteA"
        $s19 = "OpenMutexW"
        $s20 = "Ctl3dGetVer"
condition:
    uint16(0) == 0x5a4d and filesize < 177KB and
    4 of them
}
    
