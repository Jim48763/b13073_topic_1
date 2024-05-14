rule debafbddebdefefcfbcdab_exe {
strings:
        $s1 = "IoAllocateWorkItem"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "FileDescription"
        $s5 = "KdDebuggerEnabled"
        $s6 = "InitSafeBootMode"
        $s7 = "IBM Corporation "
        $s8 = "t$L;t$Hwz9\\$ ut3"
        $s9 = "KeInitializeMutex"
        $s10 = "KeGetCurrentThread"
        $s11 = "ZwQueryValueKey"
        $s12 = "nfrd965.sys"
        $s13 = "PsGetVersion"
        $s14 = "ntkrnlpa.exe"
        $s15 = "\\DosDevices\\GpdDev"
        $s16 = "OriginalFilename"
        $s17 = "ExAllocatePool"
        $s18 = "ZwOpenFile"
        $s19 = "ZwReadFile"
        $s20 = "VS_VERSION_INFO"
condition:
    uint16(0) == 0x5a4d and filesize < 29KB and
    4 of them
}
    
