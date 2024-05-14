rule bdbfddffcecdaddaefeaeb_exe {
strings:
        $s1 = "CertOpenSystemStoreW"
        $s2 = "RegSetValueExW"
        $s3 = "CoInitializeEx"
        $s4 = "GetUserNameExW"
        $s5 = "H|~rdpf)24C"
        $s6 = "w:3?*0=\"%~"
        $s7 = "=:/9)#8a$-."
        $s8 = "InternetCrackUrlA"
        $s9 = "SetThreadPriority"
        $s10 = "RemoveDirectoryW"
        $s11 = "SetFilePointerEx"
        $s12 = "GetComputerNameW"
        $s13 = "DispatchMessageW"
        $s14 = "GetModuleHandleW"
        $s15 = "CreateCompatibleBitmap"
        $s16 = "PFXExportCertStoreEx"
        $s17 = "WriteProcessMemory"
        $s18 = "RtlUserThreadStart"
        $s19 = "GetLocalTime"
        $s20 = "0'0\"*.4k/3-"
condition:
    uint16(0) == 0x5a4d and filesize < 128KB and
    4 of them
}
    
