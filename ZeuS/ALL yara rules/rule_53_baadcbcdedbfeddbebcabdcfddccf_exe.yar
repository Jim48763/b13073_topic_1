rule baadcbcdedbfeddbebcabdcfddccf_exe {
strings:
        $s1 = "MenuItemFromPoint"
        $s2 = "CreateWindowStationW"
        $s3 = "CertOpenSystemStoreW"
        $s4 = "RegSetValueExW"
        $s5 = "CoInitializeEx"
        $s6 = "GetUserNameExW"
        $s7 = "Jqsjnoh\"Ht"
        $s8 = "GetWindowDC"
        $s9 = "Accept-Encoding"
        $s10 = "InternetCrackUrlA"
        $s11 = "SetThreadPriority"
        $s12 = "RemoveDirectoryW"
        $s13 = "SetFilePointerEx"
        $s14 = "GetComputerNameW"
        $s15 = "DispatchMessageW"
        $s16 = "TerminateProcess"
        $s17 = "GetModuleHandleW"
        $s18 = "CreateCompatibleBitmap"
        $s19 = "PFXExportCertStoreEx"
        $s20 = "WriteProcessMemory"
condition:
    uint16(0) == 0x5a4d and filesize < 143KB and
    4 of them
}
    
