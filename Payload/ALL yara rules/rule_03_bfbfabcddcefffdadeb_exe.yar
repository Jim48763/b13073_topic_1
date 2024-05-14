rule bfbfabcddcefffdadeb_exe {
strings:
        $s1 = "CertOpenSystemStoreW"
        $s2 = "CertificateAuthority"
        $s3 = "DLL load status: %u"
        $s4 = "CoInitializeEx"
        $s5 = "RegSetValueExA"
        $s6 = "RtlNtStatusToDosError"
        $s7 = "cmd /C \"%s> %s1\""
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleA"
        $s10 = "RemoveDirectoryW"
        $s11 = "DispatchMessageA"
        $s12 = "RtlImageNtHeader"
        $s13 = "GetComputerNameW"
        $s14 = "PFXExportCertStoreEx"
        $s15 = "InitializeCriticalSection"
        $s16 = "WinHttpOpenRequest"
        $s17 = "GetCurrentThreadId"
        $s18 = "CreateCompatibleDC"
        $s19 = "Connection: close;"
        $s20 = "OLEAUT32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 253KB and
    4 of them
}
    
