import pe
rule bfbfdbbbbbffcbdddafaedbb_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "ManagementBaseObject"
        $s3 = "RuntimeHelpers"
        $s4 = "<Getip>b__13_0"
        $s5 = "GetSubKeyNames"
        $s6 = "FlagsAttribute"
        $s7 = "RuntimeFieldHandle"
        $s8 = "DownloaderFilename"
        $s9 = "get_ProcessorCount"
        $s10 = "ReadFromEmbeddedResources"
        $s11 = "System.Linq"
        $s12 = "ProductName"
        $s13 = "EmailSendTo"
        $s14 = "_CorExeMain"
        $s15 = "ComputeHash"
        $s16 = "dwMaxLength"
        $s17 = "LastIndexOf"
        $s18 = "XmlNodeList"
        $s19 = "VarFileInfo"
        $s20 = "OperativeSystem"
condition:
    uint16(0) == 0x5a4d and filesize < 519KB and
    4 of them
}
    
rule ccafffeedcfcecbebcbdbc_dll {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "(ch != _T('\\0'))"
        $s4 = "english-caribbean"
        $s5 = "GetEnvironmentStrings"
        $s6 = "__get_qualified_locale"
        $s7 = "=<=H=L=P=T=X=`=d=p=0>4>8>`>d>h>l>p>t>x>|>"
        $s8 = "<file unknown>"
        $s9 = "SetConsoleCtrlHandler"
        $s10 = "GetConsoleOutputCP"
        $s11 = "LC_MONETARY"
        $s12 = "english-jamaica"
        $s13 = "`local vftable'"
        $s14 = "spanish-venezuela"
        $s15 = "GetModuleHandleA"
        $s16 = "TerminateProcess"
        $s17 = "EnvironmentDirectory"
        $s18 = "_get_dstbias(&dstbias)"
        $s19 = "GetCurrentThreadId"
        $s20 = "(((_Src))) != NULL"
condition:
    uint16(0) == 0x5a4d and filesize < 517KB and
    4 of them
}
    
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
    
rule fccceacdfdedefeebdabfdccacefff_cmd {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 6KB and
    all of them
}
    