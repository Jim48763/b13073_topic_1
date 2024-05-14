import pe
rule fececfbcbabcebbedaabbedbafeebcb_exe {
strings:
        $s1 = "Directory not empty"
        $s2 = "Runtime Error!"
        $s3 = "invalid string position"
        $s4 = "No child processes"
        $s5 = "VarFileInfo"
        $s6 = "`local vftable'"
        $s7 = "TerminateProcess"
        $s8 = "GetModuleHandleW"
        $s9 = "Operation not permitted"
        $s10 = "GetCurrentDirectoryW"
        $s11 = "InitializeCriticalSection"
        $s12 = "VICEZAKOWUKEWOFEJAVE"
        $s13 = "GetCurrentThreadId"
        $s14 = "No locks available"
        $s15 = "Invalid seek"
        $s16 = "GetTickCount"
        $s17 = "Improper link"
        $s18 = "Unknown exception"
        $s19 = "Too many links"
        $s20 = "No such device"
condition:
    uint16(0) == 0x5a4d and filesize < 222KB and
    4 of them
}
    
rule aafdfeeafabffddaafbaeecbcadcaffb_exe {
strings:
        $s1 = "Release object %p"
        $s2 = "QueryDosDeviceW"
        $s3 = "`local vftable'"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleW"
        $s6 = "SetFilePointerEx"
        $s7 = "GetCurrentThreadId"
        $s8 = "OLEAUT32.dll"
        $s9 = "FindFirstFileExW"
        $s10 = "StringFromIID"
        $s11 = "ProcessIdToSessionId"
        $s12 = "Unknown exception"
        $s13 = "LoadLibraryExW"
        $s14 = "FormatMessageW"
        $s15 = "`udt returning'"
        $s16 = "GetSystemTimeAsFileTime"
        $s17 = "CoTaskMemFree"
        $s18 = ".?AV_com_error@@"
        $s19 = "OpenProcessToken"
        $s20 = "JobTransferred"
condition:
    uint16(0) == 0x5a4d and filesize < 136KB and
    4 of them
}
    
rule aaccadfbaacbbbfdbfcfefdfffbeffcbc_exe {
strings:
        $s1 = "Release object %p"
        $s2 = "QueryDosDeviceW"
        $s3 = "`local vftable'"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleW"
        $s6 = "SetFilePointerEx"
        $s7 = "GetCurrentThreadId"
        $s8 = "OLEAUT32.dll"
        $s9 = "FindFirstFileExW"
        $s10 = "StringFromIID"
        $s11 = "ProcessIdToSessionId"
        $s12 = "Unknown exception"
        $s13 = "RtlCaptureContext"
        $s14 = "LoadLibraryExW"
        $s15 = "FormatMessageW"
        $s16 = "`udt returning'"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "CoTaskMemFree"
        $s19 = ".?AV_com_error@@"
        $s20 = "OpenProcessToken"
condition:
    uint16(0) == 0x5a4d and filesize < 162KB and
    4 of them
}
    
rule efafaddedceedfccefbabbfbababc_exe {
strings:
        $s1 = "CreateWindowStationW"
        $s2 = "CorExitPrTB."
        $s3 = "EnumDeviceDrivers"
        $s4 = "VirtualProtect"
        $s5 = "HPDispEchT"
        $s6 = "DMec7 ]YO3"
        $s7 = "5La0GoT;OC"
        $s8 = "ExitProcess"
        $s9 = "</assembly>"
        $s10 = "    <security>"
        $s11 = "GetProcAddress"
        $s12 = "GetValueS~"
        $s13 = "Q`/?_e+[T?"
        $s14 = "SHELL32.dll"
        $s15 = "CreateBitmap"
        $s16 = "LoadLibraryA"
        $s17 = "dStackGuara"
        $s18 = "KERNEL32.DLL"
        $s19 = "(e+0001#SNAN"
        $s20 = "poolTimerm"
condition:
    uint16(0) == 0x5a4d and filesize < 44KB and
    4 of them
}
    
rule dabcdffbabccebebbeddfbeaaec_ps {
strings:
        $s1 = "#put evil dll in temp"
        $s2 = "namespace XPS"
        $s3 = "#put phonebook"
        $s4 = "#process cmd"
        $s5 = "#run exp "
        $s6 = "sleep(3)"
        $s7 = "finally"
        $s8 = "#clean"
condition:
    uint16(0) == 0x5a4d and filesize < 31KB and
    4 of them
}
    
rule afcbcbeeddcbcfecdcea_exe {
strings:
        $s1 = "0@.eh_fram"
        $s2 = "ATPQRSUVWH"
        $s3 = "ntoskrnl.exe"
        $s4 = "ZwCreateEvent"
        $s5 = "dump.exe 2"
        $s6 = "_^][ZYXA\\A"
        $s7 = "kernel32.dll"
        $s8 = "c:\\ok_0000"
        $s9 = "AQAPRQVH1"
        $s10 = "AXAX^YZAXAY"
        $s11 = "ntdll.dll"
        $s12 = "0`.data"
        $s13 = "0@.bss"
        $s14 = ".idata"
        $s15 = "xKcC!"
        $s16 = "D$@H1"
        $s17 = "XAYZH"
        $s18 = "memset"
        $s19 = ".text"
        $s20 = "NN!!!!"
condition:
    uint16(0) == 0x5a4d and filesize < 116KB and
    4 of them
}
    
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
    
rule fecedbdabbcefacfecefdffdbc_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "SuspendThread"
        $s3 = "RegCreateKeyExW"
        $s4 = "0@.eh_fram"
        $s5 = "ATPQRSUVWH"
        $s6 = "GetCurrentThread"
        $s7 = "ADVAPI32.dll"
        $s8 = "KERNEL32.dll"
        $s9 = "ntoskrnl.exe"
        $s10 = "VirtualAlloc"
        $s11 = "ResumeThread"
        $s12 = "CreateProcessA"
        $s13 = "ZwCreateEvent"
        $s14 = "CloseHandle"
        $s15 = "_^][ZYXA\\A"
        $s16 = "CreateFileA"
        $s17 = "kernel32.dll"
        $s18 = "3Console\\Console"
        $s19 = "CreateThread"
        $s20 = "c:\\ok_0000"
condition:
    uint16(0) == 0x5a4d and filesize < 157KB and
    4 of them
}
    
rule fcbdcadefbfcaebfdaffff_exe {
strings:
        $s1 = "0@.eh_fram"
        $s2 = "ATPQRSUVWH"
        $s3 = "ntoskrnl.exe"
        $s4 = "ZwCreateEvent"
        $s5 = "dump.exe 2"
        $s6 = "_^][ZYXA\\A"
        $s7 = "kernel32.dll"
        $s8 = "c:\\ok_0000"
        $s9 = "AQAPRQVH1"
        $s10 = "AXAX^YZAXAY"
        $s11 = "ntdll.dll"
        $s12 = "0`.data"
        $s13 = "0@.bss"
        $s14 = ".idata"
        $s15 = "W;_2F"
        $s16 = "D$@H1"
        $s17 = "XAYZH"
        $s18 = "memset"
        $s19 = ".text"
        $s20 = "NN!!!!"
condition:
    uint16(0) == 0x5a4d and filesize < 116KB and
    4 of them
}
    
rule abaaacbacafeaefaccfbeaedfea_exe {
strings:
        $s1 = "cross device link"
        $s2 = "executable format error"
        $s3 = "result out of range"
        $s4 = "directory not empty"
        $s5 = "invalid string position"
        $s6 = "operation canceled"
        $s7 = "GetConsoleOutputCP"
        $s8 = "LC_MONETARY"
        $s9 = "`local vftable'"
        $s10 = "spanish-venezuela"
        $s11 = "SetFilePointerEx"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "destination address required"
        $s15 = "GetCurrentThreadId"
        $s16 = "south-africa"
        $s17 = "resource deadlock would occur"
        $s18 = "device or resource busy"
        $s19 = "wrong protocol type"
        $s20 = "FindFirstFileExW"
condition:
    uint16(0) == 0x5a4d and filesize < 281KB and
    4 of them
}
    
rule ffbecfbbcdddfafaebfba_exe {
strings:
        $s1 = "cross device link"
        $s2 = "executable format error"
        $s3 = "result out of range"
        $s4 = "directory not empty"
        $s5 = "invalid string position"
        $s6 = "operation canceled"
        $s7 = "GetConsoleOutputCP"
        $s8 = "LC_MONETARY"
        $s9 = "`local vftable'"
        $s10 = "spanish-venezuela"
        $s11 = "SetFilePointerEx"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "destination address required"
        $s15 = "GetCurrentThreadId"
        $s16 = "south-africa"
        $s17 = "resource deadlock would occur"
        $s18 = "device or resource busy"
        $s19 = "wrong protocol type"
        $s20 = "FindFirstFileExW"
condition:
    uint16(0) == 0x5a4d and filesize < 281KB and
    4 of them
}
    
rule faebacbabddcfefdabeaa_exe {
strings:
        $s1 = "cross device link"
        $s2 = "executable format error"
        $s3 = "result out of range"
        $s4 = "directory not empty"
        $s5 = "invalid string position"
        $s6 = "operation canceled"
        $s7 = "GetConsoleOutputCP"
        $s8 = "LC_MONETARY"
        $s9 = "`local vftable'"
        $s10 = "spanish-venezuela"
        $s11 = "SetFilePointerEx"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "destination address required"
        $s15 = "GetCurrentThreadId"
        $s16 = "south-africa"
        $s17 = "resource deadlock would occur"
        $s18 = "device or resource busy"
        $s19 = "wrong protocol type"
        $s20 = "FindFirstFileExW"
condition:
    uint16(0) == 0x5a4d and filesize < 245KB and
    4 of them
}
    
rule decacfdefeecbaaffddcadfd_exe {
strings:
        $s1 = "id-cmc-dataReturn"
        $s2 = "cross device link"
        $s3 = "X400-Content-Type"
        $s4 = "process_pci_value"
        $s5 = "encrypted track 2"
        $s6 = "Trailer Field: 0x"
        $s7 = "bad function call"
        $s8 = "OBJECT DESCRIPTOR"
        $s9 = "ts_check_imprints"
        $s10 = "CRLDistributionPoints"
        $s11 = "variable has no value"
        $s12 = "legacy_server_connect"
        $s13 = "extension value error"
        $s14 = "secure device signature"
        $s15 = "ssl_cipher_strength_sort"
        $s16 = "originatorSignatureValue"
        $s17 = "ssl_check_srvr_ecc_cert_and_alg"
        $s18 = "use_certificate_chain_file"
        $s19 = "Listing certs for store %s"
        $s20 = "extendedCertificateAttributes"
condition:
    uint16(0) == 0x5a4d and filesize < 2096KB and
    4 of them
}
    
rule faecabcecaeccdefbbccdccc_exe {
strings:
        $s1 = "id-cmc-dataReturn"
        $s2 = "process_pci_value"
        $s3 = "encrypted track 2"
        $s4 = "Trailer Field: 0x"
        $s5 = "try_decode_params"
        $s6 = "OBJECT DESCRIPTOR"
        $s7 = "ts_check_imprints"
        $s8 = "CRLDistributionPoints"
        $s9 = "variable has no value"
        $s10 = "legacy_server_connect"
        $s11 = "extension value error"
        $s12 = "tls_process_client_certificate"
        $s13 = "tls_construct_cert_status_body"
        $s14 = "secure device signature"
        $s15 = "tls_construct_hello_retry_request"
        $s16 = "ssl_cipher_strength_sort"
        $s17 = "originatorSignatureValue"
        $s18 = "ssl_check_srvr_ecc_cert_and_alg"
        $s19 = "use_certificate_chain_file"
        $s20 = "Listing certs for store %s"
condition:
    uint16(0) == 0x5a4d and filesize < 8502KB and
    4 of them
}
    
rule bfbefbfcdadecaddafaadaee_exe {
strings:
        $s1 = "id-cmc-dataReturn"
        $s2 = "process_pci_value"
        $s3 = "encrypted track 2"
        $s4 = "Trailer Field: 0x"
        $s5 = "try_decode_params"
        $s6 = "OBJECT DESCRIPTOR"
        $s7 = "ts_check_imprints"
        $s8 = "CRLDistributionPoints"
        $s9 = "variable has no value"
        $s10 = "legacy_server_connect"
        $s11 = "extension value error"
        $s12 = "tls_process_client_certificate"
        $s13 = "tls_construct_cert_status_body"
        $s14 = "secure device signature"
        $s15 = "tls_construct_hello_retry_request"
        $s16 = "ssl_cipher_strength_sort"
        $s17 = "originatorSignatureValue"
        $s18 = "ssl_check_srvr_ecc_cert_and_alg"
        $s19 = "use_certificate_chain_file"
        $s20 = "Listing certs for store %s"
condition:
    uint16(0) == 0x5a4d and filesize < 8503KB and
    4 of them
}
    
rule ebeefaddabbbfbffedaeccafffd_exe {
strings:
        $s1 = "id-cmc-dataReturn"
        $s2 = "process_pci_value"
        $s3 = "encrypted track 2"
        $s4 = "Trailer Field: 0x"
        $s5 = "try_decode_params"
        $s6 = "OBJECT DESCRIPTOR"
        $s7 = "ts_check_imprints"
        $s8 = "CRLDistributionPoints"
        $s9 = "variable has no value"
        $s10 = "legacy_server_connect"
        $s11 = "extension value error"
        $s12 = "tls_process_client_certificate"
        $s13 = "tls_construct_cert_status_body"
        $s14 = "secure device signature"
        $s15 = "tls_construct_hello_retry_request"
        $s16 = "ssl_cipher_strength_sort"
        $s17 = "originatorSignatureValue"
        $s18 = "ssl_check_srvr_ecc_cert_and_alg"
        $s19 = "use_certificate_chain_file"
        $s20 = "Listing certs for store %s"
condition:
    uint16(0) == 0x5a4d and filesize < 8503KB and
    4 of them
}
    
rule ebcadfeacfadbbdeff_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 2082KB and
    4 of them
}
    
rule dcdacbffeffdecafedaecbadf_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 2083KB and
    4 of them
}
    
rule ffcffabcafecedcaacebaee_exe {
strings:
        $s1 = "o*d;h;l;pBxP t"
        $s2 = "q8SZpIXc!i&"
        $s3 = "6B27J4~-\"0"
        $s4 = "Ck'^`:y{}Om"
        $s5 = "M2H;-`Wr.i&"
        $s6 = "&K6|BR$PQVy"
        $s7 = "+4,8-daxV')"
        $s8 = "e7_K:2pJ?xX"
        $s9 = "3a2e-fXTb70"
        $s10 = "juLPNvingeO"
        $s11 = "c{39(B446-591B-47"
        $s12 = "c|.4|_tT]eSP"
        $s13 = "y_GVMwkRfgSR"
        $s14 = "ARGETDIRyOK]"
        $s15 = "MSVCP140.dll"
        $s16 = "~!*$;:@&==U_"
        $s17 = "<9wLKZXdFwHv"
        $s18 = "W5M0MpCehiHz"
        $s19 = "F3EA6B5Ewg\""
        $s20 = "G'wK+:6<_oKb"
condition:
    uint16(0) == 0x5a4d and filesize < 954KB and
    4 of them
}
    
rule feeefbebebfdbefefbff_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1576KB and
    4 of them
}
    
rule cddebeafcdfcbfdaabdcebbe_exe {
strings:
        $s1 = "UpdateInstallMode"
        $s2 = "AI_INST_PRODCODES"
        $s3 = "bad function call"
        $s4 = "Common Start Menu"
        $s5 = "Enterprise Admins"
        $s6 = "cross device link"
        $s7 = "WarningMessageBox"
        $s8 = "RunAllExitActions"
        $s9 = "AI_SKIP_MSI_ELEVATION"
        $s10 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s11 = "Remote Management Users"
        $s12 = "SetLatestVersionPath"
        $s13 = "Various custom actions"
        $s14 = "executable format error"
        $s15 = "DOMAIN_NT_AUTHORITY"
        $s16 = "result out of range"
        $s17 = "directory not empty"
        $s18 = "Terminal Server License Servers"
        $s19 = "AiSkipUserExit"
        $s20 = "invalid string position"
condition:
    uint16(0) == 0x5a4d and filesize < 1283KB and
    4 of them
}
    
rule cffcbfcbfddbfaefadfdd_exe {
strings:
        $s1 = "UpdateInstallMode"
        $s2 = "AI_INST_PRODCODES"
        $s3 = "bad function call"
        $s4 = "Common Start Menu"
        $s5 = "Enterprise Admins"
        $s6 = "cross device link"
        $s7 = "WarningMessageBox"
        $s8 = "RunAllExitActions"
        $s9 = "AI_SKIP_MSI_ELEVATION"
        $s10 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s11 = "Remote Management Users"
        $s12 = "SetLatestVersionPath"
        $s13 = "Various custom actions"
        $s14 = "executable format error"
        $s15 = "DOMAIN_NT_AUTHORITY"
        $s16 = "result out of range"
        $s17 = "directory not empty"
        $s18 = "Terminal Server License Servers"
        $s19 = "AiSkipUserExit"
        $s20 = "invalid string position"
condition:
    uint16(0) == 0x5a4d and filesize < 1285KB and
    4 of them
}
    
rule dcfecdfdeacfffdbdcfdfebede_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1577KB and
    4 of them
}
    
rule ceebefcdddfcbdacdec_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 2087KB and
    4 of them
}
    
rule abfaecabdfcbcebfedfeddcafe_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1576KB and
    4 of them
}
    
rule cdbbedfdeebfceeabfba_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1569KB and
    4 of them
}
    
rule abaceabfabbafcdbdb_exe {
strings:
        $s1 = "RtlNtStatusToDosError"
        $s2 = "SetThreadPriority"
        $s3 = "TerminateProcess"
        $s4 = "RemoveDirectoryW"
        $s5 = "GetModuleHandleW"
        $s6 = "_initialize_wide_environment"
        $s7 = "__std_exception_copy"
        $s8 = "MSVCP140.dll"
        $s9 = "Unknown exception"
        $s10 = "RtlCaptureContext"
        $s11 = "OpenSCManagerW"
        $s12 = "\\splwow64.exe"
        $s13 = "NtRaiseHardError"
        $s14 = "NtSetSecurityObject"
        $s15 = "GetFileAttributesW"
        $s16 = "GetSystemTimeAsFileTime"
        $s17 = "ZwSetValueKey"
        $s18 = "OpenProcessToken"
        $s19 = "GetProcessHeap"
        $s20 = "SizeofResource"
condition:
    uint16(0) == 0x5a4d and filesize < 47KB and
    4 of them
}
    
rule ecebccccfbddbaaeafbbcfb_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 2082KB and
    4 of them
}
    
rule afdefbfbcffcecebeebf_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1428KB and
    4 of them
}
    
rule bceadbdfcbfcdcdfbfaaeaeafebe_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1569KB and
    4 of them
}
    
rule fefaeddbdacdfdffbbfcacadfd_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1569KB and
    4 of them
}
    
rule feedaedfbfeafacdedcddccbddabd_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1576KB and
    4 of them
}
    
rule deeceeccbbcdbffdbdbebc_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 2083KB and
    4 of them
}
    
rule eddbacccfeefcabaeedddabd_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1569KB and
    4 of them
}
    
rule cdeecdbfadbfacedfcfadd_exe {
strings:
        $s1 = "UpdateInstallMode"
        $s2 = "AI_INST_PRODCODES"
        $s3 = "bad function call"
        $s4 = "Common Start Menu"
        $s5 = "Enterprise Admins"
        $s6 = "cross device link"
        $s7 = "WarningMessageBox"
        $s8 = "RunAllExitActions"
        $s9 = "AI_SKIP_MSI_ELEVATION"
        $s10 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s11 = "Remote Management Users"
        $s12 = "SetLatestVersionPath"
        $s13 = "Various custom actions"
        $s14 = "executable format error"
        $s15 = "DOMAIN_NT_AUTHORITY"
        $s16 = "result out of range"
        $s17 = "directory not empty"
        $s18 = "Terminal Server License Servers"
        $s19 = "AiSkipUserExit"
        $s20 = "invalid string position"
condition:
    uint16(0) == 0x5a4d and filesize < 1283KB and
    4 of them
}
    
rule eaebecfcdcdcbedcbcabbedde_exe {
strings:
        $s1 = "!Xq{BA6T4D8"
        $s2 = "/.>= 603)Qs"
        $s3 = "n/zG_PR&EQS"
        $s4 = "H.\"<tOd7g "
        $s5 = "%YxJob/win_"
        $s6 = "ScopeGu6 CQ"
        $s7 = "AI_BOOTSTRRER AND"
        $s8 = "<9wLFI/iawHv"
        $s9 = "y_GVMwkRfgSR"
        $s10 = "MSVCP140.dll"
        $s11 = "ARGETDIRyOKx"
        $s12 = "p%\",;4vD;LA"
        $s13 = "H?^/PHEv;(_@"
        $s14 = "l7Ps[B}:Hu:j"
        $s15 = "ad allocationl6|U"
        $s16 = "0CRT$XCAG4'T&"
        $s17 = "c{39(B446-591B"
        $s18 = "splwow64.e^nop"
        $s19 = "{z?yyr;99xwvov"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 954KB and
    4 of them
}
    
rule facaabafdafeaddeddffdcfd_exe {
strings:
        $s1 = "Common Start Menu"
        $s2 = "Enterprise Admins"
        $s3 = "cross device link"
        $s4 = "german-luxembourg"
        $s5 = "RunAllExitActions"
        $s6 = "WarningMessageBox"
        $s7 = "AI_INST_PRODCODES"
        $s8 = "bad function call"
        $s9 = "english-caribbean"
        $s10 = "ValidateInstallFolder"
        $s11 = "AI_SKIP_MSI_ELEVATION"
        $s12 = "GRP_ACCESS_CONTROL_ASSISTANCE_OPS"
        $s13 = "Remote Management Users"
        $s14 = "SetLatestVersionPath"
        $s15 = "GRP_MONITORING_USERS"
        $s16 = "Various custom actions"
        $s17 = "executable format error"
        $s18 = "DOMAIN_NT_AUTHORITY"
        $s19 = "result out of range"
        $s20 = "directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1428KB and
    4 of them
}
    