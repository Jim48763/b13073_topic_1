import pe
rule cbbafdcfbadaacfffdcdfcece_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "Contact PrestoSoft"
        $s3 = "&Arguments:"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "Fi&nd what:"
        $s7 = "DeviceIoControl"
        $s8 = "Enter File Type"
        $s9 = "&Change Font..."
        $s10 = "FileDescription"
        $s11 = "SetFilePointerEx"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "SetCurrentDirectoryW"
        $s15 = "SetConsoleCursorInfo"
        $s16 = "Ignore &case"
        $s17 = "GetClassWord"
        $s18 = "SetEndOfFile"
        $s19 = "GetTickCount"
        $s20 = "FindFirstFileExA"
condition:
    uint16(0) == 0x5a4d and filesize < 1861KB and
    4 of them
}
    
rule bbbfcaffcccbdbedcbcfccaec_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "Contact PrestoSoft"
        $s3 = "&Arguments:"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "Fi&nd what:"
        $s7 = "DeviceIoControl"
        $s8 = "Enter File Type"
        $s9 = "&Change Font..."
        $s10 = "FileDescription"
        $s11 = "SetFilePointerEx"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "SetCurrentDirectoryW"
        $s15 = "SetConsoleCursorInfo"
        $s16 = "Ignore &case"
        $s17 = "GetClassWord"
        $s18 = "SetEndOfFile"
        $s19 = "GetTickCount"
        $s20 = "FindFirstFileExA"
condition:
    uint16(0) == 0x5a4d and filesize < 1630KB and
    4 of them
}
    
rule bcdffceeaffbdbbdfccffede_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "Contact PrestoSoft"
        $s3 = "&Arguments:"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "Fi&nd what:"
        $s7 = "DeviceIoControl"
        $s8 = "Enter File Type"
        $s9 = "&Change Font..."
        $s10 = "FileDescription"
        $s11 = "SetFilePointerEx"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "SetCurrentDirectoryW"
        $s15 = "SetConsoleCursorInfo"
        $s16 = "Ignore &case"
        $s17 = "GetClassWord"
        $s18 = "SetEndOfFile"
        $s19 = "GetTickCount"
        $s20 = "FindFirstFileExA"
condition:
    uint16(0) == 0x5a4d and filesize < 2224KB and
    4 of them
}
    
rule efffbdafffbaefaffdeeaebacddbfac_exe {
strings:
        $s1 = "*:2222/CMD_LOGIN*"
        $s2 = "*twitter.com/sessions"
        $s3 = "RegSetValueExW"
        $s4 = "NtResumeThread"
        $s5 = "VirtualAllocEx"
        $s6 = "*netload.in/index*"
        $s7 = "[PDef+]: %s"
        $s8 = "DeleteSecurityContext"
        $s9 = "DeviceIoControl"
        $s10 = "bebo Lifestream"
        $s11 = "Keep-Alive: 300"
        $s12 = "*whcms*dologin*"
        $s13 = "ApplyControlToken"
        $s14 = "DispatchMessageA"
        $s15 = "GetModuleHandleW"
        $s16 = "SetCurrentDirectoryA"
        $s17 = "WriteProcessMemory"
        $s18 = "GetAddrInfoW"
        $s19 = "FLN-Password"
        $s20 = "GetTickCount"
condition:
    uint16(0) == 0x5a4d and filesize < 99KB and
    4 of them
}
    
rule becdfabedfddffbfdecfbfac_exe {
strings:
        $s1 = " ]@S7=H\"U\"J QJH"
        $s2 = "\\RY=&ER$;ENj$eYu"
        $s3 = "?WRR1_W(5c(8a,&&c"
        $s4 = "FVN82\":,aNWPN"
        $s5 = "74THEREFENW{dY"
        $s6 = "\"yyrwy{TDC3&'"
        $s7 = "v><?8+(l='&"
        $s8 = "2a!06c H+p>"
        $s9 = "i{D}JZF_N>G"
        $s10 = "Gaoiqfe~xDU"
        $s11 = "cMhA|Ydg}+Q"
        $s12 = ">`zr/ya8U@|"
        $s13 = "te 6+$\"{>?"
        $s14 = "kxVvHMT_L.U"
        $s15 = "?|U[{D]=&.9"
        $s16 = "hjnXsdrGcmE"
        $s17 = "czAMICG!iya"
        $s18 = "I\"h/kEyobt"
        $s19 = "0V9@-~'d+k#"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 225KB and
    4 of them
}
    
rule ceedabbfefffacbeeafcadab_exe {
strings:
        $s1 = "could not create one way tunnel"
        $s2 = "Error on send new tunnel cmd"
        $s3 = " -v version show the version. "
        $s4 = " Eg: ./xxx -h -s ssocksd"
        $s5 = "Can Not Connect To %s!"
        $s6 = " -a about show the about pages"
        $s7 = "_Jv_RegisterClasses"
        $s8 = "WSAGetLastError"
        $s9 = "Not support  UDP?"
        $s10 = "GetModuleHandleA"
        $s11 = "__deregister_frame_info"
        $s12 = "EnterCriticalSection"
        $s13 = " -g connport set the connect port."
        $s14 = " following options:"
        $s15 = "gethostbyname"
        $s16 = "Error : bind port %d ."
        $s17 = "Server IP Address Error!"
        $s18 = "start listen port here"
        $s19 = "                http://rootkiter.com/EarthWrom/"
        $s20 = "libgcj-16.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 46KB and
    4 of them
}
    
rule fcdedcdbfbdcecbdbbddbda_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExA"
        $s5 = "%UALKY3}O9C"
        $s6 = "DialogBoxParamA"
        $s7 = "GetKeyboardType"
        $s8 = "GetThreadLocale"
        $s9 = "GetShortPathNameA"
        $s10 = "DispatchMessageA"
        $s11 = "GetModuleHandleA"
        $s12 = "CreateCompatibleDC"
        $s13 = "GetCurrentThreadId"
        $s14 = "SHBrowseForFolderA"
        $s15 = "EnableWindow"
        $s16 = "GetLocalTime"
        $s17 = "FPUMaskValue"
        $s18 = "SetEndOfFile"
        $s19 = "GetTickCount"
        $s20 = "RegEnumValueA"
condition:
    uint16(0) == 0x5a4d and filesize < 280KB and
    4 of them
}
    
rule fbbbfdfeeeceaddaeecee_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExA"
        $s5 = "%UALKY3}O9C"
        $s6 = "DialogBoxParamA"
        $s7 = "GetShortPathNameA"
        $s8 = "RemoveDirectoryA"
        $s9 = "ImageList_Create"
        $s10 = "DispatchMessageA"
        $s11 = "GetModuleHandleA"
        $s12 = "SHBrowseForFolderA"
        $s13 = "EnableWindow"
        $s14 = "GetTickCount"
        $s15 = "RegEnumValueA"
        $s16 = "SysListView32"
        $s17 = "InvalidateRect"
        $s18 = "CloseClipboard"
        $s19 = "LoadLibraryExA"
        $s20 = "SHAutoComplete"
condition:
    uint16(0) == 0x5a4d and filesize < 239KB and
    4 of them
}
    
rule dfeccebcacbbdafcdeda_exe {
strings:
        $s1 = "cross device link"
        $s2 = "english-caribbean"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "`vector destructor iterator'"
        $s5 = " exceeds the maximum of "
        $s6 = ": message length of "
        $s7 = "executable format error"
        $s8 = "directory not empty"
        $s9 = "result out of range"
        $s10 = "RegSetValueExA"
        $s11 = "   Q: What to tell my boss?"
        $s12 = "invalid string position"
        $s13 = "operation canceled"
        $s14 = "ThisObject:"
        $s15 = "LC_MONETARY"
        $s16 = "Hi Company,"
        $s17 = "english-jamaica"
        $s18 = "`local vftable'"
        $s19 = "GetKeyboardType"
        $s20 = "GetThreadLocale"
condition:
    uint16(0) == 0x5a4d and filesize < 546KB and
    4 of them
}
    
rule acacfcfdeaaacbdbbcfd_exe {
strings:
        $s1 = "RegSetValueExA"
        $s2 = "STAThreadAttribute"
        $s3 = "ProductName"
        $s4 = "_CorExeMain"
        $s5 = "VarFileInfo"
        $s6 = "GetKeyboardType"
        $s7 = "FileDescription"
        $s8 = "GetThreadLocale"
        $s9 = "GetShortPathNameA"
        $s10 = "GetModuleHandleA"
        $s11 = "CreateCompatibleBitmap"
        $s12 = "SetCurrentDirectoryA"
        $s13 = "GetCurrentThreadId"
        $s14 = "Hajfldtxhuhz"
        $s15 = "GetLocalTime"
        $s16 = "Synchronized"
        $s17 = "FPUMaskValue"
        $s18 = "SetEndOfFile"
        $s19 = "System.Resources"
        $s20 = "GeneratedCodeAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 230KB and
    4 of them
}
    
rule abaccbccdeeafdeaccfcbecccaac_exe {
strings:
        $s1 = "RegSetValueExA"
        $s2 = "GetThreadLocale"
        $s3 = "GetKeyboardType"
        $s4 = "GetShortPathNameA"
        $s5 = "GetModuleHandleA"
        $s6 = "EnterCriticalSection"
        $s7 = "GetCurrentThreadId"
        $s8 = "CreateCompatibleDC"
        $s9 = "GetLocalTime"
        $s10 = "SetEndOfFile"
        $s11 = "FPUMaskValue"
        $s12 = "GetDriveTypeA"
        $s13 = "RegOpenKeyExA"
        $s14 = "StretchDIBits"
        $s15 = "CreateDirectoryA"
        $s16 = "GetSysColor"
        $s17 = "PACKAGEINFO"
        $s18 = "ExitProcess"
        $s19 = "DestroyIcon"
        $s20 = "ExtractIconA"
condition:
    uint16(0) == 0x5a4d and filesize < 45KB and
    4 of them
}
    
rule eeeffddabdbdddcefbaeefbfbb_exe {
strings:
        $s1 = "YgLYYbLYVGmwDRtqX"
        $s2 = "ManagementBaseObject"
        $s3 = "\\root\\SecurityCenter2"
        $s4 = "get_ProcessorCount"
        $s5 = "_CorExeMain"
        $s6 = "SocketFlags"
        $s7 = "op_Equality"
        $s8 = "VarFileInfo"
        $s9 = "ComputeHash"
        $s10 = "set_ErrorDialog"
        $s11 = "IsWindowVisible"
        $s12 = "timeout 3 > NUL"
        $s13 = "otUWNRLOOOhkmpW"
        $s14 = "FileDescription"
        $s15 = "ToShortDateString"
        $s16 = "mBjllbEQlYrTYiQHj"
        $s17 = "FFLFRzkSCIIygLKi"
        $s18 = "vMFhHFBstSGu"
        $s19 = "Dictionary`2"
        $s20 = "ComputerInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 51KB and
    4 of them
}
    
rule bfffedbabfaacebaeebbdfefad_vbs {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 92KB and
    4 of them
}
    
rule dcbcbdcbdaadeeadbabddaecefacfb_ps {
strings:
        $s1 = "start-sleep -s 3"
        $s2 = "End Function"
        $s3 = "</script>"
        $s4 = "self.close"
        $s5 = "var_func"
        $s6 = "    }"
condition:
    uint16(0) == 0x5a4d and filesize < 60KB and
    4 of them
}
    
rule acfacddcccafdadaeecefb_exe {
strings:
        $s1 = "german-luxembourg"
        $s2 = "msctls_progress32"
        $s3 = "Py_SetProgramName"
        $s4 = "spanish-guatemala"
        $s5 = "english-caribbean"
        $s6 = "Runtime Error!"
        $s7 = "RegSetValueExA"
        $s8 = "SetConsoleCtrlHandler"
        $s9 = "GetConsoleOutputCP"
        $s10 = "%s\\%s-wininst.log"
        $s11 = "LC_MONETARY"
        $s12 = "english-jamaica"
        $s13 = "spanish-venezuela"
        $s14 = "chinese-singapore"
        $s15 = "SetThreadPriority"
        $s16 = "RemoveDirectoryA"
        $s17 = "DispatchMessageA"
        $s18 = "TerminateProcess"
        $s19 = "GetModuleHandleA"
        $s20 = "Installing files..."
condition:
    uint16(0) == 0x5a4d and filesize < 213KB and
    4 of them
}
    
rule ebcabeccafecfdfcfaddaf_exe {
strings:
        $s1 = "german-luxembourg"
        $s2 = "spanish-guatemala"
        $s3 = "english-caribbean"
        $s4 = "Runtime Error!"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "LC_MONETARY"
        $s9 = "english-jamaica"
        $s10 = "FileDescription"
        $s11 = "spanish-venezuela"
        $s12 = "chinese-singapore"
        $s13 = "TerminateProcess"
        $s14 = "GetModuleHandleA"
        $s15 = "PrivateBuild"
        $s16 = "south-africa"
        $s17 = "GetTickCount"
        $s18 = "trinidad & tobago"
        $s19 = "SetHandleCount"
        $s20 = "CorExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 144KB and
    4 of them
}
    
rule ecacbbecfecafdafeffbaeeecb_exe {
strings:
        $s1 = "_crt_debugger_hook"
        $s2 = "VarFileInfo"
        $s3 = "FileDescription"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleA"
        $s6 = "GetCurrentThreadId"
        $s7 = "GetTickCount"
        $s8 = "__wgetmainargs"
        $s9 = "FormatMessageW"
        $s10 = "_invoke_watson"
        $s11 = "    </security>"
        $s12 = "GetSystemTimeAsFileTime"
        $s13 = "OpenProcessToken"
        $s14 = "VirtualProtect"
        $s15 = "Copyright "
        $s16 = "GetCurrentProcess"
        $s17 = "_XcptFilter"
        $s18 = "ExitProcess"
        $s19 = "MSVCR90.dll"
        $s20 = "IsDebuggerPresent"
condition:
    uint16(0) == 0x5a4d and filesize < 321KB and
    4 of them
}
    
rule cdaffecfcabfaab_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "Uninitialized row"
        $s3 = "gamma table being rebuilt"
        $s4 = "CreateIoCompletionPort"
        $s5 = "invalid with alpha channel"
        $s6 = "non-positive height"
        $s7 = "Directory not empty"
        $s8 = "RegSetValueExA"
        $s9 = "Runtime Error!"
        $s10 = "A512548E76954B6E92C21055517615B0"
        $s11 = "invalid distance code"
        $s12 = "No child processes"
        $s13 = "Default IME"
        $s14 = "ProductName"
        $s15 = "Ctrl+PageUp"
        $s16 = "LocalSystem"
        $s17 = "FD@ul9L$(}f"
        $s18 = "4i5U6B738%9"
        $s19 = "FileDescription"
        $s20 = "Invalid IHDR data"
condition:
    uint16(0) == 0x5a4d and filesize < 985KB and
    4 of them
}
    
rule aaddafacdbfbfeadeefeeaf_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "_initialize_narrow_environment"
        $s4 = "FileDescription"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleW"
        $s7 = "__std_type_info_destroy_list"
        $s8 = "GetCurrentThreadId"
        $s9 = "GetSystemTimeAsFileTime"
        $s10 = "OpenProcessToken"
        $s11 = "VirtualProtect"
        $s12 = "LegalTrademarks"
        $s13 = "MiKTeX.org"
        $s14 = "IsProcessorFeaturePresent"
        $s15 = "GetCurrentProcess"
        $s16 = "_execute_onexit_table"
        $s17 = "ExitProcess"
        $s18 = "IsDebuggerPresent"
        $s19 = "_initialize_onexit_table"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 47KB and
    4 of them
}
    
rule dafbeccadfdebcbafcceecdcbdadaa_exe {
strings:
        $s1 = "\\drpreinject.dll"
        $s2 = "follow_systemwide"
        $s3 = "persist_lock_file"
        $s4 = "english-caribbean"
        $s5 = "vista_inject_at_create_process"
        $s6 = "switch_to_os_at_vmm_reset_limit"
        $s7 = "unsafe_ignore_eflags"
        $s8 = "detect_dangling_fcache"
        $s9 = "Runtime Error!"
        $s10 = "private_bb_ibl_targets_init"
        $s11 = "heap_commit_increment"
        $s12 = "SetConsoleCtrlHandler"
        $s13 = "unsafe_freeze_elide_sole_ubr"
        $s14 = "fast_client_decode"
        $s15 = "coarse_htable_load"
        $s16 = "ProductName"
        $s17 = "LC_MONETARY"
        $s18 = "IAT_convert"
        $s19 = "VarFileInfo"
        $s20 = "reset_at_switch_to_os_at_vmm_limit"
condition:
    uint16(0) == 0x5a4d and filesize < 484KB and
    4 of them
}
    
rule fababecddccceefadadcbabbbafdb_exe {
strings:
        $s1 = "bad function call"
        $s2 = "msctls_progress32"
        $s3 = "cross device link"
        $s4 = "english-caribbean"
        $s5 = "CreateThreadpoolTimer"
        $s6 = "`vector destructor iterator'"
        $s7 = "disconnect_native_host"
        $s8 = "executable format error"
        $s9 = "directory not empty"
        $s10 = "CryptReleaseContext"
        $s11 = "result out of range"
        $s12 = "   </security>"
        $s13 = "Runtime Error!"
        $s14 = "Failed to create a random name"
        $s15 = "invalid string position"
        $s16 = "operation canceled"
        $s17 = "GetConsoleOutputCP"
        $s18 = ".?AVbad_cast@std@@"
        $s19 = "LoadStringW"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 924KB and
    4 of them
}
    
rule faabaffcacdbbcbeabcfddedaddba_exe {
strings:
        $s1 = "ExpandEnvironment"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "HttpAddRequestHeadersW"
        $s4 = "Failed to initialize engine state."
        $s5 = "CertGetCertificateContextProperty"
        $s6 = "RegSetValueExW"
        $s7 = "ProgramFilesFolder"
        $s8 = "QueryServiceStatus"
        $s9 = "VersionNT64"
        $s10 = "CopyFileExW"
        $s11 = "MinorUpdate"
        $s12 = "VarFileInfo"
        $s13 = "BurnPipe.%s"
        $s14 = "`local vftable'"
        $s15 = ".ExecutableName"
        $s16 = "DialogBoxParamA"
        $s17 = "FileDescription"
        $s18 = "GetThreadLocale"
        $s19 = "InternetCrackUrlW"
        $s20 = "relatedbundle.cpp"
condition:
    uint16(0) == 0x5a4d and filesize < 831KB and
    4 of them
}
    
rule cdfbefacdcaebffeabd_exe {
strings:
        $s1 = "GetTouchInputInfo"
        $s2 = "cross device link"
        $s3 = "msctls_progress32"
        $s4 = "ivitada.  Kas soovite kohe taask"
        $s5 = "Hungarian=Ez az alkalmaz"
        $s6 = "SetDefaultDllDirectories"
        $s7 = "Desea reiniciarlo ahora?"
        $s8 = "Spanish=La instalaci"
        $s9 = "lreiz palaidiet uzst"
        $s10 = "o do build de %s falhou. "
        $s11 = "Swedish=%s av %s har h"
        $s12 = " versiune de %s nu este suportat"
        $s13 = "executable format error"
        $s14 = "tirmesi indiriliyor; bu i"
        $s15 = "cia nie je k dispoz"
        $s16 = "directory not empty"
        $s17 = "de, kas var ilgt da"
        $s18 = "chargement.  Erreur"
        $s19 = "re installasjonen p"
        $s20 = "result out of range"
condition:
    uint16(0) == 0x5a4d and filesize < 6817KB and
    4 of them
}
    
rule bfbbeedffdbecceaeecacceee_exe {
strings:
        $s1 = "$ArrayType$$$BY03$$CBD"
        $s2 = "__native_vcclrit_reason"
        $s3 = "RuntimeHelpers"
        $s4 = "\\[COMMAND\\](.*)?\\[\\/COMMAND\\]"
        $s5 = "_crt_debugger_hook"
        $s6 = "std.ios_base.width"
        $s7 = "PrePrepareMethodAttribute"
        $s8 = "CHyFxNPUMoi"
        $s9 = "_CorExeMain"
        $s10 = "Process32FirstW"
        $s11 = "ipStringToArray"
        $s12 = "wmiintegrator.exe"
        $s13 = "NwwOSjkSGmJPCkJcS"
        $s14 = "getThreadInterval"
        $s15 = "get_ModuleHandle"
        $s16 = "TerminateProcess"
        $s17 = "GetExceptionCode"
        $s18 = "GetCurrentThreadId"
        $s19 = "__CxxDetectRethrow"
        $s20 = "RegexOptions"
condition:
    uint16(0) == 0x5a4d and filesize < 263KB and
    4 of them
}
    
rule ebccaedbebfeedafeeebacabacf_exe {
strings:
        $s1 = "$ArrayType$$$BY03$$CBD"
        $s2 = "__native_vcclrit_reason"
        $s3 = "RuntimeHelpers"
        $s4 = "\\[COMMAND\\](.*)?\\[\\/COMMAND\\]"
        $s5 = "_crt_debugger_hook"
        $s6 = "std.ios_base.width"
        $s7 = "PrePrepareMethodAttribute"
        $s8 = "_CorExeMain"
        $s9 = "Process32FirstW"
        $s10 = "ipStringToArray"
        $s11 = "wmiintegrator.exe"
        $s12 = "getThreadInterval"
        $s13 = "get_ModuleHandle"
        $s14 = "TerminateProcess"
        $s15 = "GetExceptionCode"
        $s16 = "GetCurrentThreadId"
        $s17 = "__CxxDetectRethrow"
        $s18 = "XRUVeGSpOgBV"
        $s19 = "TsfvhxFHRlSv"
        $s20 = "RegexOptions"
condition:
    uint16(0) == 0x5a4d and filesize < 267KB and
    4 of them
}
    
rule adbfbbacedaffdeff_exe {
strings:
        $s1 = "$ArrayType$$$BY03$$CBD"
        $s2 = "__native_vcclrit_reason"
        $s3 = "RuntimeHelpers"
        $s4 = "\\[COMMAND\\](.*)?\\[\\/COMMAND\\]"
        $s5 = "_crt_debugger_hook"
        $s6 = "std.ios_base.width"
        $s7 = "PrePrepareMethodAttribute"
        $s8 = "_CorExeMain"
        $s9 = "Process32FirstW"
        $s10 = "ipStringToArray"
        $s11 = "wmiintegrator.exe"
        $s12 = "getThreadInterval"
        $s13 = "lzvPyuZBpOBIlWWB"
        $s14 = "get_ModuleHandle"
        $s15 = "TerminateProcess"
        $s16 = "GetExceptionCode"
        $s17 = "GetCurrentThreadId"
        $s18 = "__CxxDetectRethrow"
        $s19 = "RegexOptions"
        $s20 = "OLEAUT32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 263KB and
    4 of them
}
    
rule cdedcabefffdeabfcebbe_exe {
strings:
        $s1 = "$ArrayType$$$BY03$$CBD"
        $s2 = "__native_vcclrit_reason"
        $s3 = "RuntimeHelpers"
        $s4 = "\\[COMMAND\\](.*)?\\[\\/COMMAND\\]"
        $s5 = "_crt_debugger_hook"
        $s6 = "std.ios_base.width"
        $s7 = "PrePrepareMethodAttribute"
        $s8 = "_CorExeMain"
        $s9 = "Process32FirstW"
        $s10 = "ipStringToArray"
        $s11 = "wmiintegrator.exe"
        $s12 = "getThreadInterval"
        $s13 = "get_ModuleHandle"
        $s14 = "TerminateProcess"
        $s15 = "GetExceptionCode"
        $s16 = "GetCurrentThreadId"
        $s17 = "__CxxDetectRethrow"
        $s18 = "RegexOptions"
        $s19 = "OLEAUT32.dll"
        $s20 = "Windows log."
condition:
    uint16(0) == 0x5a4d and filesize < 263KB and
    4 of them
}
    
rule deefdfbafbdcbbcddabac_exe {
strings:
        $s1 = "$ArrayType$$$BY03$$CBD"
        $s2 = "__native_vcclrit_reason"
        $s3 = "RuntimeHelpers"
        $s4 = "\\[COMMAND\\](.*)?\\[\\/COMMAND\\]"
        $s5 = "_crt_debugger_hook"
        $s6 = "std.ios_base.width"
        $s7 = "PrePrepareMethodAttribute"
        $s8 = "FcBxVQKojtP"
        $s9 = "_CorExeMain"
        $s10 = "HLtEVdCvkao"
        $s11 = "Process32FirstW"
        $s12 = "ipStringToArray"
        $s13 = "wmiintegrator.exe"
        $s14 = "getThreadInterval"
        $s15 = "get_ModuleHandle"
        $s16 = "TerminateProcess"
        $s17 = "GetExceptionCode"
        $s18 = "GetCurrentThreadId"
        $s19 = "__CxxDetectRethrow"
        $s20 = "RegexOptions"
condition:
    uint16(0) == 0x5a4d and filesize < 267KB and
    4 of them
}
    
rule dceffcefacdcbbbdaeabddead_exe {
strings:
        $s1 = "$ArrayType$$$BY03$$CBD"
        $s2 = "__native_vcclrit_reason"
        $s3 = "RuntimeHelpers"
        $s4 = "\\[COMMAND\\](.*)?\\[\\/COMMAND\\]"
        $s5 = "_crt_debugger_hook"
        $s6 = "std.ios_base.width"
        $s7 = "PrePrepareMethodAttribute"
        $s8 = "_CorExeMain"
        $s9 = "Process32FirstW"
        $s10 = "ipStringToArray"
        $s11 = "wmiintegrator.exe"
        $s12 = "getThreadInterval"
        $s13 = "get_ModuleHandle"
        $s14 = "TerminateProcess"
        $s15 = "GetExceptionCode"
        $s16 = "GetCurrentThreadId"
        $s17 = "__CxxDetectRethrow"
        $s18 = "RegexOptions"
        $s19 = "OLEAUT32.dll"
        $s20 = "Windows log."
condition:
    uint16(0) == 0x5a4d and filesize < 265KB and
    4 of them
}
    
rule fabaeeddfffcabdbaaffccadca_exe {
strings:
        $s1 = "$ArrayType$$$BY03$$CBD"
        $s2 = "__native_vcclrit_reason"
        $s3 = "RuntimeHelpers"
        $s4 = "\\[COMMAND\\](.*)?\\[\\/COMMAND\\]"
        $s5 = "_crt_debugger_hook"
        $s6 = "std.ios_base.width"
        $s7 = "PrePrepareMethodAttribute"
        $s8 = "kSwsfnchgHR"
        $s9 = "_CorExeMain"
        $s10 = "JEpAKvCQWfd"
        $s11 = "Process32FirstW"
        $s12 = "ipStringToArray"
        $s13 = "wmiintegrator.exe"
        $s14 = "getThreadInterval"
        $s15 = "get_ModuleHandle"
        $s16 = "TerminateProcess"
        $s17 = "GetExceptionCode"
        $s18 = "GetCurrentThreadId"
        $s19 = "__CxxDetectRethrow"
        $s20 = "RegexOptions"
condition:
    uint16(0) == 0x5a4d and filesize < 267KB and
    4 of them
}
    
rule bfebfbfcdedcecacdcfac_exe {
strings:
        $s1 = "http\\shell\\open\\command"
        $s2 = "CryptReleaseContext"
        $s3 = "RegSetValueExA"
        $s4 = "uURLHistory"
        $s5 = "?456789:;<="
        $s6 = "Heap32First"
        $s7 = "RAS Passwords |"
        $s8 = "ProgramFilesDir"
        $s9 = "Process32FirstW"
        $s10 = "ReadProcessMemory"
        $s11 = "DispatchMessageA"
        $s12 = "GetModuleHandleA"
        $s13 = "GetCurrentThreadId"
        $s14 = "6UnitSandBox"
        $s15 = "mozcrt19.dll"
        $s16 = "Thread32Next"
        $s17 = ";i`3CGZ6<VuC"
        $s18 = "GetTickCount"
        $s19 = "RegEnumValueA"
        $s20 = "PK11_FreeSlot"
condition:
    uint16(0) == 0x5a4d and filesize < 288KB and
    4 of them
}
    
rule acbdbbdcfbdebecbcdddadffdeacbbbf_wsf {
strings:
        $s1 = "</script>"
        $s2 = "<package>"
        $s3 = "</job>"
condition:
    uint16(0) == 0x5a4d and filesize < 122KB and
    8 of them
}
    
rule bbaccbdbdcaffbdebbda_exe {
strings:
        $s1 = "meQueryDosDeviceW"
        $s2 = "](wlb=LM%<k"
        $s3 = "aBm*IS0U6A'"
        $s4 = "tALocalFileTimeToFileTime"
        $s5 = "x^ZVmN,}\\L"
        $s6 = "KERNEL32.dll"
        $s7 = "FatalAppExitW"
        $s8 = "BuildCommDCBW"
        $s9 = "eaWriteFileEx"
        $s10 = "GetGeoInfoW"
        $s11 = "nalstrcmp"
        $s12 = "Y(yn\\O@S"
        $s13 = "\\\")8KwY"
        $s14 = "(\\n%@)\""
        $s15 = "|gK{<dw&"
        $s16 = "PV^'L=-N"
        $s17 = "_)#[P h5"
        $s18 = "PFs=6)MW"
        $s19 = "=7%<\"_:"
        $s20 = "6kT:@q-L"
condition:
    uint16(0) == 0x5a4d and filesize < 81KB and
    4 of them
}
    
rule caaeaccccfbffecfdcdaedccadcec_bat {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 5KB and
    all of them
}
    
rule bacbcfdefadddffdbbbddddffcded_exe {
strings:
        $s1 = "Picasa Updater"
        $s2 = "STAThreadAttribute"
        $s3 = "ProductName"
        $s4 = "_CorExeMain"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "Synchronized"
        $s8 = "PerformClick"
        $s9 = "set_TabIndex"
        $s10 = "System.Resources"
        $s11 = "PerformLayout"
        $s12 = "GeneratedCodeAttribute"
        $s13 = "ResourceManager"
        $s14 = "CultureInfo"
        $s15 = "IDisposable"
        $s16 = "Google Inc."
        $s17 = "set_Opacity"
        $s18 = "set_Enabled"
        $s19 = "set_Location"
        $s20 = "EventHandler"
condition:
    uint16(0) == 0x5a4d and filesize < 573KB and
    4 of them
}
    
rule addeedfedadccaeceddbafcb_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "FileDescription"
        $s5 = "GetModuleHandleA"
        $s6 = "EnterCriticalSection"
        $s7 = "Microsoft Corporation"
        $s8 = "GetCurrentThreadId"
        $s9 = "GetSystemInfo"
        $s10 = "CorExitProcess"
        $s11 = "SetHandleCount"
        $s12 = "VirtualProtect"
        $s13 = "HeapDestroy"
        $s14 = "KERNEL32.dll"
        $s15 = "VirtualQuery"
        $s16 = "GetProcAddress"
        $s17 = "OriginalFilename"
        $s18 = "CoCreateInstance"
        $s19 = "DOMAIN error"
        $s20 = "VirtualAlloc"
condition:
    uint16(0) == 0x5a4d and filesize < 61KB and
    4 of them
}
    
rule cfccaeeebdaaaeeacdefdfd_exe {
strings:
        $s1 = "%s: %s and %s are the same file"
        $s2 = "Unable to authenticate"
        $s3 = "CryptReleaseContext"
        $s4 = "RegSetValueExA"
        $s5 = "had^`ZLJOK?"
        $s6 = "DIRTHUMB;%s"
        $s7 = "(v+q#4\"KPY"
        $s8 = "DIoR`#[=QdO"
        $s9 = "WSAGetLastError"
        $s10 = "Resource shortage"
        $s11 = "%s\\iosystem.dll"
        $s12 = "GetComputerNameA"
        $s13 = "GetModuleHandleA"
        $s14 = "connect %host %port\\n"
        $s15 = "internal error in shorten_name"
        $s16 = "Bogus message code %d"
        $s17 = "Repeat key exchange"
        $s18 = "CreateCompatibleDC"
        $s19 = "too much data sent"
        $s20 = "sqlite3_open"
condition:
    uint16(0) == 0x5a4d and filesize < 575KB and
    4 of them
}
    
rule afefaebbbfeeabdeeededabcbadefd_exe {
strings:
        $s1 = "%s: %s and %s are the same file"
        $s2 = "Unable to authenticate"
        $s3 = "CryptReleaseContext"
        $s4 = "RegSetValueExA"
        $s5 = "had^`ZLJOK?"
        $s6 = "DIRTHUMB;%s"
        $s7 = "{)B'ys.*KVc"
        $s8 = "WSAGetLastError"
        $s9 = "Resource shortage"
        $s10 = "%s\\iosystem.dll"
        $s11 = "GetComputerNameA"
        $s12 = "GetModuleHandleA"
        $s13 = "connect %host %port\\n"
        $s14 = "internal error in shorten_name"
        $s15 = "Bogus message code %d"
        $s16 = "Repeat key exchange"
        $s17 = "CreateCompatibleDC"
        $s18 = "too much data sent"
        $s19 = "sqlite3_open"
        $s20 = "mozcrt19.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 569KB and
    4 of them
}
    
rule abbdaccabccabfebebdabbffc_exe {
strings:
        $s1 = "NtQueryAttributesFile"
        $s2 = "RegSetValueExW"
        $s3 = "LoadStringW"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "ERsISe\"L5Q"
        $s7 = "SystemPartition"
        $s8 = "win:Informational"
        $s9 = "TerminateProcess"
        $s10 = "GetModuleHandleA"
        $s11 = "Microsoft Corporation"
        $s12 = "\\EFI\\Microsoft\\Boot\\BCD"
        $s13 = "GetCurrentThreadId"
        $s14 = "        type=\"win32\"/>"
        $s15 = "RtlLengthSid"
        $s16 = "GetTickCount"
        $s17 = "OLEAUT32.dll"
        $s18 = "    </application>"
        $s19 = "__wgetmainargs"
        $s20 = "RtlAddAccessAllowedAceEx"
condition:
    uint16(0) == 0x5a4d and filesize < 161KB and
    4 of them
}
    
rule becdaedbeadffcbbeacad_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "LoadAcceleratorsW"
        $s3 = "msctls_progress32"
        $s4 = "english-caribbean"
        $s5 = "service_provider_name"
        $s6 = "CEFEGHIKLGIJFFFEEEEGHCEFFHI=?@JLMBBB"
        $s7 = ")+,%'(\"!#   444~~~"
        $s8 = "Are you sure to delete \" %s \""
        $s9 = "Add  Information     Insert"
        $s10 = "Fmsctls_statusbar32"
        $s11 = "\"%*&(2$&.!$)!$,%)."
        $s12 = "Find the specified text"
        $s13 = "`Rv[Mv]PvZKqtf"
        $s14 = "RegSetValueExW"
        $s15 = "CAliEditorView"
        $s16 = "CoRegisterMessageFilter"
        $s17 = "SetConsoleCtrlHandler"
        $s18 = "CoDisconnectObject"
        $s19 = ".?AVCPreviewView@@"
        $s20 = "J?S4+E4+E.(A( >.&E"
condition:
    uint16(0) == 0x5a4d and filesize < 1537KB and
    4 of them
}
    
rule efcbccbbeeeffbcaafbbceabedce_ps {
strings:
        $s1 = "while($true)"
        $s2 = "Function INF {"
        $s3 = "    return $Response"
        $s4 = "DropToStartup"
        $s5 = "    } catch { }"
        $s6 = "        break }"
        $s7 = "        'TR' {"
        $s8 = "break }"
        $s9 = "'Un' {"
        $s10 = "    try"
        $s11 = "    }"
condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    4 of them
}
    
rule acafbfccedbefeeadba_exe {
strings:
        $s1 = "gethostbyname"
        $s2 = "Process32Next"
        $s3 = "MethCallEngine"
        $s4 = "DllFunctionCall"
        $s5 = "RtlMoveMemory"
        $s6 = "GetProcAddress"
        $s7 = "CreateShortcut"
        $s8 = "VS_VERSION_INFO"
        $s9 = "LoadLibraryW"
        $s10 = "MSVBVM60.DLL"
        $s11 = "TargetPath"
        $s12 = "NsetPs&nPs?|Ps"
        $s13 = "IconLocation"
        $s14 = "akTSGsTqp"
        $s15 = "~eSi'TUf"
        $s16 = "AVjWIkGF"
        $s17 = "kernel32"
        $s18 = "s<# M+)"
        $s19 = "vYcq=Fo"
        $s20 = "%45.wAg"
condition:
    uint16(0) == 0x5a4d and filesize < 53KB and
    4 of them
}
    
rule beffddcadafcbcfaafeee_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "nCKOzulMpcz1"
        $s4 = "N3h1cNUSLuwl"
        $s5 = "MethCallEngine"
        $s6 = " hIB6Ri?wj"
        $s7 = "a4ZHruHW8QV48"
        $s8 = "OriginalFilename"
        $s9 = "VS_VERSION_INFO"
        $s10 = "Translation"
        $s11 = "FileVersion"
        $s12 = "InternalName"
        $s13 = "MSVBVM60.DLL"
        $s14 = "BsOoPsh;Rs"
        $s15 = "huogvFtU4"
        $s16 = "OsDROs\\TPs"
        $s17 = "U%Mi&>h5"
        $s18 = "Qs&nPssnPs"
        $s19 = "<E,W,|!."
        $s20 = "VoeatKti"
condition:
    uint16(0) == 0x5a4d and filesize < 140KB and
    4 of them
}
    
rule fabbdcaabefbfeddeefaafeebab_exe {
strings:
        $s1 = "gethostbyname"
        $s2 = "Process32Next"
        $s3 = "MethCallEngine"
        $s4 = "DllFunctionCall"
        $s5 = "RtlMoveMemory"
        $s6 = "GetProcAddress"
        $s7 = "CreateShortcut"
        $s8 = "NMAmNkwK53"
        $s9 = "VS_VERSION_INFO"
        $s10 = "CompanyName"
        $s11 = "LoadLibraryW"
        $s12 = "MSVBVM60.DLL"
        $s13 = "TargetPath"
        $s14 = "IconLocation"
        $s15 = "vGHop56o7po667"
        $s16 = "NsetPs&nPs"
        $s17 = "BobCYXzh"
        $s18 = "kernel32"
        $s19 = "VB5!6&*"
        $s20 = "wsock32"
condition:
    uint16(0) == 0x5a4d and filesize < 81KB and
    4 of them
}
    
rule abcaacfacdafccaeaecddfbfefecedb_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "N3h1cNUSLuwl"
        $s4 = "RefeGieortioreykrtnymrnty"
        $s5 = "MethCallEngine"
        $s6 = "DNlbzKLXKoz1"
        $s7 = "a4ZHruHW8QV48"
        $s8 = "OriginalFilename"
        $s9 = "VS_VERSION_INFO"
        $s10 = "Translation"
        $s11 = "FileVersion"
        $s12 = "InternalName"
        $s13 = "MSVBVM60.DLL"
        $s14 = "JeOxlnvQ.exe"
        $s15 = "BsOoPsh;Rs"
        $s16 = "OsDROs\\TPs"
        $s17 = "JeOxlnvQ"
        $s18 = "jGVc:~ k"
        $s19 = "/80nXINF"
        $s20 = "Qs&nPssnPs"
condition:
    uint16(0) == 0x5a4d and filesize < 161KB and
    4 of them
}
    
rule cddbabfadbfefbbafdffcbc_exe {
strings:
        $s1 = "NepIJsETgHM"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "MethCallEngine"
        $s5 = "OriginalFilename"
        $s6 = "VS_VERSION_INFO"
        $s7 = "Translation"
        $s8 = "FileVersion"
        $s9 = "InternalName"
        $s10 = "MSVBVM60.DLL"
        $s11 = "BsOoPsh;Rs"
        $s12 = "T+:D<}F{R"
        $s13 = "PsDROs\\TPs"
        $s14 = "uvvzdZFTy"
        $s15 = "EGNvhrbJ"
        $s16 = "Picture1"
        $s17 = "Sx4;e*yN"
        $s18 = "Qs&nPssnPs"
        $s19 = "?bdkMXbw"
        $s20 = "#-d2\"2="
condition:
    uint16(0) == 0x5a4d and filesize < 116KB and
    4 of them
}
    