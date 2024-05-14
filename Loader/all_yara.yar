import pe
rule dbdafecdcdbaaedfeadaee_exe {
strings:
        $s1 = "BufferedPaintInit"
        $s2 = "GetKeyboardLayout"
        $s3 = "GetTouchInputInfo"
        $s4 = "LoadAcceleratorsW"
        $s5 = "msctls_trackbar32"
        $s6 = "Sorry, can not do it."
        $s7 = "GradientStartNormal"
        $s8 = "AfxmReleaseManagedReferences"
        $s9 = "SetDefaultDllDirectories"
        $s10 = "TextExtendedDisabled"
        $s11 = "RecentFrameAlignment"
        $s12 = "CMFCRibbonMainPanel"
        $s13 = "HighlightedDisabled"
        $s14 = "CMFCToolBarFontComboBox"
        $s15 = "OleLockRunning"
        $s16 = "GetWindowTheme"
        $s17 = "RegSetValueExW"
        $s18 = "GetConsoleOutputCP"
        $s19 = "CoDisconnectObject"
        $s20 = "BeginBufferedPaint"
condition:
    uint16(0) == 0x5a4d and filesize < 2755KB and
    4 of them
}
    
rule cccafbaddddbcfbece_exe {
strings:
        $s1 = "_URC_END_OF_STACK"
        $s2 = "StartAddressOfRawData"
        $s3 = "guard variable for "
        $s4 = "covariant return thunk to "
        $s5 = "_pthread_key_sch_shmem"
        $s6 = "processthreadsapi.h"
        $s7 = "VT_VERSIONED_STREAM"
        $s8 = "NumberOfLinenumbers"
        $s9 = "_beginthreadex"
        $s10 = "SizeOfUninitializedData"
        $s11 = "_ValidateImageBase"
        $s12 = ".check_managed_app"
        $s13 = "_URC_HANDLER_FOUND"
        $s14 = "short unsigned int"
        $s15 = "X86_ARCH_CMPXCHG8B"
        $s16 = "ProductName"
        $s17 = "gbl-ctors.h"
        $s18 = "FireCat.png"
        $s19 = "VarFileInfo"
        $s20 = "maxSections"
condition:
    uint16(0) == 0x5a4d and filesize < 892KB and
    4 of them
}
    
rule abacccefaecfdeabccdfded_exe {
strings:
        $s1 = "VirtualAllocEx"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "H(coB!np6Ov"
        $s5 = "FileDescription"
        $s6 = "GetModuleHandleA"
        $s7 = "Greater Manchester1"
        $s8 = "l&(xpLCw|J"
        $s9 = "y1{R\"*G<:"
        $s10 = "ur5Fj}LI{V"
        $s11 = "ufMgWHybLv"
        $s12 = "B0x_P&ro@C"
        $s13 = "$BHp(7qL<M"
        $s14 = "KERNEL32.dll"
        $s15 = "ADVAPI32.dll"
        $s16 = "Jersey City1"
        $s17 = "GetProcAddress"
        $s18 = "OriginalFilename"
        $s19 = "Classic Shell"
        $s20 = "GetTextCharset"
condition:
    uint16(0) == 0x5a4d and filesize < 230KB and
    4 of them
}
    
rule bceabecfafeccfabedcdbdedceb_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "LoadStringA"
        $s3 = "DialogBoxParamA"
        $s4 = "TerminateProcess"
        $s5 = "SetFilePointerEx"
        $s6 = "ImageList_Create"
        $s7 = "DispatchMessageA"
        $s8 = "SetThreadStackGuarantee"
        $s9 = "OovP:OpayluD"
        $s10 = "&Small Icons"
        $s11 = "UpdateWindow"
        $s12 = "SysListView32"
        $s13 = "RtlCaptureContext"
        $s14 = "LoadLibraryExW"
        $s15 = "CorExitProcess"
        $s16 = "    </security>"
        $s17 = "DeleteCriticalSection"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "OOO Inversum0"
        $s20 = "About Controls"
condition:
    uint16(0) == 0x5a4d and filesize < 511KB and
    4 of them
}
    
rule bfebadbbfbfedefbcefecbcf_exe {
strings:
        $s1 = "CoInitializeEx"
        $s2 = "GetConsoleOutputCP"
        $s3 = "`local vftable'"
        $s4 = "DialogBoxParamW"
        $s5 = "TerminateProcess"
        $s6 = "SetFilePointerEx"
        $s7 = "GetCurrentThreadId"
        $s8 = "GetLocalTime"
        $s9 = "kind:picture"
        $s10 = "Sample Query"
        $s11 = "PropVariantClear"
        $s12 = "FindFirstFileExW"
        $s13 = "PKERNEL32.dll"
        $s14 = "GetWindowRect"
        $s15 = "#GG=`i^rY#6|L"
        $s16 = "support@pro-kon.ru0"
        $s17 = "Unknown exception"
        $s18 = "RtlCaptureContext"
        $s19 = "LoadLibraryExW"
        $s20 = "CorExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 391KB and
    4 of them
}
    
rule dcdecaaaeeeedcfededecb_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "GetEnvironmentStrings"
        $s5 = "invalid string position"
        $s6 = "GetConsoleOutputCP"
        $s7 = "Kristen ITC"
        $s8 = "LC_MONETARY"
        $s9 = "english-jamaica"
        $s10 = "`local vftable'"
        $s11 = "spanish-venezuela"
        $s12 = "TerminateProcess"
        $s13 = "Hear Them Speak!"
        $s14 = "DispatchMessageW"
        $s15 = "CreateCompatibleDC"
        $s16 = "GetCurrentThreadId"
        $s17 = "GetTickCount"
        $s18 = "Both Genders"
        $s19 = "south-africa"
        $s20 = "~[u(KZfCD'kZ"
condition:
    uint16(0) == 0x5a4d and filesize < 505KB and
    4 of them
}
    
rule fcbdadccfdfeffdcccfecff_exe {
strings:
        $s1 = "BufferedPaintInit"
        $s2 = "OleLoadFromStream"
        $s3 = "DRAGDROP_S_CANCEL"
        $s4 = "spanish-guatemala"
        $s5 = "DISP_E_BADVARTYPE"
        $s6 = "german-luxembourg"
        $s7 = "GetTouchInputInfo"
        $s8 = "request complete."
        $s9 = "%s: Execute '%s'."
        $s10 = ".\\UserImages.bmp"
        $s11 = "cross device link"
        $s12 = "WM_MDIICONARRANGE"
        $s13 = "english-caribbean"
        $s14 = "msctls_progress32"
        $s15 = "Create a new document"
        $s16 = "Incorrect use of null"
        $s17 = "Select &context menu:"
        $s18 = "DISP_E_NOTACOLLECTION"
        $s19 = "IDB_RIBBON_PANEL_BACK"
        $s20 = "OLE_E_CANT_GETMONIKER"
condition:
    uint16(0) == 0x5a4d and filesize < 12274KB and
    4 of them
}
    
rule fcecbdaafbadefadefddebccac_exe {
strings:
        $s1 = "dtoa_lock_cleanup"
        $s2 = "_URC_END_OF_STACK"
        $s3 = "valid_lead_string"
        $s4 = "NSt6locale5facetE"
        $s5 = "StartAddressOfRawData"
        $s6 = "guard variable for "
        $s7 = "covariant return thunk to "
        $s8 = "_pthread_key_sch_shmem"
        $s9 = "processthreadsapi.h"
        $s10 = "VT_VERSIONED_STREAM"
        $s11 = "NumberOfLinenumbers"
        $s12 = "*__bigtens_D2A"
        $s13 = "\"__rshift_D2A"
        $s14 = "_beginthreadex"
        $s15 = "SizeOfUninitializedData"
        $s16 = "_ValidateImageBase"
        $s17 = ".check_managed_app"
        $s18 = "_URC_HANDLER_FOUND"
        $s19 = "short unsigned int"
        $s20 = "X86_ARCH_CMPXCHG8B"
condition:
    uint16(0) == 0x5a4d and filesize < 1183KB and
    4 of them
}
    
rule fabbdeceabcecfcafaebdcbaf_exe {
strings:
        $s1 = "NetCostSample.exe"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "CoInitializeEx"
        $s4 = "`local vftable'"
        $s5 = "TerminateProcess"
        $s6 = "SetFilePointerEx"
        $s7 = "DispatchMessageW"
        $s8 = "SetThreadStackGuarantee"
        $s9 = "lGL(,g=7Xh{g"
        $s10 = "GetLocalTime"
        $s11 = "GetAddrInfoW"
        $s12 = "Unknown exception"
        $s13 = "RtlCaptureContext"
        $s14 = "LoadLibraryExW"
        $s15 = "CorExitProcess"
        $s16 = "`udt returning'"
        $s17 = "    </security>"
        $s18 = "DeleteCriticalSection"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "Error Code: 0x%x"
condition:
    uint16(0) == 0x5a4d and filesize < 370KB and
    4 of them
}
    
rule bacabafbefcafeafeacbaccaf_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "LoadAcceleratorsW"
        $s4 = "bad function call"
        $s5 = "english-caribbean"
        $s6 = "Runtime Error!"
        $s7 = "SetConsoleCtrlHandler"
        $s8 = "GetConsoleOutputCP"
        $s9 = "LoadStringW"
        $s10 = "4)S}mVd'Ppl"
        $s11 = "LC_MONETARY"
        $s12 = "1zuy~G\"as["
        $s13 = "english-jamaica"
        $s14 = "`local vftable'"
        $s15 = "DialogBoxParamW"
        $s16 = "spanish-venezuela"
        $s17 = "TerminateProcess"
        $s18 = "SetFilePointerEx"
        $s19 = "DispatchMessageW"
        $s20 = "SetThreadStackGuarantee"
condition:
    uint16(0) == 0x5a4d and filesize < 971KB and
    4 of them
}
    
rule fafcaafcdaadbcabdfbdbabac_exe {
strings:
        $s1 = "dtoa_lock_cleanup"
        $s2 = "_URC_END_OF_STACK"
        $s3 = "StartAddressOfRawData"
        $s4 = "guard variable for "
        $s5 = " __shmem_init_sjlj_once"
        $s6 = "__shmem_grabber_use_fc_key"
        $s7 = "covariant return thunk to "
        $s8 = "KADWEGAFSTWUATQFFFFkxcEEF"
        $s9 = "_pthread_key_sch_shmem"
        $s10 = "processthreadsapi.h"
        $s11 = "NumberOfLinenumbers"
        $s12 = "VT_VERSIONED_STREAM"
        $s13 = ")__bigtens_D2A"
        $s14 = "_beginthreadex"
        $s15 = "SizeOfUninitializedData"
        $s16 = "_ValidateImageBase"
        $s17 = ")check_managed_app"
        $s18 = "_URC_HANDLER_FOUND"
        $s19 = "short unsigned int"
        $s20 = "X86_ARCH_CMPXCHG8B"
condition:
    uint16(0) == 0x5a4d and filesize < 865KB and
    4 of them
}
    
rule cdccfbccecefecacbbfbfacfdcacd_exe {
strings:
        $s1 = "VirtualAllocEx"
        $s2 = "UwoQwVwdwxvWrGrvHuuru"
        $s3 = "QwJhwFrqwh{wWkuhdg"
        $s4 = "?456789:;<="
        $s5 = "fun4it|sqtfirtizqj4"
        $s6 = "WriteProcessMemory"
        $s7 = "ZsijknsjiY~ujJwwtw"
        $s8 = "DigiCert1%0#"
        $s9 = "GetTickCount"
        $s10 = "SetThreadContext"
        $s11 = "Greater Manchester1"
        $s12 = "WyqHwjfyjZxjwYmwjfi"
        $s13 = "GetFileAttributesW"
        $s14 = "*FQQZXJWXUWTKNQJ*"
        $s15 = "GetDriveTypeA"
        $s16 = "GetProcessHeap"
        $s17 = "Kdc23icmQoc21f"
        $s18 = "QiwLjyUwthjizwjFiiwjxx"
        $s19 = "OguJhwSurfhgxuhDgguhvv"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 53KB and
    4 of them
}
    
rule cfcdabfbbaeadbcabfaeefdfdae_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExA"
        $s5 = "VarFileInfo"
        $s6 = "IsWindowVisible"
        $s7 = "DialogBoxParamA"
        $s8 = "FileDescription"
        $s9 = "GetModuleHandleA"
        $s10 = "DispatchMessageA"
        $s11 = "SHBrowseForFolderA"
        $s12 = "EnableWindow"
        $s13 = "GetTickCount"
        $s14 = "SetWindowPos"
        $s15 = "RegEnumValueA"
        $s16 = "SysListView32"
        $s17 = "GetWindowRect"
        $s18 = "IIDFromString"
        $s19 = "CloseClipboard"
        $s20 = "InvalidateRect"
condition:
    uint16(0) == 0x5a4d and filesize < 85KB and
    4 of them
}
    
rule cfedbcadedeeabdbfbeefffded_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "Runtime Error!"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "GetConsoleOutputCP"
        $s7 = "LoadStringW"
        $s8 = "LC_MONETARY"
        $s9 = "english-jamaica"
        $s10 = "`local vftable'"
        $s11 = "DialogBoxParamW"
        $s12 = "spanish-venezuela"
        $s13 = "TerminateProcess"
        $s14 = "SetFilePointerEx"
        $s15 = "DispatchMessageW"
        $s16 = "SetThreadStackGuarantee"
        $s17 = "GetCurrentThreadId"
        $s18 = "OLEAUT32.dll"
        $s19 = "EnableWindow"
        $s20 = "south-africa"
condition:
    uint16(0) == 0x5a4d and filesize < 603KB and
    4 of them
}
    
rule ccfaafcdaebeecaeabfdebedfe_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "GetEnvironmentStrings"
        $s3 = "GetSystemPowerStatus"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "VarFileInfo"
        $s6 = "LC_MONETARY"
        $s7 = "english-jamaica"
        $s8 = "AFX_DIALOG_LAYOUT"
        $s9 = "spanish-venezuela"
        $s10 = "TerminateProcess"
        $s11 = "GetModuleHandleW"
        $s12 = "SetComputerNameW"
        $s13 = "GetCurrentDirectoryA"
        $s14 = "EnterCriticalSection"
        $s15 = "SetConsoleCursorInfo"
        $s16 = "GetCurrentThreadId"
        $s17 = "spanish-costa rica"
        $s18 = "ContinueDebugEvent"
        $s19 = "south-africa"
        $s20 = "SetLocalTime"
condition:
    uint16(0) == 0x5a4d and filesize < 148KB and
    4 of them
}
    
rule debdcbbfdecfdddeeaebbcd_exe {
strings:
        $s1 = "StartAddressOfRawData"
        $s2 = "_Jv_RegisterClasses"
        $s3 = "short unsigned int"
        $s4 = "gbl-ctors.h"
        $s5 = "wnkl;M14RY^"
        $s6 = "X86_TUNE_USE_SAHF"
        $s7 = "ix86_tune_indices"
        $s8 = "GetModuleHandleA"
        $s9 = "VT_ILLEGALMASKED"
        $s10 = "X86_TUNE_UNROLL_STRLEN"
        $s11 = "InitializeCriticalSection"
        $s12 = "ContextFlags"
        $s13 = "OwningThread"
        $s14 = "_startupinfo"
        $s15 = "__cpu_features_init"
        $s16 = "LockSemaphore"
        $s17 = "key_dtor_list"
        $s18 = "X86_ARCH_LAST"
        $s19 = "complex float"
        $s20 = "dummy_environ"
condition:
    uint16(0) == 0x5a4d and filesize < 631KB and
    4 of them
}
    
rule fcdfbadddaacdebffcdccfb_exe {
strings:
        $s1 = "dtoa_lock_cleanup"
        $s2 = "_URC_END_OF_STACK"
        $s3 = "valid_lead_string"
        $s4 = "NSt6locale5facetE"
        $s5 = "StartAddressOfRawData"
        $s6 = "guard variable for "
        $s7 = " __shmem_init_sjlj_once"
        $s8 = "__shmem_grabber_use_fc_key"
        $s9 = "covariant return thunk to "
        $s10 = "_pthread_key_sch_shmem"
        $s11 = "processthreadsapi.h"
        $s12 = "NumberOfLinenumbers"
        $s13 = "VT_VERSIONED_STREAM"
        $s14 = "__copybits_D2A"
        $s15 = "_beginthreadex"
        $s16 = "SizeOfUninitializedData"
        $s17 = "_ValidateImageBase"
        $s18 = ")check_managed_app"
        $s19 = "_URC_HANDLER_FOUND"
        $s20 = "short unsigned int"
condition:
    uint16(0) == 0x5a4d and filesize < 1231KB and
    4 of them
}
    
rule eccdebeadbbefcffbcfffadfdb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "msctls_progress32"
        $s3 = "TInterfacedPersistent"
        $s4 = "EVariantBadVarTypeError"
        $s5 = "GetEnhMetaFilePaletteEntries"
        $s6 = "<I@88@8HD>PK=J@<7?8"
        $s7 = "clWebLightSteelBlue"
        $s8 = "TActionClientsClass"
        $s9 = " 2001, 2002 Mike Lischke"
        $s10 = "=*>@>V>l>P?T?X?\\?`?d?h?l?p?t?x?|?"
        $s11 = "TComboBoxStyle"
        $s12 = "SetWindowTheme"
        $s13 = "HintShortCutsT"
        $s14 = "CoInitializeEx"
        $s15 = "clWebOrangeRed"
        $s16 = "ckRunningOrNew"
        $s17 = "LinkedActionLists("
        $s18 = "TContextPopupEvent"
        $s19 = "CoCreateInstanceEx"
        $s20 = "QueryServiceStatus"
condition:
    uint16(0) == 0x5a4d and filesize < 1065KB and
    4 of them
}
    
rule affcfdababedfdbb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "TInterfacedPersistent"
        $s3 = "EVariantBadVarTypeError"
        $s4 = "clWebLightSteelBlue"
        $s5 = " 2001, 2002 Mike Lischke"
        $s6 = "SetWindowTheme"
        $s7 = "clWebOrangeRed"
        $s8 = "TWinControlActionLink"
        $s9 = "TContextPopupEvent"
        $s10 = "TPrintScale"
        $s11 = "TDragObject"
        $s12 = "TBrushStyle"
        $s13 = "DockSite,4C"
        $s14 = "Layout File"
        $s15 = "fsStayOnTop"
        $s16 = "LoadStringA"
        $s17 = "clWebIndigo"
        $s18 = "clBtnShadow"
        $s19 = "GetWindowDC"
        $s20 = "TMenuMeasureItemEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 816KB and
    4 of them
}
    
rule dcdfcfbefeffcdcecadadfdffacd_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "TComponentNametyA"
        $s3 = "TInterfacedPersistent"
        $s4 = "TCustomControlActionl"
        $s5 = " visit the website for more info "
        $s6 = "clWebLightSteelBlue"
        $s7 = " 2001, 2002 Mike Lischke"
        $s8 = "SetWindowTheme"
        $s9 = "TShortCutListd"
        $s10 = "clWebOrangeRed"
        $s11 = "OnMouseWheelUp"
        $s12 = "TWinControlActionLink"
        $s13 = "TContextPopupEvent"
        $s14 = "TCustomTabControll"
        $s15 = "TPrintScale"
        $s16 = "TDragObject"
        $s17 = "TBrushStyle"
        $s18 = "Layout File"
        $s19 = "fsStayOnTop"
        $s20 = "clWebIndigo"
condition:
    uint16(0) == 0x5a4d and filesize < 817KB and
    4 of them
}
    
rule cdeacafdaefedfeedaaeebaec_exe {
strings:
        $s1 = "$%&PUQPWQJKLJLLVTSQQU"
        $s2 = "TInterfacedPersistent"
        $s3 = "SetWindowTheme"
        $s4 = "'$'ZY^QSTSTSTUWPWPURR"
        $s5 = "TContextPopupEvent"
        $s6 = "MHJSPTQTVPRSPUQ(/("
        $s7 = "QueryServiceStatus"
        $s8 = "TPrintScale"
        $s9 = "Medium Gray"
        $s10 = "TDragObject"
        $s11 = "Read Async!"
        $s12 = "TBrushStyle"
        $s13 = "fsStayOnTop"
        $s14 = "LoadStringA"
        $s15 = "clBtnShadow"
        $s16 = "Window Text"
        $s17 = "GetWindowDC"
        $s18 = "TMenuMeasureItemEvent"
        $s19 = "GetKeyboardType"
        $s20 = "IsWindowVisible"
condition:
    uint16(0) == 0x5a4d and filesize < 837KB and
    4 of them
}
    
rule dfbdebaffbfaef_exe {
strings:
        $s1 = "EnterCriticalSection"
        $s2 = "HeapDestroy"
        $s3 = "KERNEL32.dll"
        $s4 = "ADVAPI32.dll"
        $s5 = "GetProcAddress"
        $s6 = "GetUserNameA"
        $s7 = "VirtualAlloc"
        $s8 = "VirtualFree"
        $s9 = "HeapReAlloc"
        $s10 = "CloseHandle"
        $s11 = "LoadLibraryA"
        $s12 = ".rdata$zzzdbg"
        $s13 = "CreateEventA"
        $s14 = "WS2_32.dll"
        $s15 = "CreateThread"
        $s16 = "0A_A^A\\_^]["
        $s17 = "HeapCreate"
        $s18 = "UVWATAUAVAWH"
        $s19 = "lstrcpyA"
        $s20 = "D$ Iphl#"
condition:
    uint16(0) == 0x5a4d and filesize < 17KB and
    4 of them
}
    
rule ebeaeadaaecbdebaaeeacbff_exe {
strings:
        $s1 = "Indtgtskildernes6"
        $s2 = "quicksilvering"
        $s3 = "Variantfunktioner5"
        $s4 = "DgE@MOF3/`8"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "Ortopdiske3"
        $s8 = "Salgsfremmende7"
        $s9 = "Tilforladeligt7"
        $s10 = "Klimaforandringer"
        $s11 = "PANTEBREVSHANDELS"
        $s12 = "Archoplasma8"
        $s13 = "Omvurderings"
        $s14 = "W'5lU`$lV.(y"
        $s15 = "SUBEPIDERMAL"
        $s16 = "SOCIALGRUPPES"
        $s17 = "!!xD.iL3\\KrT"
        $s18 = "Kogepunktets3"
        $s19 = "Zinkkografiet"
        $s20 = "__vbaVarTstNe"
condition:
    uint16(0) == 0x5a4d and filesize < 285KB and
    4 of them
}
    
rule bcbabcdfcbffccbfc_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "Fremskridtsbyens"
        $s4 = "Slagskibene4"
        $s5 = "__vbaStrCopy"
        $s6 = "__vbaVarTstEq"
        $s7 = "blikkenslagermesters"
        $s8 = "_adj_fdivr_m32"
        $s9 = "Retranscri.exe"
        $s10 = "LegalTrademarks"
        $s11 = "Coeldershi1"
        $s12 = "AstroPicker"
        $s13 = "EFTERFORSKNINGSCENTER"
        $s14 = "Buphthalmia8"
        $s15 = "Redningsbltes"
        $s16 = "Distraktionens"
        $s17 = "OriginalFilename"
        $s18 = "NORDAMERIKANERS"
        $s19 = "Artificious4"
        $s20 = "Decompressive"
condition:
    uint16(0) == 0x5a4d and filesize < 77KB and
    4 of them
}
    
rule debfdbabcceacddac_exe {
strings:
        $s1 = "Flertalsbeslutningernes4"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "Aftgtsydelserne8"
        $s5 = "__vbaStrCopy"
        $s6 = "counterblows"
        $s7 = "__vbaLenBstr"
        $s8 = "__vbaFileOpen"
        $s9 = "__vbaLateIdCallLd"
        $s10 = "Steroidprparats7"
        $s11 = "_adj_fdivr_m32"
        $s12 = "Mesopotamia5"
        $s13 = "Scoptically8"
        $s14 = "phlebotomise"
        $s15 = "__vbaVarTstLt"
        $s16 = "__vbaLateIdSt"
        $s17 = "Anticipatable"
        $s18 = "Sydvestenvind1"
        $s19 = "OriginalFilename"
        $s20 = "SUPERSESQUITERTIAL"
condition:
    uint16(0) == 0x5a4d and filesize < 97KB and
    4 of them
}
    
rule dbcddfbbcbbcbeccebaaa_exe {
strings:
        $s1 = "Forhandlingsforsg"
        $s2 = "VarFileInfo"
        $s3 = ",.igj|-Vvaf"
        $s4 = "ProductName"
        $s5 = "F=Rja<C8~,J"
        $s6 = "__vbaStrCopy"
        $s7 = "PRAKTIKPLADSERNES"
        $s8 = "axisymmetrically"
        $s9 = "Glauconitization2"
        $s10 = "missyllabication"
        $s11 = "_adj_fdivr_m32"
        $s12 = "Sygehusvsenet2"
        $s13 = "Noncontinuably"
        $s14 = "LegalTrademarks"
        $s15 = "Francoise9"
        $s16 = "Ringmaker8"
        $s17 = "VsoHg&Tjt$"
        $s18 = "PSEUDOVELAR"
        $s19 = "__vbaUI1Str"
        $s20 = "nonsimulate"
condition:
    uint16(0) == 0x5a4d and filesize < 93KB and
    4 of them
}
    
rule eaafacecbbdbfcdddedaffccde_exe {
strings:
        $s1 = "Calc Theory"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "PN.eZKB:i#~"
        $s5 = "FileDescription"
        $s6 = "__vbaStrCopy"
        $s7 = "__vbaLenBstr"
        $s8 = "arbejdsvgring"
        $s9 = "__vbaLateIdCallLd"
        $s10 = "HYPOKEIMENOMETRY"
        $s11 = "_adj_fdivr_m32"
        $s12 = "OUTWHIRLED"
        $s13 = "ABJOINT.exe"
        $s14 = "infructuose"
        $s15 = "Functionated"
        $s16 = "__vbaVarTstLt"
        $s17 = "OriginalFilename"
        $s18 = "Nonterritorial5"
        $s19 = "kloakarbejderes"
        $s20 = "Laurbrkranses7"
condition:
    uint16(0) == 0x5a4d and filesize < 73KB and
    4 of them
}
    
rule adcaaaebdbbfafbcfdbc_exe {
strings:
        $s1 = "WmfPlaceableFileHeader"
        $s2 = "GdipCreateMatrix3"
        $s3 = "BufferedPaintInit"
        $s4 = "Operation aborted"
        $s5 = "FCreatingMainForm"
        $s6 = "clInactiveCaption"
        $s7 = "FRightClickSelect"
        $s8 = "FCaptionEmulation"
        $s9 = "StaticSynchronize"
        $s10 = "TRttiClassRefType"
        $s11 = "TRttiManagedField"
        $s12 = "GdipGraphicsClear"
        $s13 = "Change group name"
        $s14 = "TMouseLeaveEventh"
        $s15 = "claMediumseagreen"
        $s16 = "ToShortUTF8String"
        $s17 = "ImageTypeMetafile"
        $s18 = "TMeasureItemEvent"
        $s19 = "Possible deadlock"
        $s20 = "twMDISysButtonHot"
condition:
    uint16(0) == 0x5a4d and filesize < 4725KB and
    4 of them
}
    
rule caacdeccbcdadfcfaabecdd_exe {
strings:
        $s1 = "FlagsAttribute"
        $s2 = "RuntimeHelpers"
        $s3 = "GetProcessesByName"
        $s4 = "RuntimeFieldHandle"
        $s5 = "STAThreadAttribute"
        $s6 = "System.Data.SQLite"
        $s7 = "MB:n/-,#854"
        $s8 = "ComputeHash"
        $s9 = "op_Equality"
        $s10 = " AY08v6j&-!"
        $s11 = "VarFileInfo"
        $s12 = "w2\"WrbQ'&~"
        $s13 = "ProductName"
        $s14 = "_CorExeMain"
        $s15 = "FileDescription"
        $s16 = "FlushFinalBlock"
        $s17 = "a__5kklQqmjkui`"
        $s18 = "ResolveEventArgs"
        $s19 = "AEaewfqBB5dfk0fqqEd"
        $s20 = "dfY6Y6ao6nsMosvUoy"
condition:
    uint16(0) == 0x5a4d and filesize < 1244KB and
    4 of them
}
    
rule eabdcebadfeecfdff_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "msctls_trackbar32"
        $s3 = "TMeasureItemEvent"
        $s4 = "Possible deadlock"
        $s5 = "TPacketAttribute "
        $s6 = "msctls_progress32"
        $s7 = "TCustomStaticText"
        $s8 = "GetEnvironmentStrings"
        $s9 = "TSeriesMarksPositions"
        $s10 = "TInterfacedPersistent"
        $s11 = "EUnsupportedTypeError"
        $s12 = "8 8$8(8,8084888<8@8D8H8L8P8T8 4$4(4,4044484<4@4D4H4L4P4T4X4\\4`4d4h4l4p4t4x4|4"
        $s13 = "Unable to insert an item"
        $s14 = "\\DATABASES\\%s\\DB INFO"
        $s15 = "'%s' is not a valid date"
        $s16 = "< <,<@<H<L<P<T<X<\\<`<d<h<X8\\8`8d8h8l8p8t8x8|8"
        $s17 = "= =$;(;,;0;4;8;<;@;D;H;L;P;T;X;\\;`;d;h;l;p;t;x;|;"
        $s18 = "5\"5(5.545:5@5D2J2P2V2\\2b2h2n2t2z2"
        $s19 = "\\DRIVERS\\%s\\DB OPEN"
        $s20 = "GetEnhMetaFilePaletteEntries"
condition:
    uint16(0) == 0x5a4d and filesize < 1488KB and
    4 of them
}
    
rule bdcecfecfeecabbabfddefbcdcecf_exe {
strings:
        $s1 = "numberNegativePattern"
        $s2 = "FlagsAttribute"
        $s3 = "RuntimeHelpers"
        $s4 = "$this.GridSize"
        $s5 = "RuntimeFieldHandle"
        $s6 = "STAThreadAttribute"
        $s7 = "4_6>Y; 7N,W"
        $s8 = "ComputeHash"
        $s9 = "e3{>qMJ(U#:"
        $s10 = "VarFileInfo"
        $s11 = "ProductName"
        $s12 = "']LE^Ck@1\""
        $s13 = "_CorExeMain"
        $s14 = "Z&~*Vwr)jU8"
        $s15 = "FileDescription"
        $s16 = "FlushFinalBlock"
        $s17 = "Acer Incorporated"
        $s18 = "customCultureName"
        $s19 = "ResolveEventArgs"
        $s20 = "S3Vqd3d5eGV3cWo="
condition:
    uint16(0) == 0x5a4d and filesize < 1649KB and
    4 of them
}
    
rule afcbefeeeafbecddfeedac_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "     name=\"wextract\""
        $s3 = "RegSetValueExA"
        $s4 = "Dm?FVL9]&KN"
        $s5 = "LVS86.{+ Og"
        $s6 = "{d,zOnTm&UI"
        $s7 = "VarFileInfo"
        $s8 = "a0U6# 4pl$2"
        $s9 = "ProductName"
        $s10 = "j(GEv9gHF$<"
        $s11 = "#+|X)./iyAR"
        $s12 = "LoadStringA"
        $s13 = "FileDescription"
        $s14 = "Command.com /c %s"
        $s15 = "GetShortPathNameA"
        $s16 = "GetModuleHandleA"
        $s17 = "RemoveDirectoryA"
        $s18 = "DispatchMessageA"
        $s19 = "TerminateProcess"
        $s20 = "Temporary folder"
condition:
    uint16(0) == 0x5a4d and filesize < 1360KB and
    4 of them
}
    
rule cfdeceafebabbbeebedeab_exe {
strings:
        $s1 = "&9C:\\Users\\Hidd\"ask\\"
        $s2 = "t3_51<Et:<et6<;tFD"
        $s3 = "KZ6B4$\"lok"
        $s4 = "AsDoubleT\""
        $s5 = "CustomizerU"
        $s6 = "o!<^%~m6Wbg"
        $s7 = "wCheckbox&R"
        $s8 = "TClipboardg"
        $s9 = "Am#lf\">,7D"
        $s10 = "SystemInfo>"
        $s11 = "4!YM.1wUx*X"
        $s12 = "7<CIPenDash"
        $s13 = "VarFileInfo"
        $s14 = "\"Q[NdR^JL5"
        $s15 = "7hlU+Rux3=;"
        $s16 = "ProductName"
        $s17 = "iUd 8M{;RDg"
        $s18 = "AutoSize\"y"
        $s19 = "<IMG src=\""
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 1226KB and
    4 of them
}
    
rule aeebfeadaccdeaacdfcebddaeab_exe {
strings:
        $s1 = ".==CINSYgffffmmm\\0i"
        $s2 = "999'OOOTUTO'V%J$*WQX"
        $s3 = "GetEnhMetaFilePaletteEntries"
        $s4 = "SetWindowTheme"
        $s5 = "CoInitializeEx"
        $s6 = "TContextPopupEvent"
        $s7 = "CoCreateInstanceEx"
        $s8 = "AutoSizepHC"
        $s9 = "DockSite89C"
        $s10 = "TPrintScale"
        $s11 = "Medium Gray"
        $s12 = "TDragObject"
        $s13 = "TBrushStyle"
        $s14 = "TOFNotifyEx"
        $s15 = "fsStayOnTop"
        $s16 = "LoadStringA"
        $s17 = "clBtnShadow"
        $s18 = "Window Text"
        $s19 = "GetWindowDC"
        $s20 = "TMenuMeasureItemEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 888KB and
    4 of them
}
    
rule accfcbfceeeaefcdfcdfdcde_exe {
strings:
        $s1 = "{|raaKDD/11-./zrg"
        $s2 = "}}}{{{{{{xxxxxxtttrrrpppmmmkkkjjjffffffiiiiiimmmyyy"
        $s3 = "EVariantBadVarTypeError"
        $s4 = "30314743774a5c2b2041456303013126475c240b4276265c5e62221a33295c58200b1b0101525920030a302251572e330722161c76270b1922"
        $s5 = "GetEnhMetaFilePaletteEntries"
        $s6 = "TActionClientsClass"
        $s7 = "SetWindowTheme"
        $s8 = "HintShortCuts<"
        $s9 = "CoInitializeEx"
        $s10 = "TContextPopupEvent"
        $s11 = "CoCreateInstanceEx"
        $s12 = "TPrintScale"
        $s13 = "Medium Gray"
        $s14 = "TDragObject"
        $s15 = "OnUpdate|hA"
        $s16 = "TPicture ?B"
        $s17 = "Interval|hA"
        $s18 = "TBrushStyle"
        $s19 = "MaxWidthH{C"
        $s20 = "fsStayOnTop"
condition:
    uint16(0) == 0x5a4d and filesize < 713KB and
    4 of them
}
    
rule addcdcdfcadeebcaedfdb_exe {
strings:
        $s1 = "q2ox3BQnB3YqLB1D3C3"
        $s2 = "i9yBT1JJKTgiwmlg9li"
        $s3 = "RuntimeHelpers"
        $s4 = "STAThreadAttribute"
        $s5 = "OWuRXxTmQhrTRumQKR"
        $s6 = "DesignerGeneratedAttribute"
        $s7 = "ProductName"
        $s8 = "_CorExeMain"
        $s9 = "VarFileInfo"
        $s10 = "ThreadStaticAttribute"
        $s11 = "FileDescription"
        $s12 = "XaaakonmnoiUVOvZ"
        $s13 = "hxUMWXUTUcVXdyMo"
        $s14 = "gHhUFnFNoFUcyHLJ"
        $s15 = "DebuggerHiddenAttribute"
        $s16 = "GPHVmZIWmbGKgZbWXZPP"
        $s17 = "InitializeComponent"
        $s18 = "set_TabIndex"
        $s19 = "Synchronized"
        $s20 = "get_Commands"
condition:
    uint16(0) == 0x5a4d and filesize < 366KB and
    4 of them
}
    
rule ceaeeebadedccaddafeebdbabd_exe {
strings:
        $s1 = "invalid string position"
        $s2 = "GetConsoleOutputCP"
        $s3 = "YRsU[u;L6wr"
        $s4 = "`local vftable'"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleW"
        $s7 = "GetCurrentDirectoryA"
        $s8 = "InitializeCriticalSection"
        $s9 = "GetCurrentThreadId"
        $s10 = "GetLocalTime"
        $s11 = "GetTickCount"
        $s12 = "SetEndOfFile"
        $s13 = "WriteConsoleA"
        $s14 = "Unknown exception"
        $s15 = "SetHandleCount"
        $s16 = "CorExitProcess"
        $s17 = "`udt returning'"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "TransmitCommChar"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 164KB and
    4 of them
}
    
rule cabadefdadccbfcacfcdfa_exe {
strings:
        $s1 = "obagoFsouth-korea"
        $s2 = "t,4h#8ldT/_"
        $s3 = "Y`jt7@3V0;k"
        $s4 = "^_aCTi\"wH*"
        $s5 = " !\"#$%&'()"
        $s6 = "qx*piZ %`J,"
        $s7 = "VarFileInfo"
        $s8 = "AFX_DIALOG_LAYOUT"
        $s9 = "pq=MqeSuAYT&"
        $s10 = "s Hierarchyn"
        $s11 = "JkgV`\">a\"rb"
        $s12 = "public:Opro[l"
        $s13 = "#S_mf+X-_}n_."
        $s14 = "VirtualProtect"
        $s15 = "Unknown excep5"
        $s16 = "0j@(8%ob$;"
        $s17 = " Descrilo="
        $s18 = "tM<it-<ot)<ut%<x5k"
        $s19 = "Vo \"se yup"
        $s20 = ":>\"4D4~Zl,"
condition:
    uint16(0) == 0x5a4d and filesize < 507KB and
    4 of them
}
    
rule aedfeecebaedecedbcccaabef_ps {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    all of them
}
    
rule beaaadcebfbcfcdabedc_exe {
strings:
        $s1 = "ImmSetCompositionFontW"
        $s2 = "RegSetValueExW"
        $s3 = "GetModuleHandleA"
        $s4 = "acmFormatChooseW"
        $s5 = "midiOutClose"
        $s6 = "WINSPOOL.DRV"
        $s7 = "IsCharLowerA"
        $s8 = "InternetGetConnectedStateExW"
        $s9 = "SetActivePwrScheme"
        $s10 = "AssocQueryKeyW"
        $s11 = "GetTapePosition"
        $s12 = "B9EO~U{rVM"
        $s13 = "UrlCompareW"
        $s14 = "wvnsprintfA"
        $s15 = "PathAppendW"
        $s16 = "DrawTextExW"
        $s17 = "SetDlgItemTextW"
        $s18 = "JetSetColumn"
        $s19 = "KERNEL32.dll"
        $s20 = "DsGetDcNameW"
condition:
    uint16(0) == 0x5a4d and filesize < 221KB and
    4 of them
}
    
rule eaccfdeeffdaedfdbefabfbafafedd_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "VirtualAllocEx"
        $s3 = "Y1t_>0|el\""
        $s4 = "o^.Z6`\"Y<B"
        $s5 = "`pv*]JLTa(>"
        $s6 = "\"La^zd)wAo"
        $s7 = "!aIKvL@Hz:;"
        $s8 = "UJ`e~EhlY\""
        $s9 = "89i*=6Z(.cY"
        $s10 = "VarFileInfo"
        $s11 = "([t8+*:a#HL"
        $s12 = "JbYZjaUT<D+"
        $s13 = "ProductName"
        $s14 = "y[@Elu\"5Sx"
        $s15 = "'R!ybj`hD>_"
        $s16 = "FileDescription"
        $s17 = "GetModuleHandleA"
        $s18 = "ILeu~Dewy<e1K4eIy,e"
        $s19 = "(1|auK_(&Tti"
        $s20 = "aYq(e\"Q-edo"
condition:
    uint16(0) == 0x5a4d and filesize < 1876KB and
    4 of them
}
    
rule bbebcfcddfecbefdecdeccaadfabfa_exe {
strings:
        $s1 = "ToBase64Transform"
        $s2 = "REMISIONES - FILTRO"
        $s3 = "Clientes x Contrato"
        $s4 = "RuntimeHelpers"
        $s5 = "FrmAbonos_Load"
        $s6 = "get_txtUsuario"
        $s7 = "get_txtHoraIni"
        $s8 = "ControlBindingsCollection"
        $s9 = "AuthenticationMode"
        $s10 = "SerializationEntry"
        $s11 = "STAThreadAttribute"
        $s12 = "System.Data.Common"
        $s13 = "DesignerGeneratedAttribute"
        $s14 = "ProductName"
        $s15 = "eGT>pVU[\"$"
        $s16 = "dgvVehiculo"
        $s17 = "My.Computer"
        $s18 = "_CorExeMain"
        $s19 = "ComputeHash"
        $s20 = "F}dL|tq0U8s"
condition:
    uint16(0) == 0x5a4d and filesize < 1314KB and
    4 of them
}
    
rule adedaaecbefafdbcebdfbbaafae_dll {
strings:
        $s1 = "DefMenuItemHeight"
        $s2 = "EnableImageDevice"
        $s3 = "GetEnvironmentStrings"
        $s4 = "Unable to insert an item"
        $s5 = "\\'\\'%s\\'\\' is not a valid time"
        $s6 = "Generics.Collections"
        $s7 = "bsieSemiTransparent"
        $s8 = "GeTBod]aeFaaeN)beA"
        $s9 = "GetConsoleOutputCP"
        $s10 = "ProductName"
        $s11 = "bsipDefault"
        $s12 = "LoadStringW"
        $s13 = "VarFileInfo"
        $s14 = ".bsTrayIcon"
        $s15 = "clBtnShadow"
        $s16 = "dbszlibcompress"
        $s17 = "DeviceIoControl"
        $s18 = "TbsSkinComboBox"
        $s19 = "QueryDosDeviceW"
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 588KB and
    4 of them
}
    
rule dacbaeacaecbeeddcfcedaca_dll {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "cross device link"
        $s3 = "SetDefaultDllDirectories"
        $s4 = "executable format error"
        $s5 = "result out of range"
        $s6 = "directory not empty"
        $s7 = "<file unknown>"
        $s8 = "invalid string position"
        $s9 = "ninvalid null pointer"
        $s10 = "operation canceled"
        $s11 = "ProductName"
        $s12 = "VarFileInfo"
        $s13 = "`local vftable'"
        $s14 = "FileDescription"
        $s15 = "RemoveDirectoryA"
        $s16 = "TerminateProcess"
        $s17 = "SetFilePointerEx"
        $s18 = "SetThreadStackGuarantee"
        $s19 = "destination address required"
        $s20 = "ClusterGetEnumCount"
condition:
    uint16(0) == 0x5a4d and filesize < 639KB and
    4 of them
}
    