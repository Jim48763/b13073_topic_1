import pe
rule ceeedbeafffdfaddbdbebfcbaf_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "_CorExeMain"
        $s3 = "FileDescription"
        $s4 = "    </security>"
        $s5 = "set_UseShellExecute"
        $s6 = "IDisposable"
        $s7 = "</assembly>"
        $s8 = "DownloadFile"
        $s9 = "get_Location"
        $s10 = "set_Arguments"
        $s11 = "OriginalFilename"
        $s12 = "set_FileName"
        $s13 = "VS_VERSION_INFO"
        $s14 = "GetTempPath"
        $s15 = "mscoree.dll"
        $s16 = "Translation"
        $s17 = "FileVersion"
        $s18 = "InternalName"
        $s19 = "Environment"
        $s20 = "System.IO"
condition:
    uint16(0) == 0x5a4d and filesize < 9KB and
    4 of them
}
    
rule efaebddbefaebddacb_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "_CorExeMain"
        $s5 = "IXmlStorage"
        $s6 = "FileDescription"
        $s7 = "AddMessageFilter"
        $s8 = "Microsoft Corporation"
        $s9 = "GetResponseStream"
        $s10 = " Visual Studio"
        $s11 = "    </security>"
        $s12 = "get_StartInfo"
        $s13 = "GetObjectValue"
        $s14 = "set_UseShellExecute"
        $s15 = "StringSplitOptions"
        $s16 = "XmlNodeType"
        $s17 = "IDisposable"
        $s18 = "</assembly>"
        $s19 = "StringReader"
        $s20 = "set_Arguments"
condition:
    uint16(0) == 0x5a4d and filesize < 183KB and
    4 of them
}
    
rule fddeefdcaecaabeabd_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "All Goods are at Net Cost"
        $s3 = "SetInvoiceHead"
        $s4 = "System.Data.Common"
        $s5 = "STAThreadAttribute"
        $s6 = "op_Equality"
        $s7 = "_CorExeMain"
        $s8 = "pictureBox1"
        $s9 = "VarFileInfo"
        $s10 = "pz>#BMH|,xO"
        $s11 = "ReadInvoiceData"
        $s12 = "ExecuteNonQuery"
        $s13 = "get_DefaultView"
        $s14 = "dateTimePicker2"
        $s15 = "FileDescription"
        $s16 = "Contact Details"
        $s17 = "Please Select Party Name"
        $s18 = "Edit Item Details"
        $s19 = "Select Challan No"
        $s20 = "ToShortDateString"
condition:
    uint16(0) == 0x5a4d and filesize < 555KB and
    4 of them
}
    
rule ddcadfcdfcebcdecdcfcbdc_exe {
strings:
        $s1 = "add_MdiChildActivate"
        $s2 = "DescriptionAttribute"
        $s3 = "ResetMouseEventArgs"
        $s4 = "FlagsAttribute"
        $s5 = "STAThreadAttribute"
        $s6 = "op_Equality"
        $s7 = "_CorExeMain"
        $s8 = "ComputeHash"
        $s9 = "ProductName"
        $s10 = "VarFileInfo"
        $s11 = "y%#bo<8kR i"
        $s12 = "FileDescription"
        $s13 = "set_RightToLeft"
        $s14 = "IFormatProvider"
        $s15 = "get_ColorScheme"
        $s16 = "AddMessageFilter"
        $s17 = "ContextMenuStrip"
        $s18 = " Weifen Luo 2007"
        $s19 = "DebuggerHiddenAttribute"
        $s20 = "UnhookWindowsHookEx"
condition:
    uint16(0) == 0x5a4d and filesize < 289KB and
    4 of them
}
    
rule faeebbbfbdaebfacea_exe {
strings:
        $s1 = "<==>;<<A;<<A677B-..j)**"
        $s2 = "Type not supported"
        $s3 = "LastIndexOf"
        $s4 = "System.Linq"
        $s5 = "op_Equality"
        $s6 = "_CorExeMain"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "expressionCache"
        $s10 = "IFormatProvider"
        $s11 = "ResetableLazy`1"
        $s12 = "IterationResult"
        $s13 = "OrderByDescending"
        $s14 = "DebuggerHiddenAttribute"
        $s15 = "ConstantExpression"
        $s16 = "nXf@[{hzHn`v"
        $s17 = "IfHasElement"
        $s18 = "NumberStyles"
        $s19 = "valueFactory"
        $s20 = "GetRuntimeMethod"
condition:
    uint16(0) == 0x5a4d and filesize < 671KB and
    4 of them
}
    
rule dcadbfcadcbcaadfaebeadcbafb_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "You ran out of time!"
        $s3 = "set_TransparentColor"
        $s4 = "Please enter only one character"
        $s5 = "ii4lTCMJgQpJp99o4CC"
        $s6 = "hGBK0mYJZKwGIJwYZwv"
        $s7 = "RuntimeHelpers"
        $s8 = "My.WebServices"
        $s9 = "Challenge Selector"
        $s10 = "STAThreadAttribute"
        $s11 = "AuthenticationMode"
        $s12 = "DesignerGeneratedAttribute"
        $s13 = "My.Computer"
        $s14 = "PictureBox1"
        $s15 = "MsgBoxStyle"
        $s16 = "_CorExeMain"
        $s17 = "lstWordBank"
        $s18 = "c?3^a7u@O$>"
        $s19 = "ProductName"
        $s20 = "VarFileInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 624KB and
    4 of them
}
    
rule efbbadbcdeecaeffcbebccfbdcca_exe {
strings:
        $s1 = "System.Data.OleDb"
        $s2 = "Network_Printer.txt"
        $s3 = "RuntimeHelpers"
        $s4 = "STAThreadAttribute"
        $s5 = "DesignerGeneratedAttribute"
        $s6 = "mflgIsDirty"
        $s7 = "My.Computer"
        $s8 = "IOException"
        $s9 = "MsgBoxStyle"
        $s10 = "_CorExeMain"
        $s11 = "get_Columns"
        $s12 = "#(`*iv/Y9jz"
        $s13 = "ProductName"
        $s14 = "First Name:"
        $s15 = "VarFileInfo"
        $s16 = "ThreadStaticAttribute"
        $s17 = "ExecuteNonQuery"
        $s18 = "FileDescription"
        $s19 = "m_enumDVDFormat"
        $s20 = "FirstWeekOfYear"
condition:
    uint16(0) == 0x5a4d and filesize < 459KB and
    4 of them
}
    
rule fceacbdfcbcdefaeafcfd_exe {
strings:
        $s1 = "AutoPropertyValue"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "ProductName"
        $s5 = "My.Computer"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "ThreadStaticAttribute"
        $s9 = "FlushFinalBlock"
        $s10 = "FileDescription"
        $s11 = "GetConsoleWindow"
        $s12 = "\\MyTemp\\Torrent.exe"
        $s13 = "Synchronized"
        $s14 = "System.Resources"
        $s15 = "GeneratedCodeAttribute"
        $s16 = "NewLateBinding"
        $s17 = "ReferenceEquals"
        $s18 = "Dispose__Instance__"
        $s19 = "MyWebServices"
        $s20 = "get_FileSystem"
condition:
    uint16(0) == 0x5a4d and filesize < 20KB and
    4 of them
}
    
rule fbdfbeeaeccbebaeebdee_exe {
strings:
        $s1 = "ProductName"
        $s2 = "op_Equality"
        $s3 = "VarFileInfo"
        $s4 = "_CorExeMain"
        $s5 = "FileDescription"
        $s6 = "http://google.com"
        $s7 = "GetExportedTypes"
        $s8 = "Synchronized"
        $s9 = "IncludeDefinition"
        $s10 = "CustomizeDefinition"
        $s11 = "System.Resources"
        $s12 = "/C timeout 20"
        $s13 = "GeneratedCodeAttribute"
        $s14 = "defaultInstance"
        $s15 = "DebuggingModes"
        $s16 = "LegalTrademarks"
        $s17 = "IDisposable"
        $s18 = "*kqplk2\"Z9"
        $s19 = "CultureInfo"
        $s20 = "</assembly>"
condition:
    uint16(0) == 0x5a4d and filesize < 33KB and
    4 of them
}
    
rule dbdcbebcadbadbbeebcaaaaeaccfb_exe {
strings:
        $s1 = "DESKTOP_ENUMERATE"
        $s2 = "STARTUP_INFORMATION"
        $s3 = "VirtualAllocEx"
        $s4 = "DESKTOP_SWITCHDESKTOP"
        $s5 = "GetProcessesByName"
        $s6 = "ProductName"
        $s7 = "ComputeHash"
        $s8 = "op_Equality"
        $s9 = "ExclusionWD"
        $s10 = "_CorExeMain"
        $s11 = "FileDescription"
        $s12 = "ReadProcessMemory"
        $s13 = "GetConsoleWindow"
        $s14 = "DelegateResumeThread"
        $s15 = "DESKTOP_HOOKCONTROL"
        $s16 = "IAsyncResult"
        $s17 = "UTF8Encoding"
        $s18 = "DialogResult"
        $s19 = "Pandora hVNC"
        $s20 = "GetThreadContext"
condition:
    uint16(0) == 0x5a4d and filesize < 143KB and
    4 of them
}
    
rule cdacebfcabdfabfdbafbefea_exe {
strings:
        $s1 = "SchemaDecoratorComp"
        $s2 = "STAThreadAttribute"
        $s3 = "ProductName"
        $s4 = "System.Linq"
        $s5 = "op_Equality"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "FileDescription"
        $s9 = "Synchronized"
        $s10 = "DialogResult"
        $s11 = "System.Resources"
        $s12 = "ExtensionAttribute"
        $s13 = "GeneratedCodeAttribute"
        $s14 = "_Configuration"
        $s15 = "defaultInstance"
        $s16 = "set_StartInfo"
        $s17 = "DebuggingModes"
        $s18 = "LegalTrademarks"
        $s19 = "PostBridge"
        $s20 = "FromSeconds"
condition:
    uint16(0) == 0x5a4d and filesize < 22KB and
    4 of them
}
    
rule adcdbdaeeadfdbfdbeebcdbc_exe {
strings:
        $s1 = "DESKTOP_ENUMERATE"
        $s2 = "STARTUP_INFORMATION"
        $s3 = "VirtualAllocEx"
        $s4 = "DESKTOP_SWITCHDESKTOP"
        $s5 = "GetProcessesByName"
        $s6 = "ProductName"
        $s7 = "ComputeHash"
        $s8 = "op_Equality"
        $s9 = "ExclusionWD"
        $s10 = "_CorExeMain"
        $s11 = "FileDescription"
        $s12 = "ReadProcessMemory"
        $s13 = "GetConsoleWindow"
        $s14 = "DelegateResumeThread"
        $s15 = "DESKTOP_HOOKCONTROL"
        $s16 = "IAsyncResult"
        $s17 = "UTF8Encoding"
        $s18 = "DialogResult"
        $s19 = "Pandora hVNC"
        $s20 = "GetThreadContext"
condition:
    uint16(0) == 0x5a4d and filesize < 143KB and
    4 of them
}
    
rule fdbedaeaabbbcadbaafcee_exe {
strings:
        $s1 = "^(https?|ftp):\\/\\/"
        $s2 = "        name=\"SMSvcHost\" "
        $s3 = "RuntimeHelpers"
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "_CorExeMain"
        $s7 = "FileDescription"
        $s8 = "NullabilityInfo"
        $s9 = "      <assemblyIdentity "
        $s10 = "Microsoft Corporation"
        $s11 = "PrivateBuild"
        $s12 = "System.Resources"
        $s13 = "SMSvcHost.exe"
        $s14 = "Flavor=Retail"
        $s15 = "            <requestedExecutionLevel "
        $s16 = "GetResponseStream"
        $s17 = "      </compatibility> "
        $s18 = "UnexpectedValue"
        $s19 = "ExceptionUtilities"
        $s20 = "get_StartInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 44KB and
    4 of them
}
    
rule affbeefdebbefbcffdcaab_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "jooifwnpixcefxjfbl"
        $s3 = "ghmbtuvczexbcxzefe"
        $s4 = "rfmurtvjtxrkljnnuq"
        $s5 = "nuvqlniwkkbaloxilv"
        $s6 = "a\":z`K{F/*"
        $s7 = "_CorExeMain"
        $s8 = "ProductName"
        $s9 = "VarFileInfo"
        $s10 = "ThreadStaticAttribute"
        $s11 = "FileDescription"
        $s12 = "InitializeComponent"
        $s13 = "awhwvockljissdwkaa"
        $s14 = "fxqaeqiuacgzqndeec"
        $s15 = "klzcgebzmutbcbmzwa"
        $s16 = "zswossgxoqoymzilyu"
        $s17 = "ieczpclmvvuppucgyh"
        $s18 = "Synchronized"
        $s19 = "IAsyncResult"
        $s20 = "vk4?<xx)B=do"
condition:
    uint16(0) == 0x5a4d and filesize < 277KB and
    4 of them
}
    
rule faaefdefafbfdbccfabeebfccc_exe {
strings:
        $s1 = "TerminateProcess"
        $s2 = "waveOutSetVolume"
        $s3 = "GetModuleHandleW"
        $s4 = "EnterCriticalSection"
        $s5 = "ScriptLayout"
        $s6 = "NETAPI32.dll"
        $s7 = "GetTickCount"
        $s8 = "57*\"\"B0+pCg"
        $s9 = "SelectClipRgn"
        $s10 = "SetHandleCount"
        $s11 = "GetSystemTimeAsFileTime"
        $s12 = "InterlockedDecrement"
        $s13 = "VirtualProtect"
        $s14 = "@zO>.v!' 9"
        $s15 = "}TBa[5k&'m"
        $s16 = "`+K).P2v{Y"
        $s17 = "GetNearestPaletteIndex"
        $s18 = "IsProcessorFeaturePresent"
        $s19 = "9 9$9(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9x9|9"
        $s20 = "WUSER32.DLL"
condition:
    uint16(0) == 0x5a4d and filesize < 204KB and
    4 of them
}
    
rule bcaebcdcfcffaebcbcc_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "__vbaStrCopy"
        $s4 = "__vbaVarSetObj"
        $s5 = "__vbaStrVarMove"
        $s6 = "_adj_fdivr_m16i"
        $s7 = "Justiciary4"
        $s8 = "Udgiftsfrtes6"
        $s9 = "Afbestillings"
        $s10 = "OriginalFilename"
        $s11 = "Svumninge1"
        $s12 = "Ameninjur1"
        $s13 = "VS_VERSION_INFO"
        $s14 = "CompanyName"
        $s15 = "__vbaObjSet"
        $s16 = "landjordens"
        $s17 = "FileVersion"
        $s18 = "__vbaChkstk"
        $s19 = "Translation"
        $s20 = "tSn56iNbS\\"
condition:
    uint16(0) == 0x5a4d and filesize < 65KB and
    4 of them
}
    
rule cefeedddacefdebbddaa_exe {
strings:
        $s1 = "get_Enumerable"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "ProductName"
        $s5 = "My.Computer"
        $s6 = "System.Linq"
        $s7 = "MsgBoxStyle"
        $s8 = "VarFileInfo"
        $s9 = "_CorExeMain"
        $s10 = "ThreadStaticAttribute"
        $s11 = "get_IsCompleted"
        $s12 = "FileDescription"
        $s13 = "IFormatProvider"
        $s14 = "GetResponseToSign"
        $s15 = "GetChildPosition"
        $s16 = "AddMessageFilter"
        $s17 = "DebuggerHiddenAttribute"
        $s18 = "CryptographyHelper"
        $s19 = "Synchronized"
        $s20 = "CngAlgorithm"
condition:
    uint16(0) == 0x5a4d and filesize < 100KB and
    4 of them
}
    
rule cdebecbaedafcafcdeafedddaa_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "CoAddRefServerProcess"
        $s4 = "TInterfacedPersistent"
        $s5 = "EVariantBadVarTypeError"
        $s6 = "If-Unmodified-Since"
        $s7 = "Database Login"
        $s8 = "TShortCutEvent"
        $s9 = "CoCreateInstanceEx"
        $s10 = "TContextPopupEvent"
        $s11 = "GetWindowDC"
        $s12 = "Medium Gray"
        $s13 = "TGraphic,+B"
        $s14 = "Print Flags"
        $s15 = "LoadStringA"
        $s16 = "TXPManifest"
        $s17 = "Window Text"
        $s18 = "DragKindhqC"
        $s19 = "OnDrawIteml"
        $s20 = "TBrushStyle"
condition:
    uint16(0) == 0x5a4d and filesize < 1285KB and
    4 of them
}
    
rule fbadcffbafcacdcaeaebeda_exe {
strings:
        $s1 = "<-mil1_eofq"
        $s2 = "Gns*fMm`bkw"
        $s3 = "\\App 0chRme.exe"
        $s4 = "SOFTWARE\\Mp"
        $s5 = "w H\\:CZju@J"
        $s6 = "OLEAUT32.dll"
        $s7 = "Z/x\"qW#e/0."
        $s8 = "CryptUnprotectData"
        $s9 = "InitCommonControlsEx"
        $s10 = "VirtualProtect"
        $s11 = "@&H'P)X*#G"
        $s12 = "6LH3IvFhxA"
        $s13 = "a\"N{t=PC2"
        $s14 = "xTbAjh=#/<"
        $s15 = "fPWoQkxbun"
        $s16 = "0p%x:<CLB/"
        $s17 = "Ht?3a/P+`f"
        $s18 = "@%HB$~IJue"
        $s19 = "+\"GuatFeW"
        $s20 = "[NDzS5_=cf"
condition:
    uint16(0) == 0x5a4d and filesize < 360KB and
    4 of them
}
    
rule feceabaddcfbaccdaacbcabdafde_exe {
strings:
        $s1 = "CreateThreadpoolTimer"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "RtlNtStatusToDosError"
        $s4 = "Handle %x created"
        $s5 = "TerminateProcess"
        $s6 = "SetFilePointerEx"
        $s7 = "SetThreadStackGuarantee"
        $s8 = "EnterCriticalSection"
        $s9 = "Out of Memory"
        $s10 = "Status: State Change"
        $s11 = "RtlCaptureContext"
        $s12 = "CorExitProcess"
        $s13 = "FormatMessageW"
        $s14 = "LoadLibraryExW"
        $s15 = "GetTempFileNameW"
        $s16 = "Request_Complete"
        $s17 = "InternetCloseHandle"
        $s18 = "GetSystemTimeAsFileTime"
        $s19 = "SizeofResource"
        $s20 = "GetProcessHeap"
condition:
    uint16(0) == 0x5a4d and filesize < 256KB and
    4 of them
}
    
rule fcccdeaeaaabbcefebbbf_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "InitializeCriticalSection"
        $s3 = "GetProcessHeap"
        $s4 = "AsyncCreate"
        $s5 = "KERNEL32.dll"
        $s6 = "GetProcAddress"
        $s7 = "DllRegisterServer"
        $s8 = "VirtualAlloc"
        $s9 = "VirtualFree"
        $s10 = "TlsGetValue"
        $s11 = "LoadLibraryA"
        $s12 = "GetSystemTime"
        $s13 = "GetLastError"
        $s14 = "D$$;D$0s*H"
        $s15 = "HeapAlloc"
        $s16 = "HeapFree"
        $s17 = "`.rdata"
        $s18 = "D$Hk@P"
        $s19 = "9D$pr"
        $s20 = "L$(H+"
condition:
    uint16(0) == 0x5a4d and filesize < 287KB and
    4 of them
}
    
rule efeacefeefbdddbdfccffddedcaadbc_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "msctls_trackbar32"
        $s3 = "LoadAcceleratorsW"
        $s4 = "Transform finish."
        $s5 = "GetTouchInputInfo"
        $s6 = "Sorry, can not do it."
        $s7 = "AfxmReleaseManagedReferences"
        $s8 = "SetDefaultDllDirectories"
        $s9 = "RecentFrameAlignment"
        $s10 = "TextExtendedDisabled"
        $s11 = "HighlightedDisabled"
        $s12 = "CMFCRibbonMainPanel"
        $s13 = "OleLockRunning"
        $s14 = "RegSetValueExW"
        $s15 = ".?AVCPreviewView@@"
        $s16 = "GdipGetImageHeight"
        $s17 = "GetConsoleOutputCP"
        $s18 = "CoDisconnectObject"
        $s19 = "GetWindowDC"
        $s20 = "MFCLink_Url"
condition:
    uint16(0) == 0x5a4d and filesize < 2802KB and
    4 of them
}
    
rule ccfeccfffbafebbaedaaebdefbae_exe {
strings:
        $s1 = "z`p#``coadonkeg"
        $s2 = "`local vftable'"
        $s3 = "TerminateProcess"
        $s4 = "SetFilePointerEx"
        $s5 = "EnterCriticalSection"
        $s6 = "FindFirstFileExW"
        $s7 = "RtlCaptureContext"
        $s8 = "LoadLibraryExW"
        $s9 = "`udt returning'"
        $s10 = "GetSystemTimeAsFileTime"
        $s11 = "GetProcessHeap"
        $s12 = "AreFileApisANSI"
        $s13 = "IsProcessorFeaturePresent"
        $s14 = "operator co_await"
        $s15 = "ExitProcess"
        $s16 = "Washington1"
        $s17 = "RtlUnwindEx"
        $s18 = " Base Class Array'"
        $s19 = "IsDebuggerPresent"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 656KB and
    4 of them
}
    
rule abebeaaaebdbebdbaeef_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "oyagefuhqjx"
        $s3 = "`local vftable'"
        $s4 = "TerminateProcess"
        $s5 = "SetFilePointerEx"
        $s6 = "EnterCriticalSection"
        $s7 = "kcgpyesjmkfi"
        $s8 = "fceuizrtxyqy"
        $s9 = "FindFirstFileExA"
        $s10 = "rrhohtqlnkzuw"
        $s11 = "phwgikfmfaosh"
        $s12 = "hbtrgnfzqcddh"
        $s13 = "Unknown exception"
        $s14 = "RtlCaptureContext"
        $s15 = "CorExitProcess"
        $s16 = "LoadLibraryExW"
        $s17 = "`udt returning'"
        $s18 = "vemuycsheyzvjmd"
        $s19 = "GetSystemTimeAsFileTime"
        $s20 = "dingkpynhjpjybpl"
condition:
    uint16(0) == 0x5a4d and filesize < 408KB and
    4 of them
}
    
rule cdebebcfadbeabbffacbbfdfaea_exe {
strings:
        $s1 = "GetThreadPriority"
        $s2 = "GetCurrentThread"
        $s3 = "KERNEL32.dll"
        $s4 = "GetProcAddress"
        $s5 = "DllRegisterServer"
        $s6 = "ResumeThread"
        $s7 = "VirtualAlloc"
        $s8 = "VirtualFree"
        $s9 = "TlsGetValue"
        $s10 = "LoadLibraryA"
        $s11 = "CreateFileA"
        $s12 = "GetSystemTime"
        $s13 = "CreateThread"
        $s14 = "D$$;D$0s*H"
        $s15 = "`.rdata"
        $s16 = "D$Hk@P"
        $s17 = "9D$pr"
        $s18 = "L$(H+"
        $s19 = "L$ 9H"
        $s20 = "D$ Hk"
condition:
    uint16(0) == 0x5a4d and filesize < 346KB and
    4 of them
}
    
rule cecaeacebecafbddcbaaeebc_exe {
strings:
        $s1 = "FOR USING OUR SERVICE"
        $s2 = "c:/file.ojs"
        $s3 = "fLX0RwJhHA~"
        $s4 = ",WB&~xr{1Ap"
        $s5 = ".dg+a[ZEvI:"
        $s6 = "@TZDSk5XPJM"
        $s7 = "f-~}N4)\"iK"
        $s8 = "hqmy7;9r{2&"
        $s9 = "OpenColorProfileA"
        $s10 = "GetConsoleWindow"
        $s11 = "OLEAUT32.dll"
        $s12 = "Phone Number"
        $s13 = "COMDLG32.dll"
        $s14 = "PageSetupDlgA"
        $s15 = "midiOutPrepareHeader"
        $s16 = " Enter amount:"
        $s17 = "GetSaveFileNameA"
        $s18 = " Phone No.: %s"
        $s19 = "\"_&n>Zij%"
        $s20 = "37'fnDht%V"
condition:
    uint16(0) == 0x5a4d and filesize < 1577KB and
    4 of them
}
    
rule edccdaefbefecfebcf_exe {
strings:
        $s1 = "System.Data.OleDb"
        $s2 = "ratingComboBox"
        $s3 = "RuntimeHelpers"
        $s4 = "VideoGameForm_Load"
        $s5 = "STAThreadAttribute"
        $s6 = "DesignerGeneratedAttribute"
        $s7 = "IOException"
        $s8 = "MsgBoxStyle"
        $s9 = "=20R-@<z#?h"
        $s10 = "get_Columns"
        $s11 = "ProductName"
        $s12 = "+7Z mTN5a8,"
        $s13 = "F6Z %(g^a8X"
        $s14 = "_CorExeMain"
        $s15 = "Ta4;Uz&+w`{"
        $s16 = "VarFileInfo"
        $s17 = "q5Z }0>Ia8!"
        $s18 = "\"zBE;m30jo"
        $s19 = "op_Equality"
        $s20 = "mflgIsDirty"
condition:
    uint16(0) == 0x5a4d and filesize < 1899KB and
    4 of them
}
    
rule bffbcccfdacabeeeffcfaedcf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "_CorExeMain"
        $s3 = "MsgBoxStyle"
        $s4 = "IFormatProvider"
        $s5 = "AddMessageFilter"
        $s6 = "DialogResult"
        $s7 = "MsgBoxResult"
        $s8 = "System.Resources"
        $s9 = "get_StartInfo"
        $s10 = "GetObjectValue"
        $s11 = "set_UseShellExecute"
        $s12 = "StringSplitOptions"
        $s13 = "CultureInfo"
        $s14 = "set_Arguments"
        $s15 = "set_FileName"
        $s16 = "ClearProjectError"
        $s17 = "mscoree.dll"
        $s18 = "Interaction"
        $s19 = "Application"
        $s20 = "ProjectData"
condition:
    uint16(0) == 0x5a4d and filesize < 103KB and
    4 of them
}
    
rule abcaafecffddcecfaaeafdfeed_exe {
strings:
        $s1 = "XozyxwGXX9^VP+"
        $s2 = "Cg4Kf0yffnqxGM"
        $s3 = "hblNvptzAUK"
        $s4 = "7t}#-+0.$(v"
        $s5 = "EJfZO8lvtb@"
        $s6 = "Y/>ZluwI9n&"
        $s7 = "\"(YUSRxlW/"
        $s8 = "/wU)%#G s+4"
        $s9 = "YiVHRqCjE(4"
        $s10 = "<C@]jOB\"&s"
        $s11 = "rqKzRhadEbo"
        $s12 = "-$X4Ek9@qMF"
        $s13 = "2zplZuNHPjq"
        $s14 = "MTkYWB/R1p4"
        $s15 = "1XEqWxRA4Bv"
        $s16 = "&/[|)P!?Ua0"
        $s17 = "VrP$u5fOIqC"
        $s18 = "s~wjb4E0mPx"
        $s19 = "`wrCO+dNv8B"
        $s20 = "&HsBXwKfVv9"
condition:
    uint16(0) == 0x5a4d and filesize < 1235KB and
    4 of them
}
    
rule fefccbcefedbfbfbefbdddf_exe {
strings:
        $s1 = "^(https?|ftp):\\/\\/"
        $s2 = "RuntimeHelpers"
        $s3 = "_CorExeMain"
        $s4 = "NewLateBinding"
        $s5 = "get_StartInfo"
        $s6 = "GetObjectValue"
        $s7 = "set_UseShellExecute"
        $s8 = "StringSplitOptions"
        $s9 = "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}{15}{16}{17}{18}{19}{20}{21}{22}{23}{24}{25}{26}{27}{28}{29}{30}{31}{32}{33}{34}{35}{36}{37}{38}{39}{40}{41}{42}{43}{44}{45}{46}{47}{48}{49}{50}{51}{52}{53}{54}{55}{56}{57}{58}{59}{60}{61}{62}{63}{64}{65}{66}{67}{68}{69}{70}{71}{72}{73}{74}{75}{76}{77}{78}{79}{80}{81}{82}{83}{84}{85}{86}{87}{88}{89}{90}{91}{92}{93}{94}{95}{96}{97}{98}{99}{100}{101}{102}{103}{104}{105}{106}{107}{108}{109}{110}{111}{112}{113}{114}{115}{116}{117}{118}{119}{120}{121}{122}{123}{124}{125}{126}{127}{128}{129}{130}{131}{132}{133}{134}{135}{136}{137}{138}{139}{140}{141}{142}{143}{144}{145}{146}{147}{148}{149}{150}{151}{152}{153}{154}{155}{156}{157}{158}{159}{160}{161}{162}{163}{164}{165}{166}{167}{168}{169}{170}{171}{172}{173}{174}{175}{176}{177}{178}{179}{180}{181}{182}{183}{184}{185}{186}{187}{188}{189}{190}{191}{192}{193}{194}{195}{196}{197}{198}{199}{200}{201}{202}{203}{204}{205}{206}{207}{208}{209}{210}{211}{212}{213}{214}{215}{216}{217}{218}{219}{220}{221}{222}{223}{224}{225}{226}{227}{228}{229}{230}{231}{232}{233}{234}{235}{236}{237}{238}{239}{240}{241}{242}{243}{244}{245}{246}{247}{248}{249}{250}{251}{252}{253}{254}{255}{256}{257}{258}{259}{260}{261}{262}{263}{264}{265}{266}{267}{268}{269}{270}{271}{272}{273}{274}{275}{276}{277}{278}{279}{280}{281}{282}{283}{284}{285}{286}{287}{288}{289}{290}{291}{292}{293}{294}{295}{296}{297}{298}{299}{300}{301}{302}{303}{304}{305}{306}{307}{308}{309}{310}{311}{312}{313}{314}{315}{316}{317}{318}{319}{320}{321}{322}{323}{324}{325}{326}{327}{328}{329}{330}{331}{332}{333}{334}{335}{336}{337}{338}{339}{340}{341}{342}{343}{344}{345}{346}{347}{348}{349}{350}{351}{352}{353}{354}{355}{356}{357}{358}{359}{360}{361}{362}{363}{364}{365}{366}{367}{368}{369}{370}{371}{372}{373}{374}{375}{376}{377}{378}{379}{380}{381}{382}{383}{384}{385}{386}{387}{388}{389}{390}{391}{392}{393}{394}{395}{396}{397}{398}{399}{400}{401}{402}{403}{404}{405}{406}{407}{408}{409}{410}{411}{412}{413}{414}{415}{416}{417}{418}{419}{420}{421}{422}{423}{424}{425}{426}{427}{428}{429}{430}{431}{432}{433}{434}{435}{436}{437}{438}{439}{440}{441}{442}{443}{444}{445}{446}{447}{448}{449}{450}{451}{452}{453}{454}{455}{456}{457}{458}{459}{460}{461}{462}{463}{464}{465}{466}{467}{468}{469}{470}{471}{472}{473}{474}{475}{476}{477}{478}{479}{480}{481}{482}{483}{484}{485}{486}{487}{488}{489}{490}{491}{492}{493}{494}{495}{496}{497}{498}{499}{500}{501}{502}{503}{504}{505}{506}{507}{508}{509}{510}{511}{512}{513}{514}{515}{516}{517}{518}{519}{520}{521}{522}{523}{524}{525}{526}{527}{528}{529}{530}{531}{532}{533}{534}{535}{536}{537}{538}{539}{540}{541}{542}{543}{544}{545}{546}{547}{548}{549}{550}{551}{552}{553}{554}{555}{556}{557}{558}{559}{560}{561}{562}{563}{564}{565}{566}"
        $s10 = "VariantType"
        $s11 = "set_Arguments"
        $s12 = "set_FileName"
        $s13 = "mscoree.dll"
        $s14 = "WaitForExit"
        $s15 = "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}{15}{16}{17}{18}{19}{20}{21}{22}{23}{24}{25}{26}{27}{28}{29}{30}{31}{32}{33}{34}{35}"
        $s16 = "System.Net"
        $s17 = "Conversions"
        $s18 = "PADDINGXXPADDINGPADDINGX"
        $s19 = "v4.0.30319"
        $s20 = "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}"
condition:
    uint16(0) == 0x5a4d and filesize < 81KB and
    4 of them
}
    
rule dabcbecbecbfbdfcbcebeeecf_exe {
strings:
        $s1 = "1J+3vv5dfqvHv+bBL"
        $s2 = "Customer Name not entered"
        $s3 = "lfwOf+Of8rf+DT9z+Is"
        $s4 = "3P3zr5x36Nf+J3mf3Ov+zz3"
        $s5 = "mv8HvsvO7LDEfn"
        $s6 = "1+2f9inv+CP+m3"
        $s7 = "RuntimeHelpers"
        $s8 = "System.Data.Common"
        $s9 = "STAThreadAttribute"
        $s10 = "AuthenticationMode"
        $s11 = "DesignerGeneratedAttribute"
        $s12 = "0Pmv8Rz3+bn"
        $s13 = "f73+DjKcYai"
        $s14 = "MsgBoxStyle"
        $s15 = "ProductName"
        $s16 = "jX2Pr1nv3af"
        $s17 = "Customer ID"
        $s18 = "jetp9q1f8Xv"
        $s19 = "yzi0B8jPfNr"
        $s20 = "8zts+S5Oyvq"
condition:
    uint16(0) == 0x5a4d and filesize < 838KB and
    4 of them
}
    
rule ddabfacacebaaceabdb_exe {
strings:
        $s1 = "R_Bdu['DVA]"
        $s2 = "_CorExeMain"
        $s3 = "zUT0rWY3@h."
        $s4 = "ProductName"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "GetModuleHandleA"
        $s8 = "Microsoft Corporation"
        $s9 = "BefHd%LbI/fuI"
        $s10 = "Greater Manchester1"
        $s11 = "'a}t{zJDs5"
        $s12 = "h9?!2GaR[>"
        $s13 = "tru0In)foN"
        $s14 = "Z%W)NvmyXC"
        $s15 = ",D`wY{zJqT"
        $s16 = "q';T{`7Ls["
        $s17 = "'ts}Bwm$&{"
        $s18 = "Ub8wR H')J"
        $s19 = "]NF!t.4~ar"
        $s20 = "(8Je!/)Ii7"
condition:
    uint16(0) == 0x5a4d and filesize < 972KB and
    4 of them
}
    
rule ebabfebacabafcaebcbee_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "\\root\\SecurityCenter2"
        $s3 = "RuntimeHelpers"
        $s4 = "Clients\\StartMenuInternet\\"
        $s5 = "GetProcessesByName"
        $s6 = "lpVolumeNameBuffer"
        $s7 = "STAThreadAttribute"
        $s8 = "AuthenticationMode"
        $s9 = "DesignerGeneratedAttribute"
        $s10 = "LastIndexOf"
        $s11 = "My.Computer"
        $s12 = "op_Equality"
        $s13 = "PluginBytes"
        $s14 = "_CorExeMain"
        $s15 = "AES_Decrypt"
        $s16 = "ComputeHash"
        $s17 = "ProductName"
        $s18 = "NewWatchdog"
        $s19 = "SocketFlags"
        $s20 = "ThreadStaticAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 104KB and
    4 of them
}
    
rule fcdaebcdbcfcedfcbdbfffff_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "      version=\"6.0.0.0\""
        $s3 = "RegSetValueExW"
        $s4 = "LoadStringW"
        $s5 = "\"BQ2v?`fka"
        $s6 = "#4,v=s|L(G6"
        $s7 = "bf@kcMDeN%/"
        $s8 = "RcH15NoM4PW"
        $s9 = "&oq(%7,8hcF"
        $s10 = ".M%rVZd^*P9"
        $s11 = "DOU}QFK@V_B"
        $s12 = "DialogBoxParamW"
        $s13 = "ProgramFilesDir"
        $s14 = "`local vftable'"
        $s15 = "IsWindowVisible"
        $s16 = "DeviceIoControl"
        $s17 = "ARarHtmlClassName"
        $s18 = "WindowsCodecs.dll"
        $s19 = "Not enough memory"
        $s20 = "SetThreadPriority"
condition:
    uint16(0) == 0x5a4d and filesize < 4306KB and
    4 of them
}
    
rule cffdfebafefabbbdbfcbbaeca_exe {
strings:
        $s1 = "NUMBER_OF_SQUARES"
        $s2 = "btnStart_Click"
        $s3 = "STAThreadAttribute"
        $s4 = "ProductName"
        $s5 = "ShipDestroy"
        $s6 = "btnOK_Click"
        $s7 = "get_Crimson"
        $s8 = ".<5p|cfF?!^"
        $s9 = "VarFileInfo"
        $s10 = "_CorExeMain"
        $s11 = "KeyEventHandler"
        $s12 = "FileDescription"
        $s13 = "IFormatProvider"
        $s14 = "Division by Zero"
        $s15 = "GetImageFromFile"
        $s16 = " When an operator is read"
        $s17 = "InitializeComponent"
        $s18 = "KeyboardCtrl"
        $s19 = "Synchronized"
        $s20 = "IAsyncResult"
condition:
    uint16(0) == 0x5a4d and filesize < 233KB and
    4 of them
}
    
rule afeddfaaebdadccfbfbedc_exe {
strings:
        $s1 = "FileSystemAccessRule"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "op_Equality"
        $s5 = "_CorExeMain"
        $s6 = "dJ BQ,N6\"="
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "get_ModuleHandle"
        $s10 = "ResolveEventArgs"
        $s11 = "SecurityIdentifier"
        $s12 = "IAsyncResult"
        $s13 = "add_ResourceResolve"
        $s14 = "AgileDotNetRT"
        $s15 = "StringBuilder"
        $s16 = "CallSiteBinder"
        $s17 = "SetAccessControl"
        $s18 = "WindowsIdentity"
        $s19 = "System.Security"
        $s20 = "_Initialize64"
condition:
    uint16(0) == 0x5a4d and filesize < 261KB and
    4 of them
}
    
rule bfcefafccaeadfaedcee_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "Newtonsoft.Json.dll"
        $s3 = "\\root\\SecurityCenter2"
        $s4 = "RuntimeHelpers"
        $s5 = "Clients\\StartMenuInternet\\"
        $s6 = "GetProcessesByName"
        $s7 = "AuthenticationMode"
        $s8 = "lpVolumeNameBuffer"
        $s9 = "STAThreadAttribute"
        $s10 = "DesignerGeneratedAttribute"
        $s11 = "ProductName"
        $s12 = "LastIndexOf"
        $s13 = "ComputeHash"
        $s14 = "v3.5 Public"
        $s15 = "My.Computer"
        $s16 = "NewWatchdog"
        $s17 = "SocketFlags"
        $s18 = "op_Equality"
        $s19 = "PluginBytes"
        $s20 = "_CorExeMain"
condition:
    uint16(0) == 0x5a4d and filesize < 90KB and
    4 of them
}
    
rule cbdfaacafecbfedeefecfccaedce_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "Newtonsoft.Json.dll"
        $s3 = "\\root\\SecurityCenter2"
        $s4 = "RuntimeHelpers"
        $s5 = "Clients\\StartMenuInternet\\"
        $s6 = "GetProcessesByName"
        $s7 = "AuthenticationMode"
        $s8 = "lpVolumeNameBuffer"
        $s9 = "STAThreadAttribute"
        $s10 = "DesignerGeneratedAttribute"
        $s11 = "ProductName"
        $s12 = "LastIndexOf"
        $s13 = "ComputeHash"
        $s14 = "v3.5 Public"
        $s15 = "My.Computer"
        $s16 = "NewWatchdog"
        $s17 = "SocketFlags"
        $s18 = "op_Equality"
        $s19 = "PluginBytes"
        $s20 = "_CorExeMain"
condition:
    uint16(0) == 0x5a4d and filesize < 90KB and
    4 of them
}
    
rule decdbaedadbfeddacbaf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "Clients\\StartMenuInternet\\"
        $s3 = "AuthenticationMode"
        $s4 = "lpVolumeNameBuffer"
        $s5 = "STAThreadAttribute"
        $s6 = "DesignerGeneratedAttribute"
        $s7 = "ProductName"
        $s8 = "FalseString"
        $s9 = "LastIndexOf"
        $s10 = "ComputeHash"
        $s11 = "My.Computer"
        $s12 = "PluginBytes"
        $s13 = "_CorExeMain"
        $s14 = "ThreadStaticAttribute"
        $s15 = "FlushFinalBlock"
        $s16 = "ProgramList.txt"
        $s17 = "/upload.php?id="
        $s18 = "nVolumeNameSize"
        $s19 = "set_MinimizeBox"
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 38KB and
    4 of them
}
    
rule fccabecbebcdeecadbcafdecaddbb_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "Newtonsoft.Json.dll"
        $s3 = "\\root\\SecurityCenter2"
        $s4 = "RuntimeHelpers"
        $s5 = "Clients\\StartMenuInternet\\"
        $s6 = "GetProcessesByName"
        $s7 = "AuthenticationMode"
        $s8 = "lpVolumeNameBuffer"
        $s9 = "STAThreadAttribute"
        $s10 = "DesignerGeneratedAttribute"
        $s11 = "ProductName"
        $s12 = "LastIndexOf"
        $s13 = "ComputeHash"
        $s14 = "My.Computer"
        $s15 = "NewWatchdog"
        $s16 = "SocketFlags"
        $s17 = "op_Equality"
        $s18 = "PluginBytes"
        $s19 = "_CorExeMain"
        $s20 = "ThreadStaticAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 88KB and
    4 of them
}
    
rule ceafffcfcedddfedef_exe {
strings:
        $s1 = "roigtbraorn-seaarf=|roigtbraorn"
        $s2 = "RuntimeHelpers"
        $s3 = "get_ReceiveBufferSize"
        $s4 = "STAThreadAttribute"
        $s5 = "ProductName"
        $s6 = "PixelFormat"
        $s7 = "LastIndexOf"
        $s8 = "VarFileInfo"
        $s9 = "_CorExeMain"
        $s10 = "get_MachineName"
        $s11 = "FileDescription"
        $s12 = "get_ProcessName"
        $s13 = "GetDirectoryName"
        $s14 = "jlthagniasmainvp"
        $s15 = "DebuggerHiddenAttribute"
        $s16 = "roigtbraorn.Properties"
        $s17 = "AssemblyCultureAttribute"
        $s18 = "InitializeComponent"
        $s19 = "windows|roigtbraorn"
        $s20 = "roigtbraornfiale_info"
condition:
    uint16(0) == 0x5a4d and filesize < 9972KB and
    4 of them
}
    
rule bffbccdcbbfdbdfbeafdeb_exe {
strings:
        $s1 = "<dir_ques>5__1"
        $s2 = "RuntimeHelpers"
        $s3 = "get_ReceiveBufferSize"
        $s4 = "<add_up_files>d__0"
        $s5 = "STAThreadAttribute"
        $s6 = "ProductName"
        $s7 = "PixelFormat"
        $s8 = "main_socket"
        $s9 = "_CorExeMain"
        $s10 = "get_MachineName"
        $s11 = "FileDescription"
        $s12 = "get_ProcessName"
        $s13 = "GetDirectoryName"
        $s14 = "DebuggerHiddenAttribute"
        $s15 = "AssemblyCultureAttribute"
        $s16 = "InitializeComponent"
        $s17 = "Synchronized"
        $s18 = "set_TabIndex"
        $s19 = "set_ShowIcon"
        $s20 = "lookup_drive"
condition:
    uint16(0) == 0x5a4d and filesize < 11553KB and
    4 of them
}
    
rule eebdedcccfbadedeaaddbfedafdf_exe {
strings:
        $s1 = "122.15.210.128|igtmntina"
        $s2 = "RuntimeHelpers"
        $s3 = "get_ReceiveBufferSize"
        $s4 = "STAThreadAttribute"
        $s5 = "igtmntinafilesLogs"
        $s6 = "LastIndexOf"
        $s7 = "op_Equality"
        $s8 = "_CorExeMain"
        $s9 = "ProductName"
        $s10 = "PixelFormat"
        $s11 = "VarFileInfo"
        $s12 = "set_MinimizeBox"
        $s13 = "FileDescription"
        $s14 = "htintn-gtavprcs"
        $s15 = "get_MachineName"
        $s16 = "get_ProcessName"
        $s17 = "Form1_FormClosing"
        $s18 = "igtmntinadefaultP"
        $s19 = "DebuggerHiddenAttribute"
        $s20 = "InitializeComponent"
condition:
    uint16(0) == 0x5a4d and filesize < 9476KB and
    4 of them
}
    
rule afaeafdfeaebefcd_exe {
strings:
        $s1 = "ProductName"
        $s2 = ".-kX+E*P>_("
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "Microsoft Corp."
        $s6 = "netapi32.dll"
        $s7 = "VirtualProtect"
        $s8 = "Ab<XHSOh3B"
        $s9 = "ExitProcess"
        $s10 = "PACKAGEINFO"
        $s11 = "IsEqualGUID"
        $s12 = "\\}Snu>O+^J"
        $s13 = "-di\\RC'4% "
        $s14 = "version.dll"
        $s15 = "&hbZ!!Ou\"p"
        $s16 = "6O1%uOE'C0/"
        $s17 = "VariantCopy"
        $s18 = "AVICAP32.DLL"
        $s19 = "GetProcAddress"
        $s20 = "OriginalFilename"
condition:
    uint16(0) == 0x5a4d and filesize < 237KB and
    4 of them
}
    
rule ddfdbeaeadcbdbbefaaffafbbdcafbf_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "\"7\\9wp:d@0 V"
        $s3 = "Invalid 8ro"
        $s4 = "u!+`)@ D1=*"
        $s5 = "+^JK$Bl4WpH"
        $s6 = "F8]<V.DX^Zl"
        $s7 = "RSTUVWXYQZx"
        $s8 = "ProductName"
        $s9 = "b5xNdsAn1w4"
        $s10 = "VarFileInfo"
        $s11 = "JwD\";Bji<g"
        $s12 = "h.87r@tlvwx"
        $s13 = "4DE290-(J:F"
        $s14 = "7(d$H\"CB,_"
        $s15 = "FileDescription"
        $s16 = "GetModuleHandleA"
        $s17 = "<\"=*>2?:?B?J?R?Z?b?j?r?z?"
        $s18 = "EnableWindow"
        $s19 = "[aXytr'n]g0'"
        $s20 = "xWz[|_~c~gMk"
condition:
    uint16(0) == 0x5a4d and filesize < 480KB and
    4 of them
}
    
rule dbdbbcfeadfadaebddeed_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "EVariantDispatchError"
        $s3 = "TInterfacedPersistent"
        $s4 = "EVariantBadVarTypeError"
        $s5 = "GetSystemPowerStatus"
        $s6 = "ImmSetCompositionFontA"
        $s7 = "GetEnhMetaFilePaletteEntries"
        $s8 = "Unknown compression"
        $s9 = "ERR|Socket error..|"
        $s10 = " 2001, 2002 Mike Lischke"
        $s11 = "VirtualAllocEx"
        $s12 = "UntActivePorts"
        $s13 = "TShortCutList8"
        $s14 = "ckRunningOrNew"
        $s15 = "RegSetValueExA"
        $s16 = "OnMouseWheelUp"
        $s17 = "GetWindowTheme"
        $s18 = "set cdAudio door open"
        $s19 = "TWinControlActionLink"
        $s20 = "CoCreateInstanceEx"
condition:
    uint16(0) == 0x5a4d and filesize < 663KB and
    4 of them
}
    
rule bbcfaefbbfddaabadcbabbfdbebeabb_exe {
strings:
        $s1 = "set_TransparencyKey"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "AuthenticationMode"
        $s5 = "DesignerGeneratedAttribute"
        $s6 = "My.Computer"
        $s7 = "MsgBoxStyle"
        $s8 = "get_POINTER"
        $s9 = "_CorExeMain"
        $s10 = "u6jCXbK$#Vx"
        $s11 = "4,q\"b-+'ml"
        $s12 = "ProductName"
        $s13 = "zBkUexERWDs"
        $s14 = "VarFileInfo"
        $s15 = "get_DimGray"
        $s16 = "ThreadStaticAttribute"
        $s17 = "FileDescription"
        $s18 = "set_RightToLeft"
        $s19 = "PaintEventHandler"
        $s20 = "AutoSaveSettings"
condition:
    uint16(0) == 0x5a4d and filesize < 754KB and
    4 of them
}
    
rule cfebaceecdedfcfbfedfaaef_exe {
strings:
        $s1 = "SelectLeftByCharacter"
        $s2 = "ExtendSelectionLeft"
        $s3 = "SelectToPageUp"
        $s4 = "SelectUpByPage"
        $s5 = "]E=E@ETYfBU)zj"
        $s6 = "RuntimeHelpers"
        $s7 = "AreTransformsClean"
        $s8 = "get_CorrectionList"
        $s9 = "STAThreadAttribute"
        $s10 = "DesignerGeneratedAttribute"
        $s11 = "LastIndexOf"
        $s12 = "MsgBoxStyle"
        $s13 = "n8(i-\"l3;'"
        $s14 = "_CorExeMain"
        $s15 = "ProductName"
        $s16 = "VarFileInfo"
        $s17 = "ThreadStaticAttribute"
        $s18 = "FileDescription"
        $s19 = "IFormatProvider"
        $s20 = "ToggleNumbering"
condition:
    uint16(0) == 0x5a4d and filesize < 876KB and
    4 of them
}
    
rule fdabebcdcdebbdebadfebcafbadacdd_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "RegSetValueExW"
        $s4 = "CMTSilent=1"
        $s5 = "LoadStringW"
        $s6 = "pT%v0b\"1WU"
        $s7 = "DeviceIoControl"
        $s8 = "ProgramFilesDir"
        $s9 = "DialogBoxParamW"
        $s10 = "IsWindowVisible"
        $s11 = "`local vftable'"
        $s12 = "WindowsCodecs.dll"
        $s13 = "ARarHtmlClassName"
        $s14 = "GetShortPathNameW"
        $s15 = "Not enough memory"
        $s16 = "SetThreadPriority"
        $s17 = "TerminateProcess"
        $s18 = "DispatchMessageW"
        $s19 = "SetFilePointerEx"
        $s20 = "RemoveDirectoryW"
condition:
    uint16(0) == 0x5a4d and filesize < 462KB and
    4 of them
}
    
rule bcccaecdcafabffdac_exe {
strings:
        $s1 = "CMTSilent=1"
        $s2 = "nPv`~pCOL|>"
        $s3 = "GETPASSWORD1"
        $s4 = "ebuggn%WhV`0"
        $s5 = ".LW'efaul5ie"
        $s6 = "LockExclusiv"
        $s7 = "sG@vDT\"Uv`F"
        $s8 = "</trustInfo>"
        $s9 = "bk5bxKVnY/Zx-"
        $s10 = "_hypotN@or?y0"
        $s11 = "      language=\"*\"/>"
        $s12 = ".ryptProtectMemo"
        $s13 = "VirtualProtect"
        $s14 = "190725141838Z0#"
        $s15 = "PPW@h<WU<dgnqx<"
        $s16 = "`[o?Gr)I5l"
        $s17 = "49@:L;X>#G"
        $s18 = "~L(z*d.Se9"
        $s19 = "2bfF=}Z!\""
        $s20 = "|C>r<T'(o]"
condition:
    uint16(0) == 0x5a4d and filesize < 656KB and
    4 of them
}
    
rule cfaacfcddddcbddeeffdefaeeaccddfd_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExW"
        $s5 = "Q\"9k7Ns}OZ"
        $s6 = "=~_@x|VG64N"
        $s7 = "_qh>85\")}["
        $s8 = "LyfT95(7S:i"
        $s9 = "El L8QOeXj~"
        $s10 = "L1}fkQcTD6j"
        $s11 = "WxHa/o7~Pr>"
        $s12 = "7nvB:)F*qG8"
        $s13 = "#A|'vJ\"e-g"
        $s14 = "%Do^:bv&KNx"
        $s15 = "6c)`%5<E!hP"
        $s16 = ")|X[`jW*/#U"
        $s17 = "@.b6k[$\"Ez"
        $s18 = "3E}Ni*kV[&u"
        $s19 = "V H'PBI4Nwr"
        $s20 = "30=Ll;>8kWG"
condition:
    uint16(0) == 0x5a4d and filesize < 10244KB and
    4 of them
}
    
rule caaeaefdffebfacfdfcffababf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "_CorExeMain"
        $s3 = "MsgBoxStyle"
        $s4 = "MsgBoxResult"
        $s5 = "NewLateBinding"
        $s6 = "Greater Manchester1"
        $s7 = "GetObjectValue"
        $s8 = "Jersey City1"
        $s9 = "Debacfababdceba1&0$"
        $s10 = "mscoree.dll"
        $s11 = "380118235959Z0}1"
        $s12 = "New Jersey1"
        $s13 = "201217081256Z"
        $s14 = "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}{15}{16}{17}{18}{19}{20}{21}"
        $s15 = "Bcdefbeafacdcbbccabeecbadfade1"
        $s16 = "GetDomain"
        $s17 = "New York1"
        $s18 = "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}{11}{12}{13}{14}"
        $s19 = "v4.0.30319"
        $s20 = "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}"
condition:
    uint16(0) == 0x5a4d and filesize < 4234KB and
    4 of them
}
    
rule adcbebcbcfbcbdbdecbbbacbddc_exe {
strings:
        $s1 = "XmlSchemaParticle"
        $s2 = "set_MainMenuStrip"
        $s3 = "GetSchemaSerializable"
        $s4 = "ToolboxItemAttribute"
        $s5 = "set_FixedValue"
        $s6 = "GetTypedDataSetSchema"
        $s7 = "System.Data.Common"
        $s8 = "STAThreadAttribute"
        $s9 = "hRQbDziEVvG"
        $s10 = "_CorExeMain"
        $s11 = "Author_Name"
        $s12 = "get_Columns"
        $s13 = "ProductName"
        $s14 = "TouchSystem"
        $s15 = "VarFileInfo"
        $s16 = "DefaultMemberAttribute"
        $s17 = "ExecuteNonQuery"
        $s18 = "frmSanPham_Load"
        $s19 = "set_MinimizeBox"
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 377KB and
    4 of them
}
    
rule feabceebbafabdfcbfdfdffe_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "op_Equality"
        $s3 = "_CorExeMain"
        $s4 = "AddMessageFilter"
        $s5 = "Greater Manchester1"
        $s6 = "6b23cc3c-331b-438a-9ba7-9b3b273d3938"
        $s7 = "HttpClientHandler"
        $s8 = "ISerializableItem"
        $s9 = "GetObjectValue"
        $s10 = "get_EntryPoint"
        $s11 = "Jersey City1"
        $s12 = "get_HasValue"
        $s13 = "HttpWebRequest"
        $s14 = "MethodInfo"
        $s15 = "MethodBase"
        $s16 = "System.Net.Http"
        $s17 = "mscoree.dll"
        $s18 = "Application"
        $s19 = "ToByteArray"
        $s20 = "BitConverter"
condition:
    uint16(0) == 0x5a4d and filesize < 3898KB and
    4 of them
}
    
rule ebefeaccbabfadcbbebbeee_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "D(GV2~0VV4C-o]"
        $s3 = "^\"oA+Q0i\\(qD"
        $s4 = "U0C_/@&oR4T"
        $s5 = "|6U*DV5[0oC"
        $s6 = "E_@2B-c^60D"
        $s7 = "7eP3B!.V>UD"
        $s8 = "Q#ew)G*]3Fk"
        $s9 = "3Fc0a]\"Q6d"
        $s10 = "B-nGfc'rV#^"
        $s11 = "v>Y0WZ(T+w@"
        $s12 = "B+pV4D=A3f1"
        $s13 = "Go7tA%]4i3F"
        $s14 = "d3F0DKV4^!l"
        $s15 = "0DGV2}+dF*U"
        $s16 = "nG#B4rZ5Udx"
        $s17 = "EGV2f!r@/_*"
        $s18 = "Q)e`2B-nTFx"
        $s19 = "3Fw!t`?C0e^"
        $s20 = "D%tF50DC\\(D6o_"
condition:
    uint16(0) == 0x5a4d and filesize < 157KB and
    4 of them
}
    
rule deefebedcbdecabeecacffbfdcda_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "szUserMessage != NULL"
        $s3 = "SetConsoleCtrlHandler"
        $s4 = "JmhDbdf6>e8"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleA"
        $s7 = "PA[580227362014521203534]"
        $s8 = "Expression: "
        $s9 = "9A5F1F762014521203534=9A5F1F762014521203534"
        $s10 = "IsBadWritePtr"
        $s11 = "__MSVCRT_HEAP_SELECT"
        $s12 = "SetHandleCount"
        $s13 = "InterlockedDecrement"
        $s14 = "GetProcessHeap"
        $s15 = "VirtualProtect"
        $s16 = "zdI:6RYZv("
        $s17 = "(+c*jd3Ke/"
        $s18 = "Q'Z#/Nxq;@"
        $s19 = "GetCurrentProcess"
        $s20 = "ExitProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 361KB and
    4 of them
}
    
rule cefaaebdaccdbeecfcffabedd_exe {
strings:
        $s1 = "_crt_debugger_hook"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "\\SGZSClient.exe"
        $s6 = "TerminateProcess"
        $s7 = "GetCurrentThreadId"
        $s8 = "GetTickCount"
        $s9 = "_invoke_watson"
        $s10 = "FormatMessageA"
        $s11 = "GetSystemTimeAsFileTime"
        $s12 = "getGameMarketID"
        $s13 = "GetCurrentProcess"
        $s14 = "_XcptFilter"
        $s15 = "MSVCP80.dll"
        $s16 = "IsDebuggerPresent"
        $s17 = "_controlfp_s"
        $s18 = "_adjust_fdiv"
        $s19 = "KERNEL32.dll"
        $s20 = "__getmainargs"
condition:
    uint16(0) == 0x5a4d and filesize < 129KB and
    4 of them
}
    
rule ebbeeadbeedbfdffdfbd_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "ityD-biptorCKtl"
        $s4 = "FileDescription"
        $s5 = "Microsoft Corporation"
        $s6 = "PrivateBuild"
        $s7 = "YZ[2$C2\\]^P2$C_P"
        $s8 = "VirtualProtect"
        $s9 = "h,-.$)<-hyfzf{h"
        $s10 = "LegalTrademarks"
        $s11 = "l~<SAU}bZL"
        $s12 = "Pm.32Nextd"
        $s13 = "h%',-fEEBlC"
        $s14 = "ExitProcess"
        $s15 = "SHLWAPI.dll"
        $s16 = "SpecialBuild"
        $s17 = "ADVAPI32.dll"
        $s18 = "NetApiBufferFree"
        $s19 = "GetProcAddress"
        $s20 = "OriginalFilename"
condition:
    uint16(0) == 0x5a4d and filesize < 88KB and
    4 of them
}
    
rule ddacbebbdbdfaffdcbdaddcd_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "System.Linq"
        $s3 = "op_Equality"
        $s4 = "_CorExeMain"
        $s5 = "H(3?T$;.K#+"
        $s6 = "H(6W4B#>X8G"
        $s7 = "ProductName"
        $s8 = "VarFileInfo"
        $s9 = "gravePanelWhite"
        $s10 = "set_MinimizeBox"
        $s11 = "FileDescription"
        $s12 = "AddPieceToGrave"
        $s13 = "gameLayoutPanel"
        $s14 = "InitializeComponent"
        $s15 = "Synchronized"
        $s16 = "set_TabIndex"
        $s17 = "ZLnRn[vY8~w'"
        $s18 = "IAsyncResult"
        $s19 = "#B#>K,L\"<1F"
        $s20 = "^;Z:R*A ;Y/E"
condition:
    uint16(0) == 0x5a4d and filesize < 354KB and
    4 of them
}
    
rule fabfdecdfcbcacecaacdcb_exe {
strings:
        $s1 = "_CorExeMain"
        $s2 = "GetResponseStream"
        $s3 = "get_StartInfo"
        $s4 = "get_EntryPoint"
        $s5 = "set_UseShellExecute"
        $s6 = "StringSplitOptions"
        $s7 = "211204093423Z0w1\"0 "
        $s8 = "set_Arguments"
        $s9 = "set_FileName"
        $s10 = "HttpWebRequest"
        $s11 = "MethodInfo"
        $s12 = "MethodBase"
        $s13 = "mscoree.dll"
        $s14 = "Application"
        $s15 = "WaitForExit"
        $s16 = "MemoryStream"
        $s17 = "CookieContainer"
        $s18 = "Babdacffdcfcabbbeedbcabac.exe"
        $s19 = "Conversions"
        $s20 = "6.627.790.432"
condition:
    uint16(0) == 0x5a4d and filesize < 31KB and
    4 of them
}
    
rule fdecacfcbfaaeeaa_exe {
strings:
        $s1 = "=wvvv{{{oPBBBBBBB00////.'''-*%%%"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "DesignerGeneratedAttribute"
        $s5 = "gu[+0p-G>28"
        $s6 = "_CorExeMain"
        $s7 = "+,/1ADKLQH'"
        $s8 = "ProductName"
        $s9 = "VarFileInfo"
        $s10 = "ThreadStaticAttribute"
        $s11 = "FileDescription"
        $s12 = "InitializeComponent"
        $s13 = "5phinwnu.jz4"
        $s14 = "IConvertible"
        $s15 = "cypm1zqm.win"
        $s16 = "uxdpyqfg.foh"
        $s17 = "pculj5bh.vmu"
        $s18 = "mgg3ichp.ze5"
        $s19 = "yt4gw3fg.eav"
        $s20 = "y12ouoec.hrg"
condition:
    uint16(0) == 0x5a4d and filesize < 857KB and
    4 of them
}
    
rule baceaddfecbebaddbcdeccbff_exe {
strings:
        $s1 = "get_IgnoredProperties"
        $s2 = "IDifferenceFormatter"
        $s3 = "System.Linq"
        $s4 = "op_Equality"
        $s5 = "_CorExeMain"
        $s6 = "nzTkM-*Jg[K"
        $s7 = "IGrouping`2"
        $s8 = "VarFileInfo"
        $s9 = "SkipDefault"
        $s10 = "ReflectionCache"
        $s11 = "<.cctor>b__46_0"
        $s12 = "FileDescription"
        $s13 = "IsPropertyIgnored"
        $s14 = "VisitingProperty"
        $s15 = "DebuggerHiddenAttribute"
        $s16 = "IgnoreSourceProperty"
        $s17 = "._\\pW8o{yk0"
        $s18 = "AsEnumerable"
        $s19 = "Expression`1"
        $s20 = "AppendFormat"
condition:
    uint16(0) == 0x5a4d and filesize < 946KB and
    4 of them
}
    
rule acefffebacdcedacdcca_exe {
strings:
        $s1 = "get_SamplesPerSec"
        $s2 = "_ENABLE_PROFILING"
        $s3 = "remove_ReadPacket"
        $s4 = "get_BytesTransferred"
        $s5 = "GetSystemPowerStatus"
        $s6 = "GetExtendedUdpTable"
        $s7 = "set_SelectionLength"
        $s8 = "VirtualAllocEx"
        $s9 = "GetSubKeyNames"
        $s10 = "FlagsAttribute"
        $s11 = "EnterDebugMode"
        $s12 = "mozsqlite3.dll"
        $s13 = "ForLoopInitObj"
        $s14 = "RuntimeHelpers"
        $s15 = "GetProcessesByName"
        $s16 = "STAThreadAttribute"
        $s17 = "method_1732"
        $s18 = "LastIndexOf"
        $s19 = "My.Computer"
        $s20 = "op_Equality"
condition:
    uint16(0) == 0x5a4d and filesize < 359KB and
    4 of them
}
    
rule abdcdacbcffaedcbeadfddfc_exe {
strings:
        $s1 = "$this.GridSize"
        $s2 = "CSharpCodeProvider"
        $s3 = "BitConverterActivationContext"
        $s4 = "w_{c+xG1U!D"
        $s5 = "[XZ8^]}%~NT"
        $s6 = "_CorExeMain"
        $s7 = "#psScyZKYi["
        $s8 = "ProductName"
        $s9 = "VarFileInfo"
        $s10 = "FileDescription"
        $s11 = "OrdinalComparer"
        $s12 = "customCultureName"
        $s13 = "set_GenerateExecutable"
        $s14 = "DelegateBindingFlags"
        $s15 = "set_GenerateInMemory"
        $s16 = "numberGroupSeparator"
        $s17 = "CompilerParameters"
        $s18 = "dateTimeInfo"
        $s19 = "IAsyncResult"
        $s20 = "*>d~Un~#e%{$"
condition:
    uint16(0) == 0x5a4d and filesize < 707KB and
    4 of them
}
    
rule cfbbdceabafbafdebbccbaffccabea_exe {
strings:
        $s1 = "msctls_trackbar32"
        $s2 = "msctls_progress32"
        $s3 = "WinSearchChildren"
        $s4 = "SetDefaultDllDirectories"
        $s5 = "AUTOITCALLVARIABLE%d"
        $s6 = "GUICTRLCREATECONTEXTMENU"
        $s7 = "IcmpCreateFile"
        $s8 = "RegSetValueExW"
        $s9 = "<\"t|<%tx<'tt<$tp<&tl<!th<otd<]t`<[t\\<\\tX<"
        $s10 = "CoCreateInstanceEx"
        $s11 = "OpenWindowStationW"
        $s12 = "SOUNDSETWAVEVOLUME"
        $s13 = "EWM_GETCONTROLNAME"
        $s14 = "STARTMENUCOMMONDIR"
        $s15 = "GetWindowDC"
        $s16 = "LoadStringW"
        $s17 = "VB1@}~G:n*M"
        $s18 = "~f;D$@ulIyt"
        $s19 = "CopyFileExW"
        $s20 = ",[HhS.-j'Lb"
condition:
    uint16(0) == 0x5a4d and filesize < 2810KB and
    4 of them
}
    
rule bffdecffbdbcadcbbcdcaff_exe {
strings:
        $s1 = "direzioneSpecialShip"
        $s2 = "btnStart_Click"
        $s3 = "RuntimeHelpers"
        $s4 = "STAThreadAttribute"
        $s5 = "op_Equality"
        $s6 = ";~dnE5+F$r-"
        $s7 = "blackSprite"
        $s8 = "_CorExeMain"
        $s9 = "p<]:/K#ua0S"
        $s10 = "GPu|$.Sway/"
        $s11 = "1LT%Yrq>R/d"
        $s12 = "Hv.+[zI3Q\""
        $s13 = "ProductName"
        $s14 = "btnOK_Click"
        $s15 = "_07lPsi3obz"
        $s16 = "VarFileInfo"
        $s17 = "DefaultMemberAttribute"
        $s18 = "set_MinimizeBox"
        $s19 = "FileDescription"
        $s20 = "KeyEventHandler"
condition:
    uint16(0) == 0x5a4d and filesize < 724KB and
    4 of them
}
    
rule dcaedadcfaaafbcacfafdaecd_exe {
strings:
        $s1 = "RemotingException"
        $s2 = "set_SigningMethod"
        $s3 = "DescriptionAttribute"
        $s4 = "TimestampGenerator"
        $s5 = "System.Linq"
        $s6 = "_CorExeMain"
        $s7 = "ComputeHash"
        $s8 = "SimpleOAuth"
        $s9 = "|prSo5Rwxue"
        $s10 = "DefaultMemberAttribute"
        $s11 = "_instancedGenerators"
        $s12 = "ISignatureGenerator"
        $s13 = "oauth_token_secret"
        $s14 = "IAsyncResult"
        $s15 = "UTF8Encoding"
        $s16 = "\\L/ CSb^.nc"
        $s17 = "NumberStyles"
        $s18 = "AppendFormat"
        $s19 = "DigiCert1%0#"
        $s20 = "AttributeExtensions"
condition:
    uint16(0) == 0x5a4d and filesize < 919KB and
    4 of them
}
    
rule eebddeebafccbaedaeaebe_exe {
strings:
        $s1 = "==333///>7..++::<<<<,,,,,,,88888------***-."
        $s2 = "ES_DISPLAY_REQUIRED"
        $s3 = "\\root\\SecurityCenter2"
        $s4 = "EnterDebugMode"
        $s5 = "RuntimeHelpers"
        $s6 = "^z2333//////////74+666666665<,))*****@&&B"
        $s7 = "set_ReceiveBufferSize"
        $s8 = "GetProcessesByName"
        $s9 = "STAThreadAttribute"
        $s10 = "My.Computer"
        $s11 = "_CorExeMain"
        $s12 = "ComputeHash"
        $s13 = "PixelFormat"
        $s14 = "SocketFlags"
        $s15 = "ThreadStaticAttribute"
        $s16 = "get_MachineName"
        $s17 = ":Zone.Identifier"
        $s18 = "DebuggerHiddenAttribute"
        $s19 = "SystemIdleTimerReset"
        $s20 = "ICredentials"
condition:
    uint16(0) == 0x5a4d and filesize < 369KB and
    4 of them
}
    
rule edeacbaacecfaeccbebec_exe {
strings:
        $s1 = "runtime.printbool"
        $s2 = "json:\"is_admin\""
        $s3 = "*[]http.ConnState"
        $s4 = "*big.RoundingMode"
        $s5 = "*map[uint32]int32"
        $s6 = "io/ioutil.Discard"
        $s7 = ")?/a*F,#)_+-){*7)"
        $s8 = "runtime.didothers"
        $s9 = "asn1:\"optional\""
        $s10 = "unicode.Cuneiform"
        $s11 = "reflect.makeBytes"
        $s12 = "*rc4.KeySizeError"
        $s13 = "net/url.getscheme"
        $s14 = "client.RestoreDep"
        $s15 = "useRegisteredProtocol"
        $s16 = "$f64.3fc7466496cb03de"
        $s17 = "syscall.Signal.String"
        $s18 = "assignEncodingAndSize"
        $s19 = "reflect.StructTag.Get"
        $s20 = "type..eq.net.UnixAddr"
condition:
    uint16(0) == 0x5a4d and filesize < 7943KB and
    4 of them
}
    
rule caaacccffddfeffecadbfb_exe {
strings:
        $s1 = "!#W|3EF%\".!:!"
        $s2 = "Wku5cu-r S/Zu'"
        $s3 = "W~qualrrorxist"
        $s4 = "#4$|3l'\\m[f\""
        $s5 = "~ #4MwYfT<("
        $s6 = "jb~LMX>cNxd"
        $s7 = "Mq(^0KUAoTL"
        $s8 = "*%d:\"&#34;"
        $s9 = "A\"Ty^lb09t"
        $s10 = "f\"p_.^bIe*"
        $s11 = "IJT8$liUB^%"
        $s12 = "NSsql.DBTxw"
        $s13 = "k\"mgtsyvxd"
        $s14 = ".pkcs86Xaxh"
        $s15 = "}Zl'M&81)42"
        $s16 = "gubmfM9a\"X"
        $s17 = "0#GN6\"1m`|"
        $s18 = "L,hfTli]Zu)"
        $s19 = "i.z'Bs1]L}G"
        $s20 = "c/oualm23Cd"
condition:
    uint16(0) == 0x5a4d and filesize < 3162KB and
    4 of them
}
    
rule eeeaecfdebfcdaacdbbbdbafbdbf_exe {
strings:
        $s1 = "runtime.printbool"
        $s2 = "json:\"is_admin\""
        $s3 = "*[]http.ConnState"
        $s4 = "*big.RoundingMode"
        $s5 = "*map[uint32]int32"
        $s6 = "io/ioutil.Discard"
        $s7 = ")?/a*F,#)_+-){*7)"
        $s8 = "runtime.didothers"
        $s9 = "asn1:\"optional\""
        $s10 = "unicode.Cuneiform"
        $s11 = "reflect.makeBytes"
        $s12 = "*rc4.KeySizeError"
        $s13 = "net/url.getscheme"
        $s14 = "client.RestoreDep"
        $s15 = "useRegisteredProtocol"
        $s16 = "$f64.3fc7466496cb03de"
        $s17 = "syscall.Signal.String"
        $s18 = "assignEncodingAndSize"
        $s19 = "reflect.StructTag.Get"
        $s20 = "type..eq.net.UnixAddr"
condition:
    uint16(0) == 0x5a4d and filesize < 7996KB and
    4 of them
}
    
rule dabadbefcaecefaadec_exe {
strings:
        $s1 = "CreateThreadpoolTimer"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "TerminateProcess"
        $s4 = "SetFilePointerEx"
        $s5 = "SetThreadStackGuarantee"
        $s6 = "EnterCriticalSection"
        $s7 = "GetSystemTimeAsFileTime"
        $s8 = "GetProcessHeap"
        $s9 = "IsProcessorFeaturePresent"
        $s10 = "ExitProcess"
        $s11 = "IsDebuggerPresent"
        $s12 = "KERNEL32.dll"
        $s13 = "FlushFileBuffers"
        $s14 = "CabinetWClass"
        $s15 = "WriteConsoleW"
        $s16 = "GetProcAddress"
        $s17 = "2 2,2024282<2@2D2H2L2P2T2X2\\2`2d2h2l2p2t2x2|2"
        $s18 = "DOMAIN error"
        $s19 = "CreateEventExW"
        $s20 = "DecodePointer"
condition:
    uint16(0) == 0x5a4d and filesize < 142KB and
    4 of them
}
    
rule ebfcbcddeacadedccfbdeeabfc_exe {
strings:
        $s1 = "RegSetValueExW"
        $s2 = "wX:#*EB`C=y"
        $s3 = "LoadStringW"
        $s4 = "ProgramFilesDir"
        $s5 = "DialogBoxParamW"
        $s6 = "IsWindowVisible"
        $s7 = "DispatchMessageW"
        $s8 = "GetModuleHandleW"
        $s9 = "CreateCompatibleBitmap"
        $s10 = "CryptUnprotectMemory"
        $s11 = "GetCurrentDirectoryW"
        $s12 = "SHBrowseForFolderW"
        $s13 = "GETPASSWORD1"
        $s14 = "SetEndOfFile"
        $s15 = "EnableWindow"
        $s16 = "UpdateWindow"
        $s17 = "OLEAUT32.dll"
        $s18 = "GetTickCount"
        $s19 = "</trustInfo>"
        $s20 = "MapViewOfFile"
condition:
    uint16(0) == 0x5a4d and filesize < 272KB and
    4 of them
}
    
rule aedbebbdebdbeecfadffe_dll {
strings:
        $s1 = "GetModuleHandleW"
        $s2 = "TerminateProcess"
        $s3 = "EnterCriticalSection"
        $s4 = "GetCurrentThreadId"
        $s5 = "GetTickCount"
        $s6 = "SetHandleCount"
        $s7 = "    </security>"
        $s8 = "</assembly>PAPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD"
        $s9 = "2(3,3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3"
        $s10 = "GetSystemTimeAsFileTime"
        $s11 = "InterlockedDecrement"
        $s12 = "IsProcessorFeaturePresent"
        $s13 = "GetCurrentProcess"
        $s14 = "HeapDestroy"
        $s15 = "WUSER32.DLL"
        $s16 = "ExitProcess"
        $s17 = "IsDebuggerPresent"
        $s18 = "GetProcAddress"
        $s19 = "DOMAIN error"
        $s20 = "DecodePointer"
condition:
    uint16(0) == 0x5a4d and filesize < 37KB and
    4 of them
}
    
rule ffaddfceafedbfbcbdcfdebbcbfade_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "claMediumseagreen"
        $s4 = "ttdSecondaryPanel"
        $s5 = "TThemedDatePicker"
        $s6 = "FCaptionEmulation"
        $s7 = "ControlClassNameT"
        $s8 = "FAlignControlList"
        $s9 = "FCreatingMainForm"
        $s10 = "StaticSynchronize"
        $s11 = "EndFunctionInvoke"
        $s12 = "ToShortUTF8String"
        $s13 = "FRecreateChildren"
        $s14 = "MouseWheelHandler"
        $s15 = "CoAddRefServerProcess"
        $s16 = "ttbThumbBottomFocused"
        $s17 = "UnRegisterStyleEngine"
        $s18 = "Argument out of range"
        $s19 = "sfButtonTextPressed"
        $s20 = "tspMoreProgramsArrowHot"
condition:
    uint16(0) == 0x5a4d and filesize < 2187KB and
    4 of them
}
    
rule bbaeacbedaebcaddccccecc_exe {
strings:
        $s1 = "BitConvertBuilder"
        $s2 = "ES_DISPLAY_REQUIRED"
        $s3 = "EnterDebugMode"
        $s4 = "GetProcessesByName"
        $s5 = "RuntimuFieldHandlu"
        $s6 = "CallingCo~ventions"
        $s7 = "Comf{sibleA"
        $s8 = "My.Computer"
        $s9 = "_^o}DwlXatn"
        $s10 = "_CorExe]ain"
        $s11 = "System.Li~q"
        $s12 = ">NET Framew"
        $s13 = "ProductName"
        $s14 = "PixelFormat"
        $s15 = "SocketFlags"
        $s16 = "VarFileInfo"
        $s17 = "ComputeXash"
        $s18 = "~t|megypxHa"
        $s19 = "}~czrpe9dwl"
        $s20 = "L?xml versi"
condition:
    uint16(0) == 0x5a4d and filesize < 195KB and
    4 of them
}
    
rule aaaddbaeffdecdabecdffcddadedca_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "ComputeHash"
        $s3 = "System.Linq"
        $s4 = "_CorExeMain"
        $s5 = "zWswVDGHzuU=___"
        $s6 = "IsWhiteSpace"
        $s7 = "IlcException"
        $s8 = "get_StartInfo"
        $s9 = "GetObjectValue"
        $s10 = "InitializeArray"
        $s11 = "set_UseShellExecute"
        $s12 = "StringSplitOptions"
        $s13 = "IDisposable"
        $s14 = "get_Unicode"
        $s15 = "IEnumerator"
        $s16 = "ReadAllLines"
        $s17 = "DataGridCell"
        $s18 = "set_Arguments"
        $s19 = "set_FileName"
        $s20 = "CreateDecryptor"
condition:
    uint16(0) == 0x5a4d and filesize < 230KB and
    4 of them
}
    
rule bdcafffbbecbcfbcfdfe_exe {
strings:
        $s1 = "e4d5dd60-3018-4f85-9971-8d1f87448178"
        $s2 = "get_TypeHandle"
        $s3 = "RuntimeHelpers"
        $s4 = "dbDDDAebAadbfDEBcfBFACEeF"
        $s5 = "ProductName"
        $s6 = "op_Equality"
        $s7 = "MsgBoxStyle"
        $s8 = "VarFileInfo"
        $s9 = "_CorExeMain"
        $s10 = "___EbBeACabeAceAdbebdDFfaedfBAd"
        $s11 = "FileDescription"
        $s12 = "get_IsConstructor"
        $s13 = "Microsoft Corporation"
        $s14 = "___bBfAcfFCdeBFcfcaBEafFfbcbfeAd"
        $s15 = "get_DateTimeFormat"
        $s16 = "___FCecADbEffcAfEACeCfcFBaAfDD"
        $s17 = "IAsyncResult"
        $s18 = "MsgBoxResult"
        $s19 = "___bFAdEcFfeeeaBD"
        $s20 = "dDBEefbEbEEDcefFCaBAdEAb"
condition:
    uint16(0) == 0x5a4d and filesize < 160KB and
    4 of them
}
    
rule bfedadbbacbbcdedaaacbeded_exe {
strings:
        $s1 = "@nnc^kjibueObject"
        $s2 = "MinorImageVersion"
        $s3 = "ReadOnlyCollZCdaklCase"
        $s4 = "VirtualAllocEx"
        $s5 = "StringComparer"
        $s6 = "comm^qk)`nm?0l"
        $s7 = "MajorLinkerVersion"
        $s8 = "MarshalAsAttribute"
        $s9 = "QdcurityIdentifier"
        $s10 = "HbwGilZQnjf"
        $s11 = "hAy|BmsExit"
        $s12 = "?~]DkdliFUN"
        $s13 = "X@moLj}b'^_"
        $s14 = "SizeOfIm^Gu"
        $s15 = "op_Equality"
        $s16 = "byKEclkvoet"
        $s17 = "mzhnpurFTj~"
        $s18 = "_CorExeMain"
        $s19 = "IDiLo`tbclZ"
        $s20 = "SocketFl^x|"
condition:
    uint16(0) == 0x5a4d and filesize < 254KB and
    4 of them
}
    
rule fedbedeecffbdeaccbb_exe {
strings:
        $s1 = "ManagementBaseObject"
        $s2 = "ES_DISPLAY_REQUIRED"
        $s3 = "\\root\\SecurityCenter2"
        $s4 = "EnterDebugMode"
        $s5 = "RuntimeHelpers"
        $s6 = "set_ReceiveBufferSize"
        $s7 = "GetProcessesByName"
        $s8 = "STAThreadAttribute"
        $s9 = "PixelFormat"
        $s10 = "ComputeHash"
        $s11 = "My.Computer"
        $s12 = "SocketFlags"
        $s13 = "_CorExeMain"
        $s14 = "ThreadStaticAttribute"
        $s15 = "get_MachineName"
        $s16 = "_Lambda$__R13-2"
        $s17 = ":Zone.Identifier"
        $s18 = "DebuggerHiddenAttribute"
        $s19 = "SystemIdleTimerReset"
        $s20 = "ICredentials"
condition:
    uint16(0) == 0x5a4d and filesize < 33KB and
    4 of them
}
    
rule fcafbaedefeeefdebcee_exe {
strings:
        $s1 = "ManagementBaseObject"
        $s2 = "ES_DISPLAY_REQUIRED"
        $s3 = "\\root\\SecurityCenter2"
        $s4 = "EnterDebugMode"
        $s5 = "RuntimeHelpers"
        $s6 = "set_ReceiveBufferSize"
        $s7 = "GetProcessesByName"
        $s8 = "STAThreadAttribute"
        $s9 = "PixelFormat"
        $s10 = "ComputeHash"
        $s11 = "My.Computer"
        $s12 = "SocketFlags"
        $s13 = "_CorExeMain"
        $s14 = "ThreadStaticAttribute"
        $s15 = "get_MachineName"
        $s16 = "_Lambda$__R13-2"
        $s17 = ":Zone.Identifier"
        $s18 = "DebuggerHiddenAttribute"
        $s19 = "SystemIdleTimerReset"
        $s20 = "ICredentials"
condition:
    uint16(0) == 0x5a4d and filesize < 33KB and
    4 of them
}
    
rule ceecdfcbdecacaebcfcbab_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "GetSubKeyNames"
        $s3 = "<Getip>b__13_0"
        $s4 = "RuntimeHelpers"
        $s5 = "GetProcessesByName"
        $s6 = "get_ProcessorCount"
        $s7 = "ReadFromEmbeddedResources"
        $s8 = "LastIndexOf"
        $s9 = "op_Equality"
        $s10 = "EmailSendTo"
        $s11 = "_CorExeMain"
        $s12 = "XmlNodeList"
        $s13 = "ComputeHash"
        $s14 = ",'e AWl\"tN"
        $s15 = "ProductName"
        $s16 = "GroupCollection"
        $s17 = "SerializeObject"
        $s18 = "OperativeSystem"
        $s19 = "FileDescription"
        $s20 = "SendingInterval"
condition:
    uint16(0) == 0x5a4d and filesize < 553KB and
    4 of them
}
    
rule fcfcaddaabfeccfebebaffcea_exe {
strings:
        $s1 = "VirtualAllocEx"
        $s2 = "STAThreadAttribute"
        $s3 = "op_Equality"
        $s4 = "_CorExeMain"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "sC}-QUnhP+T"
        $s8 = "FileDescription"
        $s9 = "timestamp.intel.com"
        $s10 = "dKCnOxbbW7xx0xVWp5x"
        $s11 = "WriteProcessMemory"
        $s12 = "Synchronized"
        $s13 = "Ij, \"o.118t"
        $s14 = "AutoScaleMode"
        $s15 = "GeneratedCodeAttribute"
        $s16 = "CallSiteBinder"
        $s17 = "Santa Clara1\"0 "
        $s18 = "System.Security"
        $s19 = "defaultInstance"
        $s20 = "ReferenceEquals"
condition:
    uint16(0) == 0x5a4d and filesize < 767KB and
    4 of them
}
    
rule eacceadabfdfcaccabbebe_exe {
strings:
        $s1 = "ResolveTypeHandle"
        $s2 = "FlagsAttribute"
        $s3 = "$this.GridSize"
        $s4 = "RuntimeHelpers"
        $s5 = "GetProcessesByName"
        $s6 = "STAThreadAttribute"
        $s7 = "ProductName"
        $s8 = "ComputeHash"
        $s9 = "My.Computer"
        $s10 = "_E=GXI;kY&N"
        $s11 = "VarFileInfo"
        $s12 = "_CorExeMain"
        $s13 = "ThreadStaticAttribute"
        $s14 = "FlushFinalBlock"
        $s15 = "MemberRefsProxy"
        $s16 = "FileDescription"
        $s17 = "WebClientProtocol"
        $s18 = "customCultureName"
        $s19 = "get_ServicePoint"
        $s20 = "DebuggerHiddenAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 338KB and
    4 of them
}
    
rule ffdacfccbdbefeeacadddbbbcf_exe {
strings:
        $s1 = "Empty email field"
        $s2 = "$this.MinimumSize"
        $s3 = "Enrolled Students"
        $s4 = "textLastName.Location"
        $s5 = "set_OverwritePrompt"
        $s6 = "Insufficient student data"
        $s7 = "set_TransparencyKey"
        $s8 = "inputLayout.ColumnCount"
        $s9 = "RefreshSection"
        $s10 = "RuntimeHelpers"
        $s11 = ">>textLastName.Parent"
        $s12 = "MenuItemCollection"
        $s13 = "STAThreadAttribute"
        $s14 = "LastIndexOf"
        $s15 = "op_Equality"
        $s16 = "_CorExeMain"
        $s17 = "Gkh_KeyDown"
        $s18 = "Ticker Rows"
        $s19 = "get_Fuchsia"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 566KB and
    4 of them
}
    
rule cdbfdaaecbbadecbbccba_exe {
strings:
        $s1 = "txt_supplier_address"
        $s2 = "RuntimeHelpers"
        $s3 = "System.Data.Common"
        $s4 = "msClinicInfo_Click"
        $s5 = "STAThreadAttribute"
        $s6 = "op_Equality"
        $s7 = "j9k?i2eoya<"
        $s8 = "M0Z m7$la8|"
        $s9 = "_CorExeMain"
        $s10 = "UOZ 1ghsa8T"
        $s11 = "r:RIuT~lD5g"
        $s12 = "get_Columns"
        $s13 = "ProductName"
        $s14 = "pictureBox1"
        $s15 = "VarFileInfo"
        $s16 = "kVZ -7G&a8v"
        $s17 = "\"MZ A6vla8"
        $s18 = "u)Z iTG$a8W"
        $s19 = "Cancel_40px"
        $s20 = "ExecuteNonQuery"
condition:
    uint16(0) == 0x5a4d and filesize < 1096KB and
    4 of them
}
    
rule affbefbccedbafadebbfffcfd_exe {
strings:
        $s1 = "_ENABLE_PROFILING"
        $s2 = "RuntimeHelpers"
        $s3 = "System.Data.Common"
        $s4 = "STAThreadAttribute"
        $s5 = "AuthenticationMode"
        $s6 = "DesignerGeneratedAttribute"
        $s7 = "_slCheckbox"
        $s8 = "!Copyright "
        $s9 = "Enable SFX?"
        $s10 = "My.Computer"
        $s11 = "op_Equality"
        $s12 = "MsgBoxStyle"
        $s13 = "_CorExeMain"
        $s14 = "GSZ ;2hra86"
        $s15 = "ProductName"
        $s16 = "VarFileInfo"
        $s17 = "ThreadStaticAttribute"
        $s18 = "FileDescription"
        $s19 = "KeyEventHandler"
        $s20 = "get_ProcessName"
condition:
    uint16(0) == 0x5a4d and filesize < 910KB and
    4 of them
}
    
rule ffbcedbaddbbbfeacaacebcd_exe {
strings:
        $s1 = "PartialExtensions"
        $s2 = "createTypeBuilder"
        $s3 = "AssemblyBuilderAccess"
        $s4 = "StoreOperationStageComponent"
        $s5 = "RuntimeHelpers"
        $s6 = "System.Data.Common"
        $s7 = "System.Linq"
        $s8 = "op_Equality"
        $s9 = "DisplayText"
        $s10 = "_CorExeMain"
        $s11 = "ComputeHash"
        $s12 = "-tBHjK\">Eh"
        $s13 = "b[Xftgw~dVW"
        $s14 = "IGrouping`2"
        $s15 = "IFormatProvider"
        $s16 = "PropertyBuilder"
        $s17 = "DataRowCollection"
        $s18 = "OrderByDescending"
        $s19 = "GetExpressionText"
        $s20 = "IMarkupFormatter"
condition:
    uint16(0) == 0x5a4d and filesize < 1001KB and
    4 of them
}
    
rule babffebfeaabfaaaffbedbcbafffdcdcbf_exe {
strings:
        $s1 = "txt_supplier_address"
        $s2 = "RuntimeHelpers"
        $s3 = "System.Data.Common"
        $s4 = "msClinicInfo_Click"
        $s5 = "STAThreadAttribute"
        $s6 = "x/M#b>l*Q{m"
        $s7 = "op_Equality"
        $s8 = "j9k?i2eoya<"
        $s9 = "j!YZ -lwa8J"
        $s10 = "_CorExeMain"
        $s11 = "S34(p1%\"n)"
        $s12 = "get_Columns"
        $s13 = "ProductName"
        $s14 = "'zcZ dbP=a8"
        $s15 = "pictureBox1"
        $s16 = "VarFileInfo"
        $s17 = ")GZ 0?OWa8!"
        $s18 = "$Z \"mOXa8Q"
        $s19 = "s6Z C,}qa8d"
        $s20 = "OGnLk%gT(Kj"
condition:
    uint16(0) == 0x5a4d and filesize < 1085KB and
    4 of them
}
    
rule dcbbccaebbbdcabbfbebdaa_exe {
strings:
        $s1 = "<.ctor>b__20_3"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "e^.;NAT,o[u"
        $s5 = "_CorExeMain"
        $s6 = "SoundPlayer"
        $s7 = "ProductName"
        $s8 = "VarFileInfo"
        $s9 = "FileDescription"
        $s10 = "KeyEventHandler"
        $s11 = "set_FilterIndex"
        $s12 = "get_ClipRectangle"
        $s13 = "IndirectVecteur2D"
        $s14 = "InitializeComponent"
        $s15 = "Synchronized"
        $s16 = "System.Media"
        $s17 = "IAsyncResult"
        $s18 = "<Update>b__2"
        $s19 = "GraphicsUnit"
        $s20 = "DialogResult"
condition:
    uint16(0) == 0x5a4d and filesize < 583KB and
    4 of them
}
    
rule fcaadafcaddcfedefbfabeb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "TInterfacedPersistent"
        $s4 = "TShortCutEvent"
        $s5 = "TbbbKF+je;|c$A"
        $s6 = "OnMouseWheelUp"
        $s7 = "TContextPopupEvent"
        $s8 = "GetWindowDC"
        $s9 = "s&8?iYm\"Qg"
        $s10 = "LoadStringA"
        $s11 = "#51SJW$(go|"
        $s12 = "TBrushStyle"
        $s13 = "fsStayOnTop"
        $s14 = "TClipboardt"
        $s15 = "TMenuMeasureItemEvent"
        $s16 = "TCustomDockForm"
        $s17 = "TCustomGroupBox"
        $s18 = "GetThreadLocale"
        $s19 = "ooDrawFocusRect"
        $s20 = "TMenuAnimations"
condition:
    uint16(0) == 0x5a4d and filesize < 786KB and
    4 of them
}
    
rule bbbdcbbcabefafdaccbede_exe {
strings:
        $s1 = "ProductName"
        $s2 = "VarFileInfo"
        $s3 = "_CorExeMain"
        $s4 = "FileDescription"
        $s5 = "Synchronized"
        $s6 = "System.Resources"
        $s7 = "GeneratedCodeAttribute"
        $s8 = "defaultInstance"
        $s9 = "DebuggingModes"
        $s10 = "LegalTrademarks"
        $s11 = "Copyright "
        $s12 = "IDisposable"
        $s13 = "CultureInfo"
        $s14 = "DownloadFile"
        $s15 = "ConsoleApp42"
        $s16 = "get_Assembly"
        $s17 = "OriginalFilename"
        $s18 = "VS_VERSION_INFO"
        $s19 = "GetTempPath"
        $s20 = "resourceMan"
condition:
    uint16(0) == 0x5a4d and filesize < 11KB and
    4 of them
}
    
rule ecefcbbbfcccebfdcceabca_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "Directory not empty"
        $s3 = "No child processes"
        $s4 = "GetConsoleOutputCP"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "FileDescription"
        $s8 = "`local vftable'"
        $s9 = "TerminateProcess"
        $s10 = "ConsoleApp42.exe"
        $s11 = "GetModuleHandleW"
        $s12 = "Operation not permitted"
        $s13 = "EnterCriticalSection"
        $s14 = "No locks available"
        $s15 = "SetEndOfFile"
        $s16 = "Module32Next"
        $s17 = "Invalid seek"
        $s18 = "OLEAUT32.dll"
        $s19 = "GetTickCount"
        $s20 = "Improper link"
condition:
    uint16(0) == 0x5a4d and filesize < 188KB and
    4 of them
}
    
rule addbcaeafdaafdacebcaaeacbdbb_exe {
strings:
        $s1 = "set_AllowFullOpen"
        $s2 = "ForwardDiagonalLinear"
        $s3 = "get_OffsetMarshaler"
        $s4 = "get_ControlDarkDark"
        $s5 = "STAThreadAttribute"
        $s6 = "get_SumKola"
        $s7 = "op_Equality"
        $s8 = "Mn ,u&;JU1W"
        $s9 = "Form1_KeyUp"
        $s10 = "_CorExeMain"
        $s11 = "ProductName"
        $s12 = "VarFileInfo"
        $s13 = "Dw8\"?s4>c#"
        $s14 = "FileDescription"
        $s15 = "KeyEventHandler"
        $s16 = "DoubleBufferPanel"
        $s17 = "set_SizeGripStyle"
        $s18 = "tbPriceHamburger"
        $s19 = "tbSumClientInput"
        $s20 = "Resource_Meter.Checker"
condition:
    uint16(0) == 0x5a4d and filesize < 843KB and
    4 of them
}
    
rule eecbfcabedbafbcffcedcbbdae_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "`vector destructor iterator'"
        $s3 = "pllhhhgqpoowvutt||zz"
        $s4 = "\"\"\\~xX}yXzzXwtXusXqXX9)"
        $s5 = ">>?.==<;UU79_Nfdddddd3"
        $s6 = "Directory not empty"
        $s7 = "No child processes"
        $s8 = "[Y1~VUUTRRQQOOPPP>"
        $s9 = "GetConsoleOutputCP"
        $s10 = "ProductName"
        $s11 = "V,-+%?'(& N"
        $s12 = "VarFileInfo"
        $s13 = "S~|{zxvu3p&"
        $s14 = "FileDescription"
        $s15 = "`local vftable'"
        $s16 = "TerminateProcess"
        $s17 = "GetModuleHandleW"
        $s18 = "ConsoleApp42.exe"
        $s19 = "Operation not permitted"
        $s20 = "EnterCriticalSection"
condition:
    uint16(0) == 0x5a4d and filesize < 3053KB and
    4 of them
}
    
rule becadbccceacedcbebcfbeaff_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "All Goods are at Net Cost"
        $s3 = "SetInvoiceHead"
        $s4 = "System.Data.Common"
        $s5 = "STAThreadAttribute"
        $s6 = "op_Equality"
        $s7 = "_CorExeMain"
        $s8 = "pictureBox1"
        $s9 = "v5Smo@CI M>"
        $s10 = "VarFileInfo"
        $s11 = "ReadInvoiceData"
        $s12 = "ExecuteNonQuery"
        $s13 = "get_DefaultView"
        $s14 = "dateTimePicker2"
        $s15 = "FileDescription"
        $s16 = "Contact Details"
        $s17 = "Please Select Party Name"
        $s18 = "Edit Item Details"
        $s19 = "Select Challan No"
        $s20 = "ToShortDateString"
condition:
    uint16(0) == 0x5a4d and filesize < 667KB and
    4 of them
}
    
rule efccaeccfcadcffccfafd_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "RuntimeHelpers"
        $s3 = "set_ReceiveBufferSize"
        $s4 = "MarshalAsAttribute"
        $s5 = "lpVolumeNameBuffer"
        $s6 = "STAThreadAttribute"
        $s7 = "PixelFormat"
        $s8 = "ComputeHash"
        $s9 = "SocketFlags"
        $s10 = "op_Equality"
        $s11 = "_CorExeMain"
        $s12 = "get_MachineName"
        $s13 = "nVolumeNameSize"
        $s14 = "get_ServicePack"
        $s15 = "FileDescription"
        $s16 = "get_ProcessName"
        $s17 = "lpFileSystemFlags"
        $s18 = "ComputerInfo"
        $s19 = "Updating To "
        $s20 = "get_LastWriteTime"
condition:
    uint16(0) == 0x5a4d and filesize < 37KB and
    4 of them
}
    
rule aebfbfffcdcbfdedaddbddb_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "cross device link"
        $s4 = "CreateThreadpoolTimer"
        $s5 = "`vector destructor iterator'"
        $s6 = "_libm_sse2_pow_precise"
        $s7 = "executable format error"
        $s8 = "SeProfileSingleProcessPrivilege"
        $s9 = "result out of range"
        $s10 = "directory not empty"
        $s11 = "VirtualAllocEx"
        $s12 = "DividerOpacity"
        $s13 = "offsize >= 1 && offsize <= 4"
        $s14 = "width <= 0xffff && height <= 0xffff"
        $s15 = "invalid string position"
        $s16 = "ios_base::failbit set"
        $s17 = "operation canceled"
        $s18 = "Sr2t\"=U4k~"
        $s19 = "i!&#AY6HoT<"
        $s20 = "LC_MONETARY"
condition:
    uint16(0) == 0x5a4d and filesize < 731KB and
    4 of them
}
    
rule bddbcfddefbeeebdbfbe_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "My.Computer"
        $s4 = "SocketFlags"
        $s5 = "_CorExeMain"
        $s6 = "ThreadStaticAttribute"
        $s7 = "get_MachineName"
        $s8 = "FileDescription"
        $s9 = "Add Plugin ERROR"
        $s10 = "DebuggerHiddenAttribute"
        $s11 = "ComputerInfo"
        $s12 = "Updating To "
        $s13 = "get_LastWriteTime"
        $s14 = "DirectoryInfo"
        $s15 = "StringBuilder"
        $s16 = "GetWindowText"
        $s17 = "CompareMethod"
        $s18 = "GetFolderPath"
        $s19 = "SpecialFolder"
        $s20 = "GeneratedCodeAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 35KB and
    4 of them
}
    
rule cfadeafddaacbeabedcbcfddfec_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "RuntimeHelpers"
        $s3 = "set_ReceiveBufferSize"
        $s4 = "lpVolumeNameBuffer"
        $s5 = "STAThreadAttribute"
        $s6 = "PixelFormat"
        $s7 = "ComputeHash"
        $s8 = "SocketFlags"
        $s9 = "op_Equality"
        $s10 = "_CorExeMain"
        $s11 = "get_MachineName"
        $s12 = "nVolumeNameSize"
        $s13 = "get_ServicePack"
        $s14 = "get_ProcessName"
        $s15 = "lpFileSystemFlags"
        $s16 = "karinepidh.ddns.net"
        $s17 = "get_Keyboard"
        $s18 = "ComputerInfo"
        $s19 = "Updating To "
        $s20 = "get_LastWriteTime"
condition:
    uint16(0) == 0x5a4d and filesize < 28KB and
    4 of them
}
    
rule adceeddbabebccccdedddaa_ps {
strings:
        $s1 = "-ec CQAgACAAUwBFAHQALQBjAE8AbgBUAEUATgBUAAkACQAJAC0AdgBBAAkACQAJACgAIAAgAAkAJgAoACcATgBlAFcALQBPAGIAagBlACcAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAArACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAnAEMAdAAnACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAApACAACQAgACgACQAgAAkAJwBuAEUAdAAuAHcAZQBiAEMAbABpAGUATgB0ACcACQAJAAkAIAAgACAAKQApAC4AKAAgAAkAIAAnAEQAbwBXACcAIAAgACAAIAAgACAAKwAgACAAIAAnAG4AbABPAGEAZABkACcAIAAgACAAIAAgACAAKwAgACAAIAAnAGEAVABhACcAIAAgACAACQAJAAkAKQAuAGkAbgBWAG8AawBlACgACQAJAAkAKAAdIGgAdAB0AHAAcwA6AC8ALwBuAHQAcgBvAC4AZgByAC8AZwB0AHIAZABlAGsALwAxAC4AcABuAB0gCQAgACAACQAgACAAKwAJACAAIAAdIGcAHSAJACAAIAApAAkACQAgACkAIAAJAAkALQBlAE4ACQAgAAkAKAAgACAACQAnAGIAJwAJACAACQAJACAACQArAAkAIAAJACcAWQB0AGUAJwAJACAACQAJACAACQApAAkACQAgAC0AUABBAHQASAAJAAkAIAAdICQAZQBuAHYAOgBMAG8AQwBhAGwAYQBQAFAARABhAHQAYQBcAGYAbwBuAHQAZAByAHYAaABvAHMAdAAuAGUAeABlAB0gCQAJACAAOwAJACAAIAAoAAkAIAAJAE4AZQBXAC0AbwBCAEoARQBjAFQAIAAJACAALQBDAAkACQAJAHcAcwBDAFIASQBQAHQALgBzAEgAZQBMAEwACQAgAAkAKQAuAHIAdQBuACgACQAgAAkAHSAkAEUATgBWADoAbABPAGMAYQBMAGEAUABQAEQAYQBUAGEAXABmAG8AbgB0AGQAcgB2AGgAbwBzAHQALgBlAHgAZQAdIAkACQAgACkA"
        $s2 = "-w hIddeN  "
condition:
    uint16(0) == 0x5a4d and filesize < 6KB and
    all of them
}
    
rule ebdcffebabefeacdffcfcdca_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "AudioEndpointType"
        $s3 = "EventLogEntryType"
        $s4 = "Requested Key Log"
        $s5 = "StaticPerformance"
        $s6 = "set_MonikerString"
        $s7 = "_notEncodedBuffer"
        $s8 = "_keyboardDelegate"
        $s9 = "DESKTOP_ENUMERATE"
        $s10 = "HSHELL_APPCOMMAND"
        $s11 = "set_FillWithZeros"
        $s12 = "GetFrameMoveRects"
        $s13 = "CommandDictionary"
        $s14 = "remove_SendFailed"
        $s15 = "First display is 1."
        $s16 = "AdministrationApiVersion"
        $s17 = "ClientCommandsCommunication"
        $s18 = "TCP_TABLE_BASIC_CONNECTIONS"
        $s19 = "ConditionalAttribute"
        $s20 = "QDC_DATABASE_CURRENT"
condition:
    uint16(0) == 0x5a4d and filesize < 1022KB and
    4 of them
}
    
rule dfbaceeddbcbacccaabdbbbadfabf_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "AudioEndpointType"
        $s3 = "EventLogEntryType"
        $s4 = "Requested Key Log"
        $s5 = "StaticPerformance"
        $s6 = "set_MonikerString"
        $s7 = "_notEncodedBuffer"
        $s8 = "_keyboardDelegate"
        $s9 = "DESKTOP_ENUMERATE"
        $s10 = "HSHELL_APPCOMMAND"
        $s11 = "set_FillWithZeros"
        $s12 = "GetFrameMoveRects"
        $s13 = "CommandDictionary"
        $s14 = "remove_SendFailed"
        $s15 = "First display is 1."
        $s16 = "AdministrationApiVersion"
        $s17 = "ClientCommandsCommunication"
        $s18 = "TCP_TABLE_BASIC_CONNECTIONS"
        $s19 = "ConditionalAttribute"
        $s20 = "QDC_DATABASE_CURRENT"
condition:
    uint16(0) == 0x5a4d and filesize < 915KB and
    4 of them
}
    
rule dbcdadfbcdcfcaabdbdddccabbdeca_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "      version=\"6.0.0.0\""
        $s3 = "RegSetValueExW"
        $s4 = "~Mo[q?b;}cm"
        $s5 = "0~VR7\"${x|"
        $s6 = "LoadStringW"
        $s7 = "Wy7V%[FP\"k"
        $s8 = "lefjP4}r]o<"
        $s9 = "+N-A]Cf=a3U"
        $s10 = "H= @MrVvF3N"
        $s11 = "DialogBoxParamW"
        $s12 = "ProgramFilesDir"
        $s13 = "`local vftable'"
        $s14 = "IsWindowVisible"
        $s15 = "DeviceIoControl"
        $s16 = "ARarHtmlClassName"
        $s17 = "WindowsCodecs.dll"
        $s18 = "SetThreadPriority"
        $s19 = "DispatchMessageW"
        $s20 = "GetModuleHandleW"
condition:
    uint16(0) == 0x5a4d and filesize < 2167KB and
    4 of them
}
    
rule fdeabfefcfdfaadffdfccf_exe {
strings:
        $s1 = "&v!Vj!g!rAti{M"
        $s2 = "?BFSROP21h,"
        $s3 = "?D (\"zKiZb"
        $s4 = "GTlcX;-w`Wg"
        $s5 = "ed memoryZak has "
        $s6 = "-%%?.bieD\"+"
        $s7 = "3%s,:gID: \""
        $s8 = "v0(d`'^,Uy(H"
        $s9 = "TModuleInfoy"
        $s10 = "NetShareEnum"
        $s11 = "KeySlot/Auth"
        $s12 = "#X'/MtkEXr$C"
        $s13 = "NetAPI32.dll"
        $s14 = "`\\7Rjei`[]2f"
        $s15 = "k<il_urlouz&B"
        $s16 = "WNetOpenEnumA"
        $s17 = "CryptUnprotectData"
        $s18 = "SOFTWARE\\{\\De"
        $s19 = "|x9999tplh9999d`\\X9999TPLH9999D@<8999940,(9999$ "
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 367KB and
    4 of them
}
    
rule defeaacccbbeaeebcbfddddddaffcde_exe {
strings:
        $s1 = "picElementySciany"
        $s2 = "Verifing Test Message"
        $s3 = " intellectuelle de mworld."
        $s4 = "28C4C820-401A-101B-A3C9-08002B2F49FB"
        $s5 = "MSComctlLib"
        $s6 = "PrintModule"
        $s7 = "ProductName"
        $s8 = "intropm.wav"
        $s9 = "VarFileInfo"
        $s10 = "ntMUJpljoag"
        $s11 = "test message verified failed"
        $s12 = "mnuFreeSoftware"
        $s13 = "FileDescription"
        $s14 = "rightOutsetlong"
        $s15 = "Message Encoded:"
        $s16 = "Already Present "
        $s17 = "MotorolaScreentype"
        $s18 = "SecurityForm"
        $s19 = "picGhostMask"
        $s20 = "PaintDesktop"
condition:
    uint16(0) == 0x5a4d and filesize < 509KB and
    4 of them
}
    
rule fababdcffbaceacabbeeadeacce_exe {
strings:
        $s1 = "+121K1T1[1E2L207M7`7^9"
        $s2 = "GetKeyboardLayout"
        $s3 = "sqlite3_blob_open"
        $s4 = "EVariantDispatchError"
        $s5 = "TInterfacedPersistent"
        $s6 = "^UnitConnectionHelper"
        $s7 = "EVariantBadVarTypeError"
        $s8 = "GetDeviceDriverFileNameA"
        $s9 = "GetEnhMetaFilePaletteEntries"
        $s10 = "sqlite3_release_memory"
        $s11 = "GetExtendedUdpTable"
        $s12 = "sqlite3_mutex_enter"
        $s13 = "Unknown compression"
        $s14 = "sqlite3_result_blob"
        $s15 = "VirtualAllocEx"
        $s16 = "TBitmapCanvas<"
        $s17 = "sqlite3_malloc"
        $s18 = "DtServ32sm.exe"
        $s19 = "RegSetValueExA"
        $s20 = "CoCreateInstanceEx"
condition:
    uint16(0) == 0x5a4d and filesize < 616KB and
    4 of them
}
    
rule bbfecfeaafdceaeaafebfcbfcaefcc_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "TStringSparseList"
        $s3 = "EVariantDispatchError"
        $s4 = "TInterfacedPersistent"
        $s5 = "EVariantBadVarTypeError"
        $s6 = "ImmSetCompositionFontA"
        $s7 = "GetEnhMetaFilePaletteEntries"
        $s8 = " 2001, 2002 Mike Lischke"
        $s9 = "OnMouseWheelUp"
        $s10 = "GetWindowTheme"
        $s11 = "search process if desired. "
        $s12 = "EExternalException"
        $s13 = "TContextPopupEvent"
        $s14 = "TStrings|*A"
        $s15 = "GetWindowDC"
        $s16 = "OpenDialog1"
        $s17 = "TBrushStyle"
        $s18 = "fsStayOnTop"
        $s19 = "Medium Gray"
        $s20 = "TOFNotifyEx"
condition:
    uint16(0) == 0x5a4d and filesize < 658KB and
    4 of them
}
    
rule ebbcabdbecaebeedc_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "msctls_trackbar32"
        $s4 = "InsertVariableBtn"
        $s5 = "msctls_progress32"
        $s6 = "NewCancelBtnClick"
        $s7 = "Possible deadlock"
        $s8 = "TToolDockFormd\"H"
        $s9 = "CoAddRefServerProcess"
        $s10 = "TInterfacedPersistent"
        $s11 = "GetEnvironmentStrings"
        $s12 = "Return current time as a string"
        $s13 = "EVariantBadVarTypeError"
        $s14 = "Unable to insert an item"
        $s15 = "'%s' is not a valid date"
        $s16 = "?(?<?D?H?L?P?T?X?\\?L;P;T;X;\\;`;d;h;l;p;t;x;|;"
        $s17 = "< <0<?<C<U<Y<*7B7F7J7N7R7V7Z7h7w7{7"
        $s18 = "File already exists"
        $s19 = "DeviceCapabilitiesA"
        $s20 = "Invalid access code"
condition:
    uint16(0) == 0x5a4d and filesize < 1266KB and
    4 of them
}
    
rule bfcbdadacadcedcdcdaecdebd_exe {
strings:
        $s1 = "hcessheProhinathTermT"
        $s2 = "RegSetValueExA"
        $s3 = "EExternalException"
        $s4 = "TActiveThreadArray"
        $s5 = "GetWindowDC"
        $s6 = "1>&iE`Q*^%3"
        $s7 = "ProductName"
        $s8 = "LoadStringA"
        $s9 = "VarFileInfo"
        $s10 = "FileDescription"
        $s11 = "GetKeyboardType"
        $s12 = "GetThreadLocale"
        $s13 = "Division by zero"
        $s14 = "DispatchMessageA"
        $s15 = "GetModuleHandleA"
        $s16 = "EnterCriticalSection"
        $s17 = "Microsoft Corporation"
        $s18 = "GetTextExtentPoint32A"
        $s19 = "GetCurrentThreadId"
        $s20 = "WindowFromDC"
condition:
    uint16(0) == 0x5a4d and filesize < 787KB and
    4 of them
}
    
rule bbacbdaeeaeaeceffeacecc_exe {
strings:
        $s1 = "1d1521d1-9ba5-4c36-acd0-ca214c195b9c"
        $s2 = "18a97ca0-ac33-4818-8134-e3c873545986"
        $s3 = "ddd995ed-1494-4808-8d06-e59a4942b304"
        $s4 = "c00566eb-a84c-49fb-8b54-9bbc7a564cb5"
        $s5 = "90e69578-80f8-4f9e-8cf9-d197cc119f14"
        $s6 = "8378c0ca-7fa1-4a8f-8389-ae730f1f687e"
        $s7 = "0f3f2e8f-b07d-47d8-b800-d8e444e13277"
        $s8 = "2725f99e-2aec-4ce7-8a4c-a55685ca8426"
        $s9 = "9ba368af-09c4-45a7-aac7-f34864909aca"
        $s10 = "3d492704-4fff-49ea-bfa1-d91a2bdb4a41"
        $s11 = "fb2befbc-f564-4687-af67-5fbd42fa27a6"
        $s12 = "f17b6fdb-fa89-4f44-8beb-aa788ee636ff"
        $s13 = "f0c3a402-4f1a-408a-afaa-c811b08d2912"
        $s14 = "448dd418-c8be-4bcf-8fd1-a7fa0424b8d7"
        $s15 = "4e406e9e-65e9-4fe0-bdba-5694c461ac4b"
        $s16 = "dd8ae445-b51e-48ec-b8e4-446e5fd9fdc1"
        $s17 = "407c8462-a212-416d-9c94-286a6172096d"
        $s18 = "00e8117a-9b87-460e-88e2-17899b7fe706"
        $s19 = "5c9c04d0-71dd-43c8-8368-570071d68d98"
        $s20 = "8dd86845-a45c-43aa-abbf-83fd666bde4c"
condition:
    uint16(0) == 0x5a4d and filesize < 1306KB and
    4 of them
}
    
rule dadefdcfdfcadeaaeaabbbcbadae_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "msctls_trackbar32"
        $s4 = "TStringSparseList"
        $s5 = "OnItemSelected,?H"
        $s6 = "OnCustomizeAddedd"
        $s7 = "TPacketAttribute "
        $s8 = "Possible deadlock"
        $s9 = "CoAddRefServerProcess"
        $s10 = "GetEnvironmentStrings"
        $s11 = "EVariantBadVarTypeError"
        $s12 = "8 8$8(8,8084888<8@8D8H8L8P8T8X8\\8`8d8h8l8p8$6(6,6064686P6f6j6"
        $s13 = "Unable to insert an item"
        $s14 = "'%s' is not a valid date"
        $s15 = "=X?\\?`?d?h?l?p?H9L9P9T9X9l9p9t9x9|9"
        $s16 = "File already exists"
        $s17 = "Invalid access code"
        $s18 = "Directory not empty"
        $s19 = "Database Login"
        $s20 = "TShortCutEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 1224KB and
    4 of them
}
    
rule dfaacddaadfdecfffecbeedcebaaffae_exe {
strings:
        $s1 = "RegSetValueExA"
        $s2 = "EExternalException"
        $s3 = "TActiveThreadArray"
        $s4 = "GetWindowDC"
        $s5 = "ProductName"
        $s6 = "LoadStringA"
        $s7 = "VarFileInfo"
        $s8 = "LquKdMwfnjU"
        $s9 = "9\"0%7#!hLV"
        $s10 = "FileDescription"
        $s11 = "GetKeyboardType"
        $s12 = "GetThreadLocale"
        $s13 = "Division by zero"
        $s14 = "DispatchMessageA"
        $s15 = "GetModuleHandleA"
        $s16 = "EnterCriticalSection"
        $s17 = "GetTextExtentPoint32A"
        $s18 = "GetCurrentThreadId"
        $s19 = "WindowFromDC"
        $s20 = "SetEndOfFile"
condition:
    uint16(0) == 0x5a4d and filesize < 467KB and
    4 of them
}
    
rule fbbaccedbafdbfdffffc_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "msctls_trackbar32"
        $s4 = "OnContextPopupXAP"
        $s5 = "TControlCanvasP<P"
        $s6 = "msctls_progress32"
        $s7 = "TPacketAttribute "
        $s8 = "TCustomStaticText"
        $s9 = "Possible deadlock"
        $s10 = "CoAddRefServerProcess"
        $s11 = "TCustomDropDownButton"
        $s12 = "EUnsupportedTypeError"
        $s13 = "TInterfacedPersistent"
        $s14 = "< <$<(<,<0<4<8<<<@<B8F8J8N8R8V8Z8^8b8f8j8n8r8v8"
        $s15 = "Unable to insert an item"
        $s16 = "'%s' is not a valid date"
        $s17 = "TCustomActionControl"
        $s18 = "File already exists"
        $s19 = "Invalid access code"
        $s20 = "Directory not empty"
condition:
    uint16(0) == 0x5a4d and filesize < 1581KB and
    4 of them
}
    
rule ceedabafebbcfdccfbfabeeacce_exe {
strings:
        $s1 = "InitCommonControlsEx."
        $s2 = "Kampel 1151)0'"
        $s3 = "ES[each sid"
        $s4 = "#Hotkeys%?_"
        $s5 = ",. Invalid;"
        $s6 = "ProductName"
        $s7 = "`/}iewport%"
        $s8 = "VarFileInfo"
        $s9 = "ght)c jfplu"
        $s10 = "FileDescription"
        $s11 = "n C=%6.2f and A"
        $s12 = "=SafeArrayPtrOf!e"
        $s13 = "Initial Guesses:"
        $s14 = "IE(AL(\"%s\",4),\""
        $s15 = "kd8GABuffer'"
        $s16 = "sbHorizontal"
        $s17 = "THTMLPicture"
        $s18 = "yIn7ase of0s"
        $s19 = "90$ NDropdr`"
        $s20 = "butesAExitCo"
condition:
    uint16(0) == 0x5a4d and filesize < 623KB and
    4 of them
}
    
rule aeddeeeccddfecdaeffdffddacd_exe {
strings:
        $s1 = "RuntimuFieldHandlu"
        $s2 = "CallingCo~ventions"
        $s3 = "Comf{sibleA"
        $s4 = "_^o}DwlXatn"
        $s5 = "op_Equality"
        $s6 = "_CorExe]ain"
        $s7 = "System.Li~q"
        $s8 = ">NET Framew"
        $s9 = "ProductName"
        $s10 = "VarFileInfo"
        $s11 = "ComputeXash"
        $s12 = "~t|megypxHa"
        $s13 = "}~czrpe9dwl"
        $s14 = "L?xml versi"
        $s15 = "FileDescription"
        $s16 = "MessageBoxRuttons"
        $s17 = "set_RedirestStandardE"
        $s18 = "Microsoft0Corporatio~"
        $s19 = "gut_FileName"
        $s20 = "Synchronized"
condition:
    uint16(0) == 0x5a4d and filesize < 320KB and
    4 of them
}
    
rule bffdabbddacadccdaeabfbb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "msctls_trackbar32"
        $s4 = "InsertVariableBtn"
        $s5 = "DisabledImagesd>I"
        $s6 = "TStringSparseList"
        $s7 = "msctls_progress32"
        $s8 = "TPacketAttribute "
        $s9 = "NewCancelBtnClick"
        $s10 = "Possible deadlock"
        $s11 = "CoAddRefServerProcess"
        $s12 = "TInterfacedPersistent"
        $s13 = "GetEnvironmentStrings"
        $s14 = "Return current time as a string"
        $s15 = "EVariantBadVarTypeError"
        $s16 = "Unable to insert an item"
        $s17 = "'%s' is not a valid date"
        $s18 = "File already exists"
        $s19 = "DeviceCapabilitiesA"
        $s20 = "Invalid access code"
condition:
    uint16(0) == 0x5a4d and filesize < 1359KB and
    4 of them
}
    
rule cebafcfecbaecdeddfedffad_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "TSpinSpeedButtons"
        $s4 = "TrailingTextColor"
        $s5 = "RightClickSelect8"
        $s6 = "PositionGapColorT"
        $s7 = "CoAddRefServerProcess"
        $s8 = "TInterfacedPersistent"
        $s9 = "TCancelledChangeEvent"
        $s10 = "StatusStrings.NotStarted"
        $s11 = "Cannot assign object to "
        $s12 = "'%s' is not a valid date"
        $s13 = "TTodoItemSelectEvent"
        $s14 = "TDragOverHeaderEvent"
        $s15 = "TPersistenceLocation"
        $s16 = "Cannot get the format enumerator"
        $s17 = "8-848K8R8i8F:+;7;D;V;\\;l;|;"
        $s18 = "TPlannerDataBinding"
        $s19 = "EditOnSelectedClick"
        $s20 = "End game strategies"
condition:
    uint16(0) == 0x5a4d and filesize < 2853KB and
    4 of them
}
    
rule ebeedcebcccecfabfaffafabecffacadc_exe {
strings:
        $s1 = "deallocating None"
        $s2 = "s*|z:ascii_decode"
        $s3 = "PyDescr_NewMember"
        $s4 = "mon_decimal_point"
        $s5 = "method_descriptor"
        $s6 = "Py_SetProgramName"
        $s7 = "/4h7fpep#FapbpC4T"
        $s8 = "_PyTime_FloatTime"
        $s9 = "OSztuGCWdE|t}t{tC"
        $s10 = "PyType_GenericNew"
        $s11 = "S|z:escape_encode"
        $s12 = "Os|ii:DeleteKeyEx"
        $s13 = "PyErr_ProgramText"
        $s14 = "can't assign sys.argv"
        $s15 = "empty, returns start."
        $s16 = "The error setting of the decoder or encoder."
        $s17 = "9U:_:i:D;T;q;W=g=z="
        $s18 = "lllii|i:DuplicateHandle"
        $s19 = "can't concat %.100s to %.100s"
        $s20 = "can only join an iterable"
condition:
    uint16(0) == 0x5a4d and filesize < 2605KB and
    4 of them
}
    
rule ffbefecdcebefdaffeabaa_exe {
strings:
        $s1 = "SetDefaultDllDirectories"
        $s2 = "      version=\"6.0.0.0\""
        $s3 = "RegSetValueExW"
        $s4 = "LoadStringW"
        $s5 = "oCLHei?3K>w"
        $s6 = "=_jZ\"1Q&ng"
        $s7 = ":d`$f|\"4mv"
        $s8 = "d/vGsi.fhw4"
        $s9 = "o{gsA09Mf6]"
        $s10 = "6&cW\"!4<)v"
        $s11 = "YFPxA2COH;-"
        $s12 = ">A@|_kapDhY"
        $s13 = "0\"|.F1d<Oe"
        $s14 = "DPZ(*T-bHF,"
        $s15 = "DialogBoxParamW"
        $s16 = "ProgramFilesDir"
        $s17 = "`local vftable'"
        $s18 = "IsWindowVisible"
        $s19 = "DeviceIoControl"
        $s20 = "ARarHtmlClassName"
condition:
    uint16(0) == 0x5a4d and filesize < 1556KB and
    4 of them
}
    
rule fbdbcfbebbaceebdbaeb_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "System.Data.Common"
        $s3 = "msClinicInfo_Click"
        $s4 = "STAThreadAttribute"
        $s5 = "get_Columns"
        $s6 = "ProductName"
        $s7 = "pictureBox2"
        $s8 = "W;-NH,c]Q>g"
        $s9 = "Cancel_40px"
        $s10 = "fK}U$/eG{4n"
        $s11 = "j9k?i2eoya<"
        $s12 = "_CorExeMain"
        $s13 = "VarFileInfo"
        $s14 = "2,w;#S/bi.D"
        $s15 = "a^L=s]dY7l."
        $s16 = "KTZ DCW;a8d"
        $s17 = "g]C}Z:Q{-1n"
        $s18 = "3sZ =q(oa8|"
        $s19 = "Nza|`!J3BPr"
        $s20 = "/DZ 4+X3a8W"
condition:
    uint16(0) == 0x5a4d and filesize < 3738KB and
    4 of them
}
    
rule edefaecfbcbeadabafacceddccbee_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "EOutOfResources\\"
        $s4 = "TInterfacedPersistent"
        $s5 = "TShortCutEvent"
        $s6 = "m@I+++1*\"_}M0"
        $s7 = "TIdCoderCollection"
        $s8 = "TContextPopupEvent"
        $s9 = "GetWindowDC"
        $s10 = "v98YXFWlm*N"
        $s11 = "LoadStringA"
        $s12 = "TBrushStyle"
        $s13 = "fsStayOnTop"
        $s14 = "0|=_-n6d1}4"
        $s15 = "TMenuMeasureItemEvent"
        $s16 = "TCustomGroupBox"
        $s17 = "GetThreadLocale"
        $s18 = "ooDrawFocusRect"
        $s19 = "TMenuAnimations"
        $s20 = "TCanResizeEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 843KB and
    4 of them
}
    
rule bbdaaaabafcdfedae_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "TrailingTextColor"
        $s3 = "EVariantDispatchError"
        $s4 = "TInterfacedPersistent"
        $s5 = "EVariantBadVarTypeError"
        $s6 = "ImmSetCompositionFontA"
        $s7 = " 2001, 2002 Mike Lischke"
        $s8 = "OnMouseWheelUp"
        $s9 = "OnMeasureItemh"
        $s10 = "GetWindowTheme"
        $s11 = "TWinControlActionLink"
        $s12 = "EExternalException"
        $s13 = "TContextPopupEvent"
        $s14 = "TAnimate<~B"
        $s15 = "GetWindowDC"
        $s16 = "OpenDialog1"
        $s17 = "TBrushStyle"
        $s18 = "fsStayOnTop"
        $s19 = "Medium Gray"
        $s20 = "AutoSize|*C"
condition:
    uint16(0) == 0x5a4d and filesize < 773KB and
    4 of them
}
    
rule aceaabefcbcfbadbcfaaebe_exe {
strings:
        $s1 = "EOutOfResources\\"
        $s2 = "GetKeyboardLayout"
        $s3 = "TInterfacedPersistent"
        $s4 = "ImmSetCompositionFontA"
        $s5 = "GetEnhMetaFilePaletteEntries"
        $s6 = "TWinControlActionLink"
        $s7 = "EExternalException"
        $s8 = "TContextPopupEvent"
        $s9 = "TIdCoderCollection"
        $s10 = "IdException"
        $s11 = "GetWindowDC"
        $s12 = "AutoSize@(C"
        $s13 = "TBrushStyle"
        $s14 = "fsStayOnTop"
        $s15 = "O:IjrY6g{#>"
        $s16 = "LoadStringA"
        $s17 = "TMenuMeasureItemEvent"
        $s18 = "TCustomGroupBox"
        $s19 = "TMenuActionLink"
        $s20 = "ooDrawFocusRect"
condition:
    uint16(0) == 0x5a4d and filesize < 843KB and
    4 of them
}
    
rule bfbcffccccdacabdfcbfb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "EOutOfResources\\"
        $s4 = "TInterfacedPersistent"
        $s5 = "TShortCutEvent"
        $s6 = "TIdCoderCollection"
        $s7 = "TContextPopupEvent"
        $s8 = "GetWindowDC"
        $s9 = "@Gt)N9DA(BS"
        $s10 = "x}%ZRC,Xyz8"
        $s11 = "^WobY/ ez\""
        $s12 = "+HF^R5r\"m@"
        $s13 = "LoadStringA"
        $s14 = "Xa:WBFmQ85{"
        $s15 = "Hizb^e\"]sT"
        $s16 = "<-z/fK{%NIC"
        $s17 = "8Md+Aqy<Zjx"
        $s18 = "oGctrFnY%LX"
        $s19 = "TBrushStyle"
        $s20 = "fsStayOnTop"
condition:
    uint16(0) == 0x5a4d and filesize < 4246KB and
    4 of them
}
    
rule cfccdddeabfdceeaaddadfab_exe {
strings:
        $s1 = "ProductName"
        $s2 = "kJx1Qo4dLZA"
        $s3 = "VarFileInfo"
        $s4 = "_CorExeMain"
        $s5 = "vMz0KJHunLU"
        $s6 = "FileDescription"
        $s7 = "GetExportedTypes"
        $s8 = "DebuggerHiddenAttribute"
        $s9 = "fMF7Lm4QP6kQ"
        $s10 = "Dictionary`2"
        $s11 = "Durbanville1"
        $s12 = "get_CurrentThread"
        $s13 = "System.Resources"
        $s14 = "StringBuilder"
        $s15 = "RrjlEZA6urobE"
        $s16 = "EZahDgtrS1SEo"
        $s17 = "get_ManagedThreadId"
        $s18 = "GeneratedCodeAttribute"
        $s19 = "ReferenceEquals"
        $s20 = "Western Cape1"
condition:
    uint16(0) == 0x5a4d and filesize < 952KB and
    4 of them
}
    
rule ecfbdfaceacebaabdbafddded_exe {
strings:
        $s1 = "     name=\"wextract\""
        $s2 = "Sh%M}*e(`O>"
        $s3 = "j/z`i,2oN0b"
        $s4 = "(^&HyL9f~B`"
        $s5 = "ProductName"
        $s6 = "LoadStringA"
        $s7 = "2mkV4B&[+Pd"
        $s8 = "VarFileInfo"
        $s9 = "^h]g-XnF\"R"
        $s10 = "FileDescription"
        $s11 = "Command.com /c %s"
        $s12 = "GetShortPathNameA"
        $s13 = "GetModuleHandleW"
        $s14 = "RemoveDirectoryA"
        $s15 = "TerminateProcess"
        $s16 = "DispatchMessageA"
        $s17 = "SetCurrentDirectoryA"
        $s18 = "Microsoft Corporation"
        $s19 = "GetCurrentThreadId"
        $s20 = "EnableWindow"
condition:
    uint16(0) == 0x5a4d and filesize < 1179KB and
    4 of them
}
    
rule febfecafbcabefbbfdabffecbaf_exe {
strings:
        $s1 = "set_SevenOrHigher"
        $s2 = "GetKeyboardLayout"
        $s3 = "set_MonikerString"
        $s4 = "get_IsTerminating"
        $s5 = "GetWebcamResponse"
        $s6 = "set_usernameField"
        $s7 = "MakeGenericMethod"
        $s8 = "IPInterfaceProperties"
        $s9 = "Key can not be empty."
        $s10 = "GetSystemInfoResponse"
        $s11 = "keyboardStateNative"
        $s12 = "get_UnicastAddresses"
        $s13 = "DeletePath I/O error"
        $s14 = "DictionarySerializer"
        $s15 = "GetDrives No drives"
        $s16 = "ElapsedEventHandler"
        $s17 = "TemporalCompression"
        $s18 = "GetSubKeyNames"
        $s19 = "FlagsAttribute"
        $s20 = "Executed File!"
condition:
    uint16(0) == 0x5a4d and filesize < 353KB and
    4 of them
}
    
rule afeaedfadbfecaffedfafc_exe {
strings:
        $s1 = "))Tl00C]00<S223M222L333M333M++J'"
        $s2 = "AutoPropertyValue"
        $s3 = "set_MainMenuStrip"
        $s4 = "1J+3vv5dfqvHv+bBL"
        $s5 = "security_question"
        $s6 = "set_AttendenceStatusLabel"
        $s7 = "lfwOf+Of8rf+DT9z+Is"
        $s8 = "3P3zr5x36Nf+J3mf3Ov+zz3"
        $s9 = "SearchComboBox"
        $s10 = "mv8HvsvO7LDEfn"
        $s11 = "1+2f9inv+CP+m3"
        $s12 = "set_SizingGrip"
        $s13 = "RuntimeHelpers"
        $s14 = "GenderImpLabel"
        $s15 = "h$%Yy--H]333M333KKL[J"
        $s16 = "get_AddressTextBox"
        $s17 = "STAThreadAttribute"
        $s18 = "AuthenticationMode"
        $s19 = "DesignerGeneratedAttribute"
        $s20 = "T+M(4O=jN/i"
condition:
    uint16(0) == 0x5a4d and filesize < 1294KB and
    4 of them
}
    
rule accfeeabbfbcbcbfdaedbec_exe {
strings:
        $s1 = "FlagsAttribute"
        $s2 = "System.Linq"
        $s3 = "_CorExeMain"
        $s4 = "MsgBoxStyle"
        $s5 = "Greater Manchester1"
        $s6 = "get_EntryPoint"
        $s7 = "Jersey City1"
        $s8 = "MethodInfo"
        $s9 = "Enumerable"
        $s10 = "MethodBase"
        $s11 = "mscoree.dll"
        $s12 = "380118235959Z0}1"
        $s13 = "New Jersey1"
        $s14 = "Dbcdccaaadbbafcc1&0$"
        $s15 = "Afaedacabceacddbcace.exe"
        $s16 = "Bebeadfbdaffebbebaeebdbdbdbfe1&0$"
        $s17 = "20201209215745Z"
        $s18 = "New York1"
        $s19 = "v4.0.30319"
        $s20 = "Abdbdfbcfbeabffdfdbdbfeeabdbf1"
condition:
    uint16(0) == 0x5a4d and filesize < 3521KB and
    4 of them
}
    
rule fbaceacdccbfcccd_exe {
strings:
        $s1 = "TerminateProcess"
        $s2 = "waveOutSetVolume"
        $s3 = "GetModuleHandleW"
        $s4 = "EnterCriticalSection"
        $s5 = "PathGetArgsW"
        $s6 = "GetTickCount"
        $s7 = "WNetCancelConnectionA"
        $s8 = "StringFromIID"
        $s9 = "SetHandleCount"
        $s10 = "GetSystemTimeAsFileTime"
        $s11 = "InterlockedDecrement"
        $s12 = "GetDeviceCaps"
        $s13 = "VirtualProtect"
        $s14 = "\"L{6<y0et"
        $s15 = "IsProcessorFeaturePresent"
        $s16 = "9 9$9(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9p9t9x9|9"
        $s17 = "AVIFileOpen"
        $s18 = "WUSER32.DLL"
        $s19 = "ExitProcess"
        $s20 = "MSVFW32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 176KB and
    4 of them
}
    
rule afaaafcbaadbfefcdbcaffccbded_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "SetDefaultDllDirectories"
        $s5 = "RpcBindingToStringBindingA"
        $s6 = "SetConsoleCtrlHandler"
        $s7 = "LC_MONETARY"
        $s8 = "english-jamaica"
        $s9 = "InternetTimeFromSystemTime"
        $s10 = "spanish-venezuela"
        $s11 = "TerminateProcess"
        $s12 = "waveOutSetVolume"
        $s13 = "SetFilePointerEx"
        $s14 = "SetThreadStackGuarantee"
        $s15 = "EnterCriticalSection"
        $s16 = "south-africa"
        $s17 = "OLEAUT32.dll"
        $s18 = "XHxXhy>(tOJc"
        $s19 = "ImmDisableIME"
        $s20 = "trinidad & tobago"
condition:
    uint16(0) == 0x5a4d and filesize < 430KB and
    4 of them
}
    
rule cecefbbbaacfdfdeececbcfb_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "GetKeyboardLayout"
        $s3 = "VirtualAllocEx"
        $s4 = "MsgWindowClass"
        $s5 = "ProductName"
        $s6 = "IsWindowVisible"
        $s7 = "getcamsingleframe"
        $s8 = "RemoveDirectoryA"
        $s9 = "TerminateProcess"
        $s10 = "GetConsoleWindow"
        $s11 = "GetLastInputInfo"
        $s12 = "DispatchMessageA"
        $s13 = "GetModuleHandleA"
        $s14 = "CreateCompatibleBitmap"
        $s15 = "UnhookWindowsHookEx"
        $s16 = "WriteProcessMemory"
        $s17 = "GetLocalTime"
        $s18 = "ProgramFiles"
        $s19 = "GetTickCount"
        $s20 = "downloadfromlocaltofile"
condition:
    uint16(0) == 0x5a4d and filesize < 97KB and
    4 of them
}
    
rule dcabfdabbcdeadcebebbddaedd_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "##;%**D.99K5>>O5>>O.99K%))D"
        $s3 = "_2048.Resources.resources"
        $s4 = "set_TransparentColor"
        $s5 = "RuntimeHelpers"
        $s6 = "STAThreadAttribute"
        $s7 = "AuthenticationMode"
        $s8 = "DesignerGeneratedAttribute"
        $s9 = "MsgBoxStyle"
        $s10 = "_CorExeMain"
        $s11 = "E',{!;S3uIH"
        $s12 = "ProductName"
        $s13 = "VarFileInfo"
        $s14 = "ThreadStaticAttribute"
        $s15 = "FileDescription"
        $s16 = "KeyEventHandler"
        $s17 = "set_AutoValidate"
        $s18 = "get_ControlLight"
        $s19 = "AutoSaveSettings"
        $s20 = "DebuggerHiddenAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 523KB and
    4 of them
}
    
rule dbbdfefdcfbddafeaccebbdfcaab_exe {
strings:
        $s1 = "ttdSecondaryPanel"
        $s2 = "DefOrientation$D@"
        $s3 = "TRttiClassRefType"
        $s4 = "TThemedDatePicker"
        $s5 = "procedure NewPage"
        $s6 = "FAlignControlList"
        $s7 = "/Filter /Standard"
        $s8 = "EndFunctionInvoke"
        $s9 = "claMediumseagreen"
        $s10 = "Operation aborted"
        $s11 = "horizontal_header"
        $s12 = "GlassHatchCBClick"
        $s13 = "msctls_progress32"
        $s14 = "/Macrosheet /Part"
        $s15 = "VerticalAlignment"
        $s16 = "RollbackRetaining"
        $s17 = "msctls_trackbar32"
        $s18 = "System.ClassesTvI"
        $s19 = "TfrxDesignerUnits"
        $s20 = "FCaptionEmulation"
condition:
    uint16(0) == 0x5a4d and filesize < 5927KB and
    4 of them
}
    
rule baeacbaeddcbceeaabadeaebda_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "EVariantDispatchError"
        $s3 = "TInterfacedPersistent"
        $s4 = "EVariantBadVarTypeError"
        $s5 = "ImmSetCompositionFontA"
        $s6 = "9 9$9(9,9094989<9@9D9H9L9P9T9X9\\9`9d9h9l9\\<}<j="
        $s7 = " 2001, 2002 Mike Lischke"
        $s8 = "TShortCutEvent"
        $s9 = "OnMouseWheelUp"
        $s10 = "GetWindowTheme"
        $s11 = "EExternalException"
        $s12 = "TContextPopupEvent"
        $s13 = "GetWindowDC"
        $s14 = "TBrushStyle"
        $s15 = "fsStayOnTop"
        $s16 = "TMacroEvent"
        $s17 = "Medium Gray"
        $s18 = "LoadStringA"
        $s19 = "E/W]pmYnb} "
        $s20 = "TMenuMeasureItemEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 591KB and
    4 of them
}
    
rule beefedeebbddacdaccefccbdbc_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "LogoPictureBox"
        $s3 = "RuntimeHelpers"
        $s4 = "My.WebServices"
        $s5 = "InternalPartitionEnumerator"
        $s6 = "passwordAdministrator"
        $s7 = "System.Data.Common"
        $s8 = "STAThreadAttribute"
        $s9 = "AuthenticationMode"
        $s10 = "DesignerGeneratedAttribute"
        $s11 = "My.Computer"
        $s12 = "PictureBox1"
        $s13 = "_CorExeMain"
        $s14 = "Version {0}"
        $s15 = "VarFileInfo"
        $s16 = "ThreadStaticAttribute"
        $s17 = "ExecuteNonQuery"
        $s18 = "set_MinimizeBox"
        $s19 = "FileDescription"
        $s20 = ";Initial Catalog="
condition:
    uint16(0) == 0x5a4d and filesize < 630KB and
    4 of them
}
    
rule bfeddbbecbfcffaf_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "ProductName"
        $s3 = "XmlNodeList"
        $s4 = "VarFileInfo"
        $s5 = "_CorExeMain"
        $s6 = ":NOn ]\"VgP"
        $s7 = "FileDescription"
        $s8 = "Microsoft Corporation"
        $s9 = "Synchronized"
        $s10 = "ICredentials"
        $s11 = "set_TabIndex"
        $s12 = "RegexOptions"
        $s13 = "Dictionary`2"
        $s14 = "{[M%--ZH?&iT"
        $s15 = "System.Resources"
        $s16 = "AutoScaleMode"
        $s17 = "StringBuilder"
        $s18 = "GeneratedCodeAttribute"
        $s19 = "GetResponseStream"
        $s20 = "set_HideSelection"
condition:
    uint16(0) == 0x5a4d and filesize < 237KB and
    4 of them
}
    
rule daccddbddefceecceecacdeadccaec_exe {
strings:
        $s1 = "ttdSecondaryPanel"
        $s2 = "TRttiClassRefType"
        $s3 = "Fisc_dsql_prepare"
        $s4 = "TThemedDatePicker"
        $s5 = "procedure NewPage"
        $s6 = "FAlignControlList"
        $s7 = "EndFunctionInvoke"
        $s8 = "claMediumseagreen"
        $s9 = "Operation aborted"
        $s10 = "GlassHatchCBClick"
        $s11 = "msctls_progress32"
        $s12 = "TRttiManagedField"
        $s13 = "VerticalAlignment"
        $s14 = "RollbackRetaining"
        $s15 = "FCalcFieldsOffset"
        $s16 = "msctls_trackbar32"
        $s17 = "TfrxDesignerUnits"
        $s18 = "FCaptionEmulation"
        $s19 = "blob_desc_charset"
        $s20 = "FCreatingMainForm"
condition:
    uint16(0) == 0x5a4d and filesize < 5397KB and
    4 of them
}
    
rule ecbcccafadcbdefdfccdabebb_exe {
strings:
        $s1 = "System.Data.OleDb"
        $s2 = "Network_Printer.txt"
        $s3 = "RuntimeHelpers"
        $s4 = "STAThreadAttribute"
        $s5 = "DesignerGeneratedAttribute"
        $s6 = "My.Computer"
        $s7 = "IOException"
        $s8 = "MsgBoxStyle"
        $s9 = "_CorExeMain"
        $s10 = "get_Columns"
        $s11 = "ProductName"
        $s12 = "First Name:"
        $s13 = "VarFileInfo"
        $s14 = "lW3hP}4p$xF"
        $s15 = "ThreadStaticAttribute"
        $s16 = "ExecuteNonQuery"
        $s17 = "FileDescription"
        $s18 = "FirstWeekOfYear"
        $s19 = "get_fnameTextBox"
        $s20 = "birthdateTextBox"
condition:
    uint16(0) == 0x5a4d and filesize < 554KB and
    4 of them
}
    
rule fcfbeaeebdaedaabfeebdafffcbb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "msctls_trackbar32"
        $s4 = "4`2UUCVWDVcgVcAc`TVdd"
        $s5 = "6GRcZR_e3RUGRcEjaV6cc`c"
        $s6 = "{~upujci^Ti^Ti^T_VMTMETMETME!"
        $s7 = "xsxngpe\\i^TTMETMETME!"
        $s8 = "le\\_XP^WN]VM^WN_XPle\\"
        $s9 = "yqzmbwk`wk`wk`]TKTMETMETME"
        $s10 = "If-Unmodified-Since"
        $s11 = "Yeead+  UZdT`cUT`^ "
        $s12 = "4`:_ZeZR]ZkV6i"
        $s13 = "TShortCutEvent"
        $s14 = "EDB=EZ^VDeR^a5ReR|"
        $s15 = "TContextPopupEvent"
        $s16 = "4`4cVReV:_deR_TV6i"
        $s17 = "GetWindowDC"
        $s18 = "TStrings, A"
        $s19 = "Medium Gray"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 1392KB and
    4 of them
}
    
rule fcbdfaeaadfdcdbdfdbedeeadbfd_vbs {
strings:
        $s1 = "VJsyKMoK=\"7.42.B3.92.56.57.27.47.42.C2.C6.C6.57.E6.42.82.56.57.C6.16.65.47.56.35.E2.92.72.36.96.47.16.47.72.B2.72.35.C2.36.96.C6.72.B2.92.72.26.57.05.72.C2.72.04.04.04.72.82.56.36.16.C6.07.56.27.E2.72.04.04.04.E6.F6.E4.72.C2.72.46.56.C6.96.72.B2.72.16.64.47.96.E6.72.B2.72.94.96.72.B2.72.37.D6.72.B2.72.16.72.82.46.C6.56.96.64.47.56.74.E2.92.72.37.C6.96.47.55.72.B2.72.96.37.72.B2.72.D6.72.B2.72.14.E2.E6.72.B2.72.F6.96.47.16.72.B2.72.D6.F6.47.57.14.E2.72.B2.72.47.E6.56.72.B2.72.D6.56.76.72.B2.72.16.E6.16.D4.72.B2.72.E2.D6.56.47.37.72.B2.72.97.35.72.82.56.07.97.45.47.56.74.E2.97.C6.26.D6.56.37.37.14.E2.D5.66.56.25.B5.B3.76.66.63.53.47.42.02.D3.02.C6.F6.36.F6.47.F6.27.05.97.47.96.27.57.36.56.35.A3.A3.D5.27.56.76.16.E6.16.D4.47.E6.96.F6.05.56.36.96.67.27.56.35.E2.47.56.E4.E2.D6.56.47.37.97.35.B5.B3.92.23.73.03.33.02.C2.D5.56.07.97.45.C6.F6.36.F6.47.F6.27.05.97.47.96.27.57.36.56.35.E2.47.56.E4.E2.D6.56.47.37.97.35.B5.82.47.36.56.A6.26.F4.F6.45.A3.A3.D5.D6.57.E6.54.B5.02.D3.02.76.66.63.53.47.42.B3.92.76.E6.96.07.42.82.02.C6.96.47.E6.57.02.D7.47.56.96.57.15.D2.02.13.02.47.E6.57.F6.36.D2.02.D6.F6.36.E2.56.C6.76.F6.F6.76.02.07.D6.F6.36.D2.02.E6.F6.96.47.36.56.E6.E6.F6.36.D2.47.37.56.47.02.D3.02.76.E6.96.07.42.B7.02.F6.46'=lzkctqcIzMSoEnfsaEqF$;\""
        $s2 = "for i=999-998 to str1"
        $s3 = "End Function"
        $s4 = "End Sub"
        $s5 = "end if"
condition:
    uint16(0) == 0x5a4d and filesize < 10KB and
    4 of them
}
    
rule bcebffccdadfcebadabfdf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "e4x5yl10inb"
        $s4 = "_CorExeMain"
        $s5 = "AES_Decrypt"
        $s6 = "ernUfFoGWyg"
        $s7 = "VarFileInfo"
        $s8 = "T9w*XihasIq"
        $s9 = "FileDescription"
        $s10 = "Stub.Program"
        $s11 = "System.Resources"
        $s12 = "CallSiteBinder"
        $s13 = "$$method0x6000005-1"
        $s14 = "ResourceManager"
        $s15 = "InitializeArray"
        $s16 = "C<(%X9E/\""
        $s17 = "Y4=Q]<Fr01"
        $s18 = "8DdWt2`&{:"
        $s19 = "[2@B9WA5/D"
        $s20 = "*#Ox;y[*S$c"
condition:
    uint16(0) == 0x5a4d and filesize < 572KB and
    4 of them
}
    
rule bcefdbdceebfdeefdbcadebfbb_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "EOutOfResources\\"
        $s4 = "TInterfacedPersistent"
        $s5 = "TShortCutEvent"
        $s6 = "TIdCoderCollection"
        $s7 = "TContextPopupEvent"
        $s8 = "GetWindowDC"
        $s9 = "p!tu$69:]Z("
        $s10 = "LoadStringA"
        $s11 = "Na^Ap c#J-n"
        $s12 = "TBrushStyle"
        $s13 = "fsStayOnTop"
        $s14 = "z ]QW#&^bi*"
        $s15 = "TMenuMeasureItemEvent"
        $s16 = "TCustomGroupBox"
        $s17 = "GetThreadLocale"
        $s18 = "ooDrawFocusRect"
        $s19 = "TMenuAnimations"
        $s20 = "TCanResizeEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 1769KB and
    4 of them
}
    
rule cbaceedbabffdadbebcfedfdebf_exe {
strings:
        $s1 = "GdipGetImageWidth"
        $s2 = "AUDIO_STREAM_STOP"
        $s3 = "GetKeyboardLayout"
        $s4 = "French - Standard"
        $s5 = "WebMonitor Client"
        $s6 = "cross device link"
        $s7 = "CreateThreadpoolTimer"
        $s8 = "`vector destructor iterator'"
        $s9 = "The service is stopped"
        $s10 = "executable format error"
        $s11 = "GetExtendedUdpTable"
        $s12 = "result out of range"
        $s13 = "send_reg_value_edit"
        $s14 = "KEYLOG_STREAM_START"
        $s15 = "directory not empty"
        $s16 = "VirtualAllocEx"
        $s17 = "RegSetValueExW"
        $s18 = "invalid string position"
        $s19 = "SetConsoleCtrlHandler"
        $s20 = "send_app_interval_set"
condition:
    uint16(0) == 0x5a4d and filesize < 773KB and
    4 of them
}
    
rule efecacbebceaaeedabbcecedeff_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = ":)nJ{f'S#_9"
        $s4 = "rPF nZ\"Ii5"
        $s5 = "_CorExeMain"
        $s6 = "AES_Decrypt"
        $s7 = "lwoui4p0aq5"
        $s8 = "VarFileInfo"
        $s9 = "Vv}Gaqn^OuM"
        $s10 = "FileDescription"
        $s11 = "Stub.Program"
        $s12 = "System.Resources"
        $s13 = "CallSiteBinder"
        $s14 = "$$method0x6000005-1"
        $s15 = "ResourceManager"
        $s16 = "InitializeArray"
        $s17 = "i,/mZ\"ckq"
        $s18 = "/T( \":c*K"
        $s19 = "CmxDFTd~q9"
        $s20 = ",a?qewfo(y"
condition:
    uint16(0) == 0x5a4d and filesize < 552KB and
    4 of them
}
    
rule dfccbbabacfecceed_exe {
strings:
        $s1 = "ES_DISPLAY_REQUIRED"
        $s2 = "RuntimeHelpers"
        $s3 = "MarshalAsAttribute"
        $s4 = "RuntimeFieldHandle"
        $s5 = "STAThreadAttribute"
        $s6 = "VarFileInfo"
        $s7 = "_CorExeMain"
        $s8 = "SocketFlags"
        $s9 = "get_MachineName"
        $s10 = "FileDescription"
        $s11 = "Lime.Packets"
        $s12 = "programMutex"
        $s13 = "ComputerInfo"
        $s14 = "root\\SecurityCenter"
        $s15 = "StringBuilder"
        $s16 = "CompareMethod"
        $s17 = "PacketHandler"
        $s18 = "AddressFamily"
        $s19 = "TimerCallback"
        $s20 = "GetWindowText"
condition:
    uint16(0) == 0x5a4d and filesize < 29KB and
    4 of them
}
    
rule bbcbeedaecaeeaaafaacebc_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "Directory not empty"
        $s3 = "Runtime Error!"
        $s4 = "No child processes"
        $s5 = "GetConsoleOutputCP"
        $s6 = "?Q6dIw5YUPp"
        $s7 = "1Q]cG.o3Wz "
        $s8 = "vC'DTE^X5K:"
        $s9 = "LufGeYq<)2["
        $s10 = "<kR>IYV?zd}"
        $s11 = "ljy'C3;P9p]"
        $s12 = "5du_HN9hIzB"
        $s13 = "IR9wQ;\"^g}"
        $s14 = "(z4B5Haq~,_"
        $s15 = "i<nZu/b=Wwp"
        $s16 = "F=+t>_bu][-"
        $s17 = "T8kD`Ju;dvb"
        $s18 = "Wroen\"jQp."
        $s19 = "3+.lIk~%@q^"
        $s20 = "#4WOCoBn\"H"
condition:
    uint16(0) == 0x5a4d and filesize < 7448KB and
    4 of them
}
    
rule cacfbbcbafaaaeeefecdbeced_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "b6HLj6654'E<c046p"
        $s4 = "1,6%1_1r1z0Y4,eAf"
        $s5 = "4Te>f69AfVaQfQf@b"
        $s6 = "SHRegCreateUSKeyW"
        $s7 = "CreateColorTransformA"
        $s8 = "`vector destructor iterator'"
        $s9 = "Runtime Error!"
        $s10 = "81c204beaff93f=a2f4f3bb"
        $s11 = "SetConsoleCtrlHandler"
        $s12 = "7>8f661>181c004feafc;"
        $s13 = "_2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c004feaff93f9a2f4f3bb681f6616181c00"
        $s14 = "DK1%Y[AWC]b"
        $s15 = "6eAWR]10IC@"
        $s16 = "BSpEHVR1UCA"
        $s17 = "63804b@ja,."
        $s18 = "ZMTfbYxXE]V"
        $s19 = "izTXVLYc|Q@"
        $s20 = "LC_MONETARY"
condition:
    uint16(0) == 0x5a4d and filesize < 344KB and
    4 of them
}
    
rule efedecceaebaabdcfdaacedbf_exe {
strings:
        $s1 = "6U,GK4\"Y/R"
        $s2 = "eTGvs8B`6Kf"
        $s3 = "3&7qmaI|FYp"
        $s4 = "Pv?d5F-|KeS"
        $s5 = "i$|CPGumlYy"
        $s6 = "vG.:Oxpg[)"
        $s7 = "xnOF~QJu]T"
        $s8 = "/`}wvJ%Mz?"
        $s9 = "@SCYIhLG8'"
        $s10 = "GU<LI?SBCCm"
        $s11 = "Administrator"
        $s12 = "5^<'^c\"`K"
        $s13 = "Cyy07G$-%_"
        $s14 = " 765-2068)"
        $s15 = "5c-W .? mO"
        $s16 = "DocOptions"
        $s17 = "A[~F-8j*\\"
        $s18 = "BIN0001.OLE"
        $s19 = "Root Entry"
        $s20 = "\"[#m:s\"W"
condition:
    uint16(0) == 0x5a4d and filesize < 575KB and
    4 of them
}
    
rule cbdcbfbcbaeadffaddcfccafba_exe {
strings:
        $s1 = "last_insert_rowid"
        $s2 = "GetEnvironmentStrings"
        $s3 = "`vector destructor iterator'"
        $s4 = "x-ebcdic-koreanandkoreanextended"
        $s5 = "wrong # of entries in index "
        $s6 = "authorization denied"
        $s7 = " USING COVERING INDEX "
        $s8 = "x-ebcdic-icelandic-euro"
        $s9 = "invalid string position"
        $s10 = "On tree page %d cell %d: "
        $s11 = "database is locked"
        $s12 = "GetConsoleOutputCP"
        $s13 = "6d718e:W;f>"
        $s14 = "_a23cdefghi"
        $s15 = "tbl_name=%Q"
        $s16 = "local time unavailable"
        $s17 = "`local vftable'"
        $s18 = "no query solution"
        $s19 = "cannot commit - no transaction is active"
        $s20 = "TerminateProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 1052KB and
    4 of them
}
    
rule bebccdfecddfadbfafddf_exe {
strings:
        $s1 = "cropRectRightlong"
        $s2 = "GetConsoleOutputCP"
        $s3 = " 2\"/$IVcHZ"
        $s4 = "JfX|TR.I%)$"
        $s5 = "k>GTan%K}Q^"
        $s6 = "Vcp}bIhNAB]"
        $s7 = "X{IVcp}uh[N"
        $s8 = "%\"Z,;FS`EJ"
        $s9 = "\"KyZ]7?-Cw"
        $s10 = "\"byDY1)]jw"
        $s11 = "RP\"-<IV}*8"
        $s12 = "`8P\"/<IVAu"
        $s13 = "D&ILa1R*)%d"
        $s14 = "~aQ$b>KX=,9"
        $s15 = "!\"g/?IVcYJ"
        $s16 = "GetModuleHandleW"
        $s17 = "TerminateProcess"
        $s18 = "printSixteenBitbool"
        $s19 = "WriteProcessMemory"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 690KB and
    4 of them
}
    
rule abafedceddefdddfefcdcceae_exe {
strings:
        $s1 = " 2\"/$IVcHZ"
        $s2 = "k>GTan%K}Q^"
        $s3 = "Vcp}bIhNAB]"
        $s4 = "X{IVcp}uh[N"
        $s5 = "%\"Z,;FS`EJ"
        $s6 = "\"KyZ]7?-Cw"
        $s7 = "\"byDY1)]jw"
        $s8 = "RP\"-<IV}*8"
        $s9 = "`8P\"/<IVAu"
        $s10 = "~aQ$b>KX=,9"
        $s11 = "!\"g/?IVcYJ"
        $s12 = "GetModuleHandleW"
        $s13 = "TerminateProcess"
        $s14 = "WriteProcessMemory"
        $s15 = "GetCurrentThreadId"
        $s16 = "~\"T -:GTan{"
        $s17 = "GetTickCount"
        $s18 = "SetHandleCount"
        $s19 = "    </security>"
        $s20 = "GetSystemTimeAsFileTime"
condition:
    uint16(0) == 0x5a4d and filesize < 557KB and
    4 of them
}
    
rule bdefbfebaafccccee_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "cross device link"
        $s4 = "CreateThreadpoolTimer"
        $s5 = "`vector destructor iterator'"
        $s6 = "x-ebcdic-koreanandkoreanextended"
        $s7 = "executable format error"
        $s8 = "result out of range"
        $s9 = "If-Unmodified-Since"
        $s10 = "directory not empty"
        $s11 = "x-ebcdic-icelandic-euro"
        $s12 = "h([0-9a-fA-F])"
        $s13 = "invalid string position"
        $s14 = "ios_base::failbit set"
        $s15 = "operation canceled"
        $s16 = ".?AVbad_cast@std@@"
        $s17 = "LC_MONETARY"
        $s18 = "Accept-Encoding"
        $s19 = "english-jamaica"
        $s20 = "`local vftable'"
condition:
    uint16(0) == 0x5a4d and filesize < 557KB and
    4 of them
}
    
rule ebdebbabfdfdbddcfdafebbeacbd_exe {
strings:
        $s1 = "'4AO[hu}pcV"
        $s2 = "B\"0= U2')c"
        $s3 = "bCn;- i9|7e"
        $s4 = "lbyLr(\">hu"
        $s5 = "DzANP,%4p}s"
        $s6 = "&uADV\"0[N^"
        $s7 = ",fxHB\"thjw"
        $s8 = "jzDLN\"Tavy"
        $s9 = ".!0_C\"|fkx"
        $s10 = "i{\"LY :cp}"
        $s11 = "zO.\"`a=W6i"
        $s12 = "8s|.>:GDe`l"
        $s13 = "GetModuleHandleW"
        $s14 = "TerminateProcess"
        $s15 = "WriteProcessMemory"
        $s16 = "GetCurrentThreadId"
        $s17 = "(5BN\\iv|obU"
        $s18 = "[HMG8+j&rG<-"
        $s19 = "GetTickCount"
        $s20 = "p,Z\"/<IVcp}"
condition:
    uint16(0) == 0x5a4d and filesize < 1085KB and
    4 of them
}
    
rule aadfbaeddaacdebfef_exe {
strings:
        $s1 = "reldnaHemarFxxC__"
        $s2 = "__CxxFrameHandler"
        $s3 = "xedaerhtnigeb_"
        $s4 = "tablit l'action pr"
        $s5 = "sutatSecivreSyreuQ"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "elbisiVwodniWsI"
        $s10 = "SetThreadPriority"
        $s11 = "Ouvre ce document"
        $s12 = ")Restaure la fen"
        $s13 = "AeldnaHeludoMteG"
        $s14 = "GetModuleHandleA"
        $s15 = "dnammoc\\nepo\\llehs\\s%"
        $s16 = "dIdaerhTtnerruCteG"
        $s17 = "emaNyldneirF"
        $s18 = "EnableWindow"
        $s19 = "emiTlacoLteG"
        $s20 = "tnuoCkciTteG"
condition:
    uint16(0) == 0x5a4d and filesize < 105KB and
    4 of them
}
    
rule bbdaafaeecadebeeaeaaaadfcd_exe {
strings:
        $s1 = "reldnaHemarFxxC__"
        $s2 = "__CxxFrameHandler"
        $s3 = "xedaerhtnigeb_"
        $s4 = "tablit l'action pr"
        $s5 = "sutatSecivreSyreuQ"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "elbisiVwodniWsI"
        $s10 = "SetThreadPriority"
        $s11 = "Ouvre ce document"
        $s12 = ")Restaure la fen"
        $s13 = "AeldnaHeludoMteG"
        $s14 = "GetModuleHandleA"
        $s15 = "dnammoc\\nepo\\llehs\\s%"
        $s16 = "dIdaerhTtnerruCteG"
        $s17 = "emaNyldneirF"
        $s18 = "EnableWindow"
        $s19 = "emiTlacoLteG"
        $s20 = "tnuoCkciTteG"
condition:
    uint16(0) == 0x5a4d and filesize < 105KB and
    4 of them
}
    
rule efaecfeefafbbaabecdaabbad_exe {
strings:
        $s1 = "reldnaHemarFxxC__"
        $s2 = "__CxxFrameHandler"
        $s3 = "xedaerhtnigeb_"
        $s4 = "tablit l'action pr"
        $s5 = "sutatSecivreSyreuQ"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "elbisiVwodniWsI"
        $s10 = "SetThreadPriority"
        $s11 = "Ouvre ce document"
        $s12 = ")Restaure la fen"
        $s13 = "AeldnaHeludoMteG"
        $s14 = "GetModuleHandleA"
        $s15 = "dnammoc\\nepo\\llehs\\s%"
        $s16 = "dIdaerhTtnerruCteG"
        $s17 = "emaNyldneirF"
        $s18 = "EnableWindow"
        $s19 = "emiTlacoLteG"
        $s20 = "tnuoCkciTteG"
condition:
    uint16(0) == 0x5a4d and filesize < 105KB and
    4 of them
}
    
rule cedabbcefbebbbbeadcba_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "GetEnvironmentStrings"
        $s3 = "RegSetValueExA"
        $s4 = "GetConsoleOutputCP"
        $s5 = "mKoSQnHypCM"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = ";*/4{U_dR9-"
        $s9 = "FileDescription"
        $s10 = "SetThreadPriority"
        $s11 = "C:\\PQGvQrHQ.exe"
        $s12 = "C:\\j7ket33L.exe"
        $s13 = "C:\\hyeF__9o.exe"
        $s14 = "C:\\663Jeo0t.exe"
        $s15 = "TerminateProcess"
        $s16 = "C:\\gWcGemcY.exe"
        $s17 = "C:\\1gJewhfJ.exe"
        $s18 = "C:\\yaDTQMxe.exe"
        $s19 = "C:\\YX8ej8w3.exe"
        $s20 = "C:\\fhvHfOIe.exe"
condition:
    uint16(0) == 0x5a4d and filesize < 522KB and
    4 of them
}
    
rule eafbdddfeabefdcfdbaaeefcfddeebcb_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "GetEnvironmentStrings"
        $s3 = "RegSetValueExA"
        $s4 = "GetConsoleOutputCP"
        $s5 = "ProductName"
        $s6 = "mKoSQnHypCM"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "SetThreadPriority"
        $s10 = "TerminateProcess"
        $s11 = "GetComputerNameA"
        $s12 = "GetModuleHandleW"
        $s13 = "0 2O2t2W4S6W6[6_6c6g6k6o6|6"
        $s14 = "EnterCriticalSection"
        $s15 = "GetLocalTime"
        $s16 = "SetEndOfFile"
        $s17 = "UpdateWindow"
        $s18 = "EnableWindow"
        $s19 = "GetTickCount"
        $s20 = "__vbaLenBstr"
condition:
    uint16(0) == 0x5a4d and filesize < 221KB and
    4 of them
}
    
rule dfececddffddaaeaecbf_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "GetEnvironmentStrings"
        $s3 = "RegSetValueExA"
        $s4 = "GetConsoleOutputCP"
        $s5 = "mKoSQnHypCM"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = ";*/4{U_dR9-"
        $s9 = "FileDescription"
        $s10 = "SetThreadPriority"
        $s11 = "C:\\PQGvQrHQ.exe"
        $s12 = "C:\\j7ket33L.exe"
        $s13 = "C:\\hyeF__9o.exe"
        $s14 = "C:\\663Jeo0t.exe"
        $s15 = "TerminateProcess"
        $s16 = "C:\\gWcGemcY.exe"
        $s17 = "C:\\1gJewhfJ.exe"
        $s18 = "C:\\yaDTQMxe.exe"
        $s19 = "C:\\YX8ej8w3.exe"
        $s20 = "C:\\fhvHfOIe.exe"
condition:
    uint16(0) == 0x5a4d and filesize < 522KB and
    4 of them
}
    
rule dfbeeaeefffeecadbbeeedacadbccf_exe {
strings:
        $s1 = "ProductName"
        $s2 = "LoadStringA"
        $s3 = "VarFileInfo"
        $s4 = "3EMDHN12:I4"
        $s5 = "5<^7=3g0.4E"
        $s6 = "FileDescription"
        $s7 = "34AC>KA;>:1?48CAE"
        $s8 = "GetShortPathNameA"
        $s9 = "3>0FC:8;KFFL;8<A"
        $s10 = "RemoveDirectoryA"
        $s11 = ":48IDOI1F=E:5"
        $s12 = ":?79:C=03IB=59"
        $s13 = "GetDeviceCaps"
        $s14 = "r`ozv>oRich{v>o"
        $s15 = "CompareFileTime"
        $s16 = "LegalTrademarks"
        $s17 = "kpfCv[caD#"
        $s18 = "_WFqu-52NI"
        $s19 = ",)6u+t|R8X"
        $s20 = "Copyright "
condition:
    uint16(0) == 0x5a4d and filesize < 169KB and
    4 of them
}
    
rule feaffddeebaebabeffbf_exe {
strings:
        $s1 = "File Download Failed!"
        $s2 = "/minimum/version.zip"
        $s3 = "RegSetValueExA"
        $s4 = "28C4C820-401A-101B-A3C9-08002B2F49FB"
        $s5 = "http://ocsp.comodoca.com0"
        $s6 = "UzpVersion2"
        $s7 = "modRegistry"
        $s8 = "MSComctlLib"
        $s9 = "/others.zip"
        $s10 = "VarFileInfo"
        $s11 = "HModCPUINFO"
        $s12 = "K.D.K. Software"
        $s13 = "DeviceIoControl"
        $s14 = "rightOutsetlong"
        $s15 = "0.0KB (0 bytes)"
        $s16 = "Uses a local area network "
        $s17 = "Down Load Manager"
        $s18 = "Hidden sectors = "
        $s19 = "BytesPerSector = "
        $s20 = "<KDKUpdateUtility"
condition:
    uint16(0) == 0x5a4d and filesize < 559KB and
    4 of them
}
    
rule effdaccfcbabbbcbacbeacd_exe {
strings:
        $s1 = "B|)b`pWUzw"
        $s2 = "nE~4a:pftb"
        $s3 = "ExitProcess"
        $s4 = "KERNEL32.dll"
        $s5 = "o?CSd=[y[W"
        $s6 = "SetErrorMode"
        $s7 = "Z78&75+Co"
        $s8 = "Vi`c66E\\"
        $s9 = "ozhylPZU"
        $s10 = "yJ\"3,wU"
        $s11 = ")/an7< r"
        $s12 = "2mT]*yRM"
        $s13 = "RBlE#o1Q"
        $s14 = ".NoTLVPN"
        $s15 = "r~<\\ @Y"
        $s16 = "Nd:'HM)"
        $s17 = "7%vU^ZY"
        $s18 = "\";P%Ym"
        $s19 = "Qi+<]:8"
        $s20 = "-#lY+Ck"
condition:
    uint16(0) == 0x5a4d and filesize < 70KB and
    4 of them
}
    
rule cdfcccaadfecfccedcafbf_dll {
strings:
        $s1 = "GetTickCount"
        $s2 = "-9IdUb*RVF"
        $s3 = "O6h$Z04Fg+"
        $s4 = "GetTempPathA"
        $s5 = "KERNEL32.dll"
        $s6 = "CreateProcessA"
        $s7 = "0ju1nR}}SE"
        $s8 = "USER32.dll"
        $s9 = "CloseHandle"
        $s10 = "CreateFileA"
        $s11 = "SetErrorMode"
        $s12 = "JS[P=-+\""
        $s13 = "ZS1@E$jM8"
        $s14 = "WS'4k#F.p"
        $s15 = "wsprintfA"
        $s16 = "v:uh~zs.0"
        $s17 = "nAS-\\L6z"
        $s18 = "Q\\#6&\\[R"
        $s19 = "WriteFile"
        $s20 = "cMMb[\\:+"
condition:
    uint16(0) == 0x5a4d and filesize < 125KB and
    4 of them
}
    
rule cefeadeffbafffbcfcececaad_exe {
strings:
        $s1 = "ExitProcess"
        $s2 = "KERNEL32.dll"
        $s3 = "I\\|r)Bd{#"
        $s4 = "SetErrorMode"
        $s5 = "\"h\\i RBU"
        $s6 = ":6RBVF*T|"
        $s7 = "PQ2E_|dv:"
        $s8 = "o\\f!j+^C"
        $s9 = "-@h2Ob=2<"
        $s10 = "1A},}ZI*P"
        $s11 = "qPz-^x:\\"
        $s12 = "5f&\\2.\""
        $s13 = "hk/(OGu`"
        $s14 = "-BM|)7dD"
        $s15 = "Vx[@Xn$T"
        $s16 = "o[jaB0:#"
        $s17 = "@qI]GUev"
        $s18 = "mE9S{1A#"
        $s19 = "QwBifzUD"
        $s20 = "}(@an@2w"
condition:
    uint16(0) == 0x5a4d and filesize < 70KB and
    4 of them
}
    
rule aedcdfedfacacacdebdabfcbda_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "     name=\"wextract\""
        $s3 = "RegSetValueExA"
        $s4 = "ren Arbeitsordner an."
        $s5 = "c+x[<02E4mJ"
        $s6 = "YOlcA(jZgr@"
        $s7 = "ProductName"
        $s8 = "LoadStringA"
        $s9 = ".\"_}<'u{7X"
        $s10 = "1<j%H3()N=["
        $s11 = "VarFileInfo"
        $s12 = "Q}t=]biDKO|"
        $s13 = "FileDescription"
        $s14 = "Command.com /c %s"
        $s15 = "GetShortPathNameA"
        $s16 = "TerminateProcess"
        $s17 = "Befehlsoptionen:"
        $s18 = "RemoveDirectoryA"
        $s19 = "Temporary folder"
        $s20 = "DispatchMessageA"
condition:
    uint16(0) == 0x5a4d and filesize < 832KB and
    4 of them
}
    
rule daacaddbcacebccbbd_exe {
strings:
        $s1 = "Not enought space on "
        $s2 = "FileSystemAccessRule"
        $s3 = "executing error code: "
        $s4 = "RuntimeHelpers"
        $s5 = "GetProcessesByName"
        $s6 = "MozillaWindowClass"
        $s7 = "STAThreadAttribute"
        $s8 = "smethod_168"
        $s9 = "System.Linq"
        $s10 = "op_Equality"
        $s11 = "EnoughSpace"
        $s12 = "_CorExeMain"
        $s13 = "ComputeHash"
        $s14 = "BuildPacket"
        $s15 = "vlCb!FID1BK"
        $s16 = "ProductName"
        $s17 = "SocketFlags"
        $s18 = "IsWindowVisible"
        $s19 = "get_VolumeLabel"
        $s20 = "GetLastInputInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 197KB and
    4 of them
}
    
rule aefbdbbebdeccbdffeecae_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "     name=\"wextract\""
        $s3 = "JAG~$2F&J*F4J F2J1D"
        $s4 = ")88Dod_(r8I[=j"
        $s5 = "F6<k? 18|4J"
        $s6 = "ProductName"
        $s7 = ">3R&ol+.-/!"
        $s8 = "B8v^3za}-SF"
        $s9 = "LoadStringA"
        $s10 = "VarFileInfo"
        $s11 = "9syoY3O%}@g"
        $s12 = "rbV%Xz_e#m!"
        $s13 = "FileDescription"
        $s14 = "exe\\wextract.dbg"
        $s15 = "Command.com /c %s"
        $s16 = "GetShortPathNameA"
        $s17 = "RemoveDirectoryA"
        $s18 = "Temporary folder"
        $s19 = "DispatchMessageA"
        $s20 = "GetModuleHandleA"
condition:
    uint16(0) == 0x5a4d and filesize < 1308KB and
    4 of them
}
    
rule dcdbcccdfcafbfdc_exe {
strings:
        $s1 = "HSHELL_APPCOMMAND"
        $s2 = "Not enought space on "
        $s3 = "WaitForServerMessage"
        $s4 = "get_BytesTransferred"
        $s5 = "ReceiveServerAfkSystem"
        $s6 = "executing error code: "
        $s7 = "ElapsedEventHandler"
        $s8 = "RuntimeHelpers"
        $s9 = "SocketArgsPool"
        $s10 = "SPI_GETSCREENSAVERRUNNING"
        $s11 = "set_ReceiveBufferSize"
        $s12 = "GetProcessesByName"
        $s13 = "MozillaWindowClass"
        $s14 = "STAThreadAttribute"
        $s15 = "FromMinutes"
        $s16 = "System.Linq"
        $s17 = "op_Equality"
        $s18 = "_CorExeMain"
        $s19 = "ComputeHash"
        $s20 = "BuildPacket"
condition:
    uint16(0) == 0x5a4d and filesize < 85KB and
    4 of them
}
    
rule eafbabaceafafcfcedddbdbb_exe {
strings:
        $s1 = "Unfinished method"
        $s2 = "ll never be of any use."
        $s3 = "be a little less naive: don"
        $s4 = "CreateBrightnessFilter"
        $s5 = "t believe it!) that on earth there are no men"
        $s6 = "CreateSwapColorFilter"
        $s7 = "__vbaLateMemCallLd"
        $s8 = "'!d@v ~=Db("
        $s9 = "dnA4%LjHcKw"
        $s10 = "New_Caption"
        $s11 = "r5$+8\"[.uZ"
        $s12 = "ProductName"
        $s13 = "E5 dVh{\"HU"
        $s14 = "C@j-./^Lc=,"
        $s15 = "iQ\"1/l%P$g"
        $s16 = "WindowStyle"
        $s17 = "VarFileInfo"
        $s18 = "Keep quiet. Don"
        $s19 = "SetVolumeLabelA"
        $s20 = "clsFileAnalyzer"
condition:
    uint16(0) == 0x5a4d and filesize < 1243KB and
    4 of them
}
    
rule cdbedcdfdefeddfe_exe {
strings:
        $s1 = "GetKeyboardLayout"
        $s2 = "__vbaVerifyVarObj"
        $s3 = "LoadAcceleratorsW"
        $s4 = "CreateThreadpoolTimer"
        $s5 = "_o__register_onexit_function"
        $s6 = "NtQueryWnfStateData"
        $s7 = "RegSetValueExW"
        $s8 = "originCallerModule"
        $s9 = "|Ct*dBvcN\""
        $s10 = "Hl]J)u?STEq"
        $s11 = "qNgum9J_&GD"
        $s12 = "MSComctlLib"
        $s13 = "LoadStringW"
        $s14 = "J-+!D63^E42"
        $s15 = "Q\"VP&$<lC:"
        $s16 = "ProductName"
        $s17 = "aK63Lqpm:H|"
        $s18 = "L&\"kM%#DR "
        $s19 = "PrintDlgExW"
        $s20 = "FreshWindow"
condition:
    uint16(0) == 0x5a4d and filesize < 1564KB and
    4 of them
}
    
rule bebfccbfbbeddececefc_exe {
strings:
        $s1 = "R~\\IZ__RdZ]W\\Dp_Rp\\]@\\_VdZ]W\\Dp_RAVC\\@V"
        $s2 = "GetKeyboardLayout"
        $s3 = "english-caribbean"
        $s4 = "spanish-guatemala"
        $s5 = "cross device link"
        $s6 = "bad function call"
        $s7 = "CreateThreadpoolTimer"
        $s8 = "`vector destructor iterator'"
        $s9 = "executable format error"
        $s10 = "result out of range"
        $s11 = "directory not empty"
        $s12 = "invalid string position"
        $s13 = "ios_base::failbit set"
        $s14 = "operation canceled"
        $s15 = "LC_MONETARY"
        $s16 = "IsWindowVisible"
        $s17 = "english-jamaica"
        $s18 = "`local vftable'"
        $s19 = "spanish-venezuela"
        $s20 = "TerminateProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 468KB and
    4 of them
}
    
rule bebebfefabedbceadbdffc_exe {
strings:
        $s1 = "g;)]\"}-oH8"
        $s2 = "-A06sD|7H9<"
        $s3 = "`5bF4E|]{p-"
        $s4 = "k6'Cbc$x !]"
        $s5 = "zY$P{vxO5kW"
        $s6 = "Ep/'}K2UQ%o"
        $s7 = "wqhBC:t(<Pu"
        $s8 = "GetModuleHandleA"
        $s9 = "zpP*pijUtn\""
        $s10 = "#:N!ZEcIt**|"
        $s11 = "HttpSendRequestW"
        $s12 = "s8*~C0r*\\e4)"
        $s13 = "CryptUnprotectData"
        $s14 = "9I\"-PE7`h"
        $s15 = "&VhA3$-4+6"
        $s16 = "xLdhsQ\"^*"
        $s17 = "`[GS#-nf;g"
        $s18 = "sIhfDdHz.#"
        $s19 = "p}qP#wvl+Y"
        $s20 = "T]#J{1: |/"
condition:
    uint16(0) == 0x5a4d and filesize < 1448KB and
    4 of them
}
    
rule acdacfdfdcefbbcadadabffafdb_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "<file unknown>"
        $s3 = "GetConsoleOutputCP"
        $s4 = "CopyFileExW"
        $s5 = "VarFileInfo"
        $s6 = "_Locale != NULL"
        $s7 = "`local vftable'"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleW"
        $s10 = "EnterCriticalSection"
        $s11 = "SetCurrentDirectoryW"
        $s12 = "WriteProfileSectionW"
        $s13 = "SetNamedPipeHandleState"
        $s14 = "(((_Src))) != NULL"
        $s15 = "Expression: "
        $s16 = "QueryActCtxW"
        $s17 = "GetTickCount"
        $s18 = "SetThreadContext"
        $s19 = "sizeInBytes > retsize"
        $s20 = "SetConsoleCursorPosition"
condition:
    uint16(0) == 0x5a4d and filesize < 277KB and
    4 of them
}
    
rule beccfafdebedcaaffdedebbacbfce_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "<file unknown>"
        $s3 = "invalid string position"
        $s4 = "kupadirokuxenovova"
        $s5 = "GetConsoleOutputCP"
        $s6 = "CopyFileExW"
        $s7 = ",*G{Y8Oj?k5"
        $s8 = "SetThreadLocale"
        $s9 = "`local vftable'"
        $s10 = "Process32FirstW"
        $s11 = "SetThreadPriority"
        $s12 = "TerminateProcess"
        $s13 = "GetModuleHandleW"
        $s14 = "EnterCriticalSection"
        $s15 = "SetCurrentDirectoryW"
        $s16 = "fipohenelodahopakaxehoya"
        $s17 = "(((_Src))) != NULL"
        $s18 = "Expression: "
        $s19 = "GetTickCount"
        $s20 = "sizeInBytes > retsize"
condition:
    uint16(0) == 0x5a4d and filesize < 251KB and
    4 of them
}
    
rule daffbdcafefbaabedeafadea_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "`vector destructor iterator'"
        $s3 = "vonaxacaboxebatayunusi"
        $s4 = "Wifawuvi fitowaxexe"
        $s5 = "<file unknown>"
        $s6 = "VarFileInfo"
        $s7 = "QueryDosDeviceW"
        $s8 = "`local vftable'"
        $s9 = "TerminateProcess"
        $s10 = "bewopudokomajehu"
        $s11 = "GetModuleHandleW"
        $s12 = "EnterCriticalSection"
        $s13 = "(((_Src))) != NULL"
        $s14 = "6OXh&9!V @ W"
        $s15 = "Expression: "
        $s16 = "GetTickCount"
        $s17 = "FindFirstFileExA"
        $s18 = "SetConsoleCursorPosition"
        $s19 = "GetCursorInfo"
        $s20 = "VerifyVersionInfoA"
condition:
    uint16(0) == 0x5a4d and filesize < 296KB and
    4 of them
}
    
rule cfbecfbfabfcfaadaccebfeca_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "english-caribbean"
        $s3 = "GetEnvironmentStrings"
        $s4 = "invalid string position"
        $s5 = "GetConsoleOutputCP"
        $s6 = "LC_MONETARY"
        $s7 = "VarFileInfo"
        $s8 = "`local vftable'"
        $s9 = "sajbmianozu.iya"
        $s10 = "english-jamaica"
        $s11 = "spanish-venezuela"
        $s12 = "chinese-singapore"
        $s13 = "TerminateProcess"
        $s14 = "RemoveDirectoryW"
        $s15 = "GetModuleHandleW"
        $s16 = "EnterCriticalSection"
        $s17 = "south africa"
        $s18 = "GetTickCount"
        $s19 = "GetDevicePowerState"
        $s20 = "Unknown exception"
condition:
    uint16(0) == 0x5a4d and filesize < 293KB and
    4 of them
}
    
rule bacffcbebbfffcedbefbabbefedbf_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "J@f(\"bGpm4?\\"
        $s5 = "RegSetValueExA"
        $s6 = "-UQWhuwk8dK"
        $s7 = "Kz8R?.=<QYr"
        $s8 = "VdY#Iro)>};"
        $s9 = ".iIFM|?$3+X"
        $s10 = "1@nr8QV(*j,"
        $s11 = "1?LiX-l\"Du"
        $s12 = "_*oXq]3Ivz;"
        $s13 = "MZyoWv%n{b~"
        $s14 = "!t|_B%^v*pX"
        $s15 = "*X]+R8v5640"
        $s16 = "Rq}9{G[84dK"
        $s17 = "qV$0C42ZX&j"
        $s18 = "z(R|j8`#AtT"
        $s19 = "VarFileInfo"
        $s20 = "dm>~*o3&[Nv"
condition:
    uint16(0) == 0x5a4d and filesize < 6537KB and
    4 of them
}
    
rule dedaefedfcfcddbcabceb_exe {
strings:
        $s1 = "03SWIx]!=F;"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = ".)j$>'fw5Pm"
        $s5 = "FileDescription"
        $s6 = "Entrust.net1@0>"
        $s7 = "lRankiqnesHs.exe"
        $s8 = "GetModuleHandleA"
        $s9 = ">z%{:RH44pW5"
        $s10 = "    </trustInfo>"
        $s11 = "        version=\"1.0.0.0\""
        $s12 = "r,E%*iX?\""
        $s13 = "79K%q&O-v="
        $s14 = "hezrH~kQyv"
        $s15 = "+h:*!cWKY>"
        $s16 = "/mJjMT63<g"
        $s17 = "<;o^pFq_*E"
        $s18 = "7-P(6eEz`h"
        $s19 = ".FRKS%Dnd2"
        $s20 = "2cRICWq\"y"
condition:
    uint16(0) == 0x5a4d and filesize < 804KB and
    4 of them
}
    
rule aadabadacadebadacbdeadcabbfafebace_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "H]ajbT\"0y}"
        $s5 = "c,]h\"rP7lF"
        $s6 = "ayRuP2\"be|"
        $s7 = "ProductName"
        $s8 = "nQ=S l&\"-u"
        $s9 = "!\">@NXfMxj"
        $s10 = "Qpo|g\"=O0."
        $s11 = "VarFileInfo"
        $s12 = "*+TPe\"ft$j"
        $s13 = "S4@[9ix1>wV"
        $s14 = "URFXQt8jur "
        $s15 = "fI`=Z0*an';"
        $s16 = "=Q@%+m?.*fE"
        $s17 = "FileDescription"
        $s18 = "DialogBoxParamA"
        $s19 = "GetShortPathNameA"
        $s20 = "RemoveDirectoryA"
condition:
    uint16(0) == 0x5a4d and filesize < 3325KB and
    4 of them
}
    
rule acbfebaeefbffccfbebcdbeaedd_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExA"
        $s5 = "Xos?v=E6\"5"
        $s6 = "ce8rG^dZDn>"
        $s7 = "(2GIF+c}rfL"
        $s8 = "!\"roWp;&{'"
        $s9 = "8Ttp\")BA+e"
        $s10 = "8'7lUi^5Z#."
        $s11 = "u9dHy\"U[Db"
        $s12 = "H}O,VnI?_zh"
        $s13 = "o|%N(1@yie8"
        $s14 = "u<C4KX;f&rV"
        $s15 = "?ihE1FLg(R$"
        $s16 = ".<,'JRqEWD}"
        $s17 = "Pq.C3YBsM+F"
        $s18 = "k:H.ip$>[DY"
        $s19 = "1?LiX-l\"Du"
        $s20 = ".\"6^Lsc+mU"
condition:
    uint16(0) == 0x5a4d and filesize < 7081KB and
    4 of them
}
    
rule edeedfdcfcdfbbecebaceddaf_exe {
strings:
        $s1 = "'%s' is not a valid date"
        $s2 = "ECompressInternalError"
        $s3 = "http://ocsp.comodoca.com0"
        $s4 = "EnglishName"
        $s5 = "I/@]N?mS1E*"
        $s6 = "P+e#jXB(|=y"
        $s7 = "xNJ5kcC*2/)"
        $s8 = "m\"=JIA`~^;"
        $s9 = "S^\"p,q5W9N"
        $s10 = "t_WH'+Pks[r"
        $s11 = "=q>hy0dA849"
        $s12 = "ZkV]s*MUL<A"
        $s13 = "LoadStringA"
        $s14 = "4^'VO@C(Wgk"
        $s15 = "s[Q7&J_<-bR"
        $s16 = ":m=\",]ovl7"
        $s17 = "*q:h\"M(OfH"
        $s18 = "|N&4d,A{>9a"
        $s19 = "y2/#SdGJ-<D"
        $s20 = "fI9k*v(d`]G"
condition:
    uint16(0) == 0x5a4d and filesize < 4915KB and
    4 of them
}
    
rule dcdbbecdecbfcebcadcc_exe {
strings:
        $s1 = "fmSS_Certificates"
        $s2 = "msctls_progress32"
        $s3 = "0IdHTTPHeaderInfo"
        $s4 = "lbVerCodeLifetime"
        $s5 = "SetDefaultDllDirectories"
        $s6 = "Colors.DropTargetBorderColor"
        $s7 = "PipeClient_MainPipeMessage"
        $s8 = "YIdHashMessageDigest"
        $s9 = "More information at:"
        $s10 = "AstRmtControlExport"
        $s11 = "lbCertificatesClick"
        $s12 = "seStartRowExit"
        $s13 = "RegSetValueExA"
        $s14 = "FormatCurrency"
        $s15 = "uAITableViewer"
        $s16 = "TVirtualStringTree"
        $s17 = "JclRegistry"
        $s18 = "sbCopy_hwid"
        $s19 = "nRegistryEx"
        $s20 = "\"kY!v&tb+$"
condition:
    uint16(0) == 0x5a4d and filesize < 5159KB and
    4 of them
}
    
rule deaabbafadedaabadeffaac_exe {
strings:
        $s1 = "'%s' is not a valid date"
        $s2 = "ECompressInternalError"
        $s3 = "rEJo}<k`nDi"
        $s4 = "DX%rzc+O-;#"
        $s5 = "vz'[#|FS$-L"
        $s6 = "P\"/JZ?[xDX"
        $s7 = "EZ'6vC-NMi`"
        $s8 = "O~q(V19hbsJ"
        $s9 = "YuyTDHVbWO2"
        $s10 = "LoadStringA"
        $s11 = "%>yH4jI2c-k"
        $s12 = "a:.mje%2B\""
        $s13 = "jtB|,'^X;kU"
        $s14 = "e{j$Ah?zJT("
        $s15 = "-3}CSe.+IYw"
        $s16 = "@tL#~Jky<7p"
        $s17 = "GRPKgyDlp7@"
        $s18 = "n*v$iLwVkt,"
        $s19 = "8J\"i2/,N=O"
        $s20 = "4(-HmED7S01"
condition:
    uint16(0) == 0x5a4d and filesize < 4530KB and
    4 of them
}
    
rule beecbdafabbbeecabafdeddadfb_exe {
strings:
        $s1 = "set_SevenOrHigher"
        $s2 = "GetKeyboardLayout"
        $s3 = "set_MonikerString"
        $s4 = "Chrome Copyright "
        $s5 = "get_IsTerminating"
        $s6 = "GetWebcamResponse"
        $s7 = "MakeGenericMethod"
        $s8 = "IPInterfaceProperties"
        $s9 = "System.ServiceProcess"
        $s10 = "Key can not be empty."
        $s11 = "Listening for connection ..."
        $s12 = "keyboardStateNative"
        $s13 = "TaskManagerParentAddress"
        $s14 = "get_UnicastAddresses"
        $s15 = "DeletePath I/O error"
        $s16 = "FileSystemAccessRule"
        $s17 = "remove_DataAvailable"
        $s18 = "DictionarySerializer"
        $s19 = "GetDrives No drives"
        $s20 = "ElapsedEventHandler"
condition:
    uint16(0) == 0x5a4d and filesize < 539KB and
    4 of them
}
    
rule cdffaedebbcbfafbadbcfdad_exe {
strings:
        $s1 = "DataRowExtensions"
        $s2 = "Inventory Reports"
        $s3 = "', `ContactNo` ='"
        $s4 = "All fields are required."
        $s5 = "txtDatePublish"
        $s6 = "RuntimeHelpers"
        $s7 = "4.94.34121 (Free) "
        $s8 = "System.Data.Common"
        $s9 = "STAThreadAttribute"
        $s10 = "Publisher :"
        $s11 = "ProductName"
        $s12 = "$%Ee^hv5+1#"
        $s13 = "(Eq\"-)ByIR"
        $s14 = "_CorExeMain"
        $s15 = "VarFileInfo"
        $s16 = "G/5-^k)hYM%"
        $s17 = "q/jU5f&3tXm"
        $s18 = "PictureBox1"
        $s19 = "NumbersOnly"
        $s20 = "igJV:q>zfl="
condition:
    uint16(0) == 0x5a4d and filesize < 1793KB and
    4 of them
}
    
rule bdaecbeafabbdafdbcfcadfabf_vbs {
strings:
        $s1 = "set subs = new FastRunner"
        $s2 = "Ob5opbkR9+HxxbX"
        $s3 = "Class FastRunner"
        $s4 = "getInfo = temp"
        $s5 = "tLrDP0o4P+7t4Ly"
        $s6 = " chr(121) & chr(116) & chr(104"
        $s7 = " file.size  & \"^\" "
        $s8 = " chr(111) & chr(110) & chr(46) & chr(101) & chr(120"
        $s9 = "end function"
        $s10 = " installdir & install"
        $s11 = "ile = installdi"
        $s12 = "or  x = 1 to ubound ("
        $s13 = "ileExists(strsa"
        $s14 = " \" \\\" & chr(34) & "
        $s15 = " split (install"
        $s16 = "sodownload.dele"
        $s17 = " \"Columns=FA 00 00 00 FA 00 01 00 6E 00 02 00 6E 00 03 00 78 00 04 00 78 00 05 00 78 00 06 00 64 00 07 00 FA 00 08 00"
        $s18 = "End Class"
        $s19 = "end if"
condition:
    uint16(0) == 0x5a4d and filesize < 259KB and
    4 of them
}
    
rule dfebaafaaefebfbccaeeceeffb_exe {
strings:
        $s1 = "PB_WindowID"
        $s2 = "GetShortPathNameA"
        $s3 = "DispatchMessageA"
        $s4 = "TerminateProcess"
        $s5 = "GetModuleHandleA"
        $s6 = "EnterCriticalSection"
        $s7 = "GetCurrentThreadId"
        $s8 = "EnableWindow"
        $s9 = "DefFrameProcA"
        $s10 = "PB_DropAccept"
        $s11 = "MDI_ChildClass"
        $s12 = "GetTempFileNameA"
        $s13 = "        version=\"6.0.0.0\""
        $s14 = "</assembly>PPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD"
        $s15 = "CoTaskMemFree"
        $s16 = "TranslateAcceleratorA"
        $s17 = "RegisterClassA"
        $s18 = "SizeofResource"
        $s19 = "GetCurrentProcess"
        $s20 = "SHBrowseForFolder"
condition:
    uint16(0) == 0x5a4d and filesize < 276KB and
    4 of them
}
    
rule ddcdbdeefdddfaccbeafcccadcf_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "RegSetValueExW"
        $s4 = "u@UDS$EF`Ve"
        $s5 = "LoadStringW"
        $s6 = "9F_XO;A)q83"
        $s7 = "DeviceIoControl"
        $s8 = "ProgramFilesDir"
        $s9 = "DialogBoxParamW"
        $s10 = "IsWindowVisible"
        $s11 = "`local vftable'"
        $s12 = "WindowsCodecs.dll"
        $s13 = "ARarHtmlClassName"
        $s14 = "GetShortPathNameW"
        $s15 = "Not enough memory"
        $s16 = "SetThreadPriority"
        $s17 = "TerminateProcess"
        $s18 = "DispatchMessageW"
        $s19 = "SetFilePointerEx"
        $s20 = "RemoveDirectoryW"
condition:
    uint16(0) == 0x5a4d and filesize < 493KB and
    4 of them
}
    
rule dbbefddaddaccacfaeac_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "AuthenticationMode"
        $s4 = "DesignerGeneratedAttribute"
        $s5 = "TiR?9\"ZAMg"
        $s6 = "-OMy\"r8(K^"
        $s7 = "My.Computer"
        $s8 = "0r9IZ3\"U*l"
        $s9 = "bLeftBishop"
        $s10 = "op_Equality"
        $s11 = "MsgBoxStyle"
        $s12 = "_CorExeMain"
        $s13 = "unitToPlace"
        $s14 = "ComputeHash"
        $s15 = "jv_y'PKw.$g"
        $s16 = "ProductName"
        $s17 = "UB!&_s-=G/q"
        $s18 = "VarFileInfo"
        $s19 = "k\"EjONfrJ."
        $s20 = ">)pgoA@nIVY"
condition:
    uint16(0) == 0x5a4d and filesize < 810KB and
    4 of them
}
    
rule bebebefecdfffbadfcadcdcc_exe {
strings:
        $s1 = "_CorExeMain"
        $s2 = "IFormatProvider"
        $s3 = "System.Resources"
        $s4 = "StringBuilder"
        $s5 = "GetResponseStream"
        $s6 = "NewLateBinding"
        $s7 = "set_AccessibleName"
        $s8 = "StringSplitOptions"
        $s9 = "Sxysxtem.Rexfxlxexcxtxixoxn.Axsxsxexmxblxxy"
        $s10 = "IDisposable"
        $s11 = "CultureInfo"
        $s12 = "timeout {0}"
        $s13 = "IEnumerable"
        $s14 = "AppWinStyle"
        $s15 = "RichTextBox"
        $s16 = "set_Capacity"
        $s17 = "GetEnumerator"
        $s18 = "HttpStatusCode"
        $s19 = "ClearProjectError"
        $s20 = "HttpWebRequest"
condition:
    uint16(0) == 0x5a4d and filesize < 184KB and
    4 of them
}
    
rule ecddacbcbffcebfbdaebabcbdda_exe {
strings:
        $s1 = "E82200000068A44E0EEC50E84300000083C408FF742404FFD0FF74240850E83000000083C408C3565531C0648B70308B760C8B761C8B6E088B7E208B3638471875F3803F6B7407803F4B7402EB"
        $s2 = ",wdQSsUQ?QrRM/"
        $s3 = ",|R[C/-LKM)"
        $s4 = "7Z4|Q<H'G62"
        $s5 = "T`Y\"p6Z)&C"
        $s6 = "^<(4d]LS=s'"
        $s7 = "1H5G$)74pw&"
        $s8 = "K%ST/NI G3Y"
        $s9 = "yc Q+[={*_<"
        $s10 = "LOs2#3H:b!7"
        $s11 = "}rS1WO'_4P2"
        $s12 = "R$iS8C?}%EM"
        $s13 = "zI$<dnk'l1r"
        $s14 = "_$(,g3~QULW"
        $s15 = "UB6!50L?\"4"
        $s16 = "m{TRzY:QU#4"
        $s17 = "S$L6.oPGFA&"
        $s18 = "p_s,P<LrEY;"
        $s19 = "G*R)X/I+F(L"
        $s20 = "\"@>|=P6A[a"
condition:
    uint16(0) == 0x5a4d and filesize < 177KB and
    4 of them
}
    
rule edaeceadfeefbbebfcfdaeed_exe {
strings:
        $s1 = "UnitInjectProcess"
        $s2 = "GetKeyboardLayout"
        $s3 = "OThreadUnit"
        $s4 = "[Page Down]"
        $s5 = "GetThreadLocale"
        $s6 = "SetThreadPriority"
        $s7 = "HKEY_CLASSES_ROOT"
        $s8 = "TerminateProcess"
        $s9 = "DispatchMessageA"
        $s10 = "GetModuleHandleA"
        $s11 = "EnterCriticalSection"
        $s12 = "WriteProcessMemory"
        $s13 = "GetCurrentThreadId"
        $s14 = "GetLocalTime"
        $s15 = "SetEndOfFile"
        $s16 = "'P\":'R>6!0%"
        $s17 = "FPUMaskValue"
        $s18 = "TPUtilWindow"
        $s19 = "SetThreadContext"
        $s20 = "VirtualFreeEx"
condition:
    uint16(0) == 0x5a4d and filesize < 519KB and
    4 of them
}
    
rule fbeddcaaacccddfaeddabecae_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "Dosya tablosu dolu."
        $s3 = "ProductName"
        $s4 = "a_*\"4oryAE"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "H::2UEE:UDD9TEE)SCC\"SED"
        $s8 = "tirilemedi.;Taray"
        $s9 = "Bu dosya bulunam"
        $s10 = "Temporary folder"
        $s11 = "Do you want to continue?"
        $s12 = "       <assemblyIdentity"
        $s13 = "Microsoft Corporation"
        $s14 = "\\JJX[IIdZJJQUEE&QBB"
        $s15 = "pINJJ<KP[Efk"
        $s16 = "Windows klas"
        $s17 = "       wextract.manifest"
        $s18 = " veya bozulmu"
        $s19 = "yor.$Bellek ay"
        $s20 = "Win32 Kabin Ay"
condition:
    uint16(0) == 0x5a4d and filesize < 188KB and
    4 of them
}
    
rule cfeefdcaaabcadabfccdcedbbfb_exe {
strings:
        $s1 = "u%;ABCDEFgVV"
        $s2 = "Class_TPUtilW"
        $s3 = "AR7U$u]7!L]CqL"
        $s4 = "VirtualProtect"
        $s5 = "Pht,4R1X\""
        $s6 = "_CRuntime e"
        $s7 = "& Setup\\In"
        $s8 = "ExitProcess"
        $s9 = "PACKAGEINFO"
        $s10 = "SHGetMalloc"
        $s11 = "vQ|ie|eJ~aKf"
        $s12 = "SysFreeString"
        $s13 = "GetProcAddress"
        $s14 = "oleaut32.dll"
        $s15 = "VirtualAlloc"
        $s16 = "user32.dll"
        $s17 = "are\\Micros"
        $s18 = "VirtualFree"
        $s19 = "FtpPutFileW"
        $s20 = "lstrlenWWrite/"
condition:
    uint16(0) == 0x5a4d and filesize < 38KB and
    4 of them
}
    
rule cbafcfcacdaefeffbaeedbfb_exe {
strings:
        $s1 = "S4j:cAe<N6T"
        $s2 = "ProductName"
        $s3 = "sX&|ad$0%m("
        $s4 = "VarFileInfo"
        $s5 = "Dmy\"Rl+%NO"
        $s6 = "\"_`Na(/FS~"
        $s7 = "FileDescription"
        $s8 = "Microsoft Corp."
        $s9 = "snMy&,kBy/a?"
        $s10 = "ion I7farmaG"
        $s11 = "|1Q\"4CdBP`d"
        $s12 = "%,13LMNdddeheehgekgeeeheddddNMH31/%"
        $s13 = "LegalTrademarks"
        $s14 = "fTHJ4OeLVt"
        $s15 = "+QUJ5oz,^m"
        $s16 = "Shb<%+npT,"
        $s17 = "+F:^dz`/W_"
        $s18 = "#|K'YnP7ZV"
        $s19 = "Hkwd87@u.,"
        $s20 = "We 't(@79?"
condition:
    uint16(0) == 0x5a4d and filesize < 943KB and
    4 of them
}
    
rule decfdbcaaecffdabddf_exe {
strings:
        $s1 = "u%;ABCDEFgVV"
        $s2 = "Class_TPUtilW"
        $s3 = "AR7U$u]7!L]CqL"
        $s4 = "VirtualProtect"
        $s5 = "Pht,4R1X\""
        $s6 = "_CRuntime e"
        $s7 = "& Setup\\In"
        $s8 = "ExitProcess"
        $s9 = "PACKAGEINFO"
        $s10 = "SHGetMalloc"
        $s11 = "vQ|ie|eJ~aKf"
        $s12 = "SysFreeString"
        $s13 = "GetProcAddress"
        $s14 = "oleaut32.dll"
        $s15 = "VirtualAlloc"
        $s16 = "user32.dll"
        $s17 = "are\\Micros"
        $s18 = "VirtualFree"
        $s19 = "FtpPutFileW"
        $s20 = "lstrlenWWritev"
condition:
    uint16(0) == 0x5a4d and filesize < 38KB and
    4 of them
}
    
rule eeeabbaafeacdaeacecefddfbcef_dll {
strings:
        $s1 = "cabac decode of qscale diff failed at %d %d"
        $s2 = "Unknown function in '%s'"
        $s3 = "707172737475767778797:7;7<7=7>7?7@7A7B7C7D7E7F7G7H7I7J7K7L7M7N7O74;5;6;7;"
        $s4 = "Error! Got no format or no keyframe!"
        $s5 = "limiting QP %f -> %f"
        $s6 = "out of room to push characters"
        $s7 = "read_quant_table error"
        $s8 = "Bad value for reserved field"
        $s9 = "Missing reference picture"
        $s10 = "my guess is %d bits ;)"
        $s11 = "_Jv_RegisterClasses"
        $s12 = "missing picture in access unit"
        $s13 = "x264 - core %d"
        $s14 = "Missing GSM magic!"
        $s15 = "2Pass file invalid"
        $s16 = "NAL %d at %d/%d length %d"
        $s17 = "#%),.247:<?"
        $s18 = "&-5=>6.'/7?"
        $s19 = "=;853/-*&$ "
        $s20 = "B$%&'()KLMn"
condition:
    uint16(0) == 0x5a4d and filesize < 3537KB and
    4 of them
}
    
rule ccebacdbfafdcccbfbdcbefd_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "%-24s %-15s 0x%x(%d) "
        $s3 = "0n^_TIXE1>0nX_XEETC\\1"
        $s4 = "dps}tntirtaex~"
        $s5 = "RegSetValueExA"
        $s6 = "3~AT_eYCTPU11P2eYCTPU"
        $s7 = "\\XB\\PERY1D_Z_^F_"
        $s8 = "1w^C\\PE|TBBPVTp11"
        $s9 = "3FBACX_EWp1"
        $s10 = "ProductName"
        $s11 = "VarFileInfo"
        $s12 = "FileDescription"
        $s13 = "GetFileSecurityA"
        $s14 = "3cTBD\\TeYCTPU11"
        $s15 = "GetModuleHandleA"
        $s16 = "<;11ctvn|d}exnbk1111"
        $s17 = "pgEHATnX_W^qq111111111AK0!11117M0!"
        $s18 = "CreateService(Parameters)"
        $s19 = "Microsoft Corporation"
        $s20 = "REG_MULTI_SZ"
condition:
    uint16(0) == 0x5a4d and filesize < 189KB and
    4 of them
}
    
rule bbfaedbbdffedbdebfbdaefc_exe {
strings:
        $s1 = "GetEnvironmentStrings"
        $s2 = "ProductName"
        $s3 = "SUVWj@Ph|$B"
        $s4 = "VarFileInfo"
        $s5 = "FileDescription"
        $s6 = "TerminateProcess"
        $s7 = "GetModuleHandleA"
        $s8 = "IsBadCodePtr"
        $s9 = "PrivateBuild"
        $s10 = "__MSVCRT_HEAP_SELECT"
        $s11 = ";8967452330011"
        $s12 = "SetHandleCount"
        $s13 = "GetProcessHeap"
        $s14 = "VirtualProtect"
        $s15 = "LegalTrademarks"
        $s16 = "GetCurrentProcess"
        $s17 = "ExitProcess"
        $s18 = "HeapDestroy"
        $s19 = "SpecialBuild"
        $s20 = "KERNEL32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 153KB and
    4 of them
}
    
rule beafaabfbddbfddcdfdabda_exe {
strings:
        $s1 = "}Q\"ABV0@Ym"
        $s2 = ",W4C7P8T:O>"
        $s3 = "1<&B-_0F\"@"
        $s4 = "De821VirtuN"
        $s5 = "&yh8lQ4Hx<0"
        $s6 = "V DNASRLUk\\"
        $s7 = "l7l8i9c:aY%}"
        $s8 = "OLEAUT32.dll"
        $s9 = "AuthenticAMD?"
        $s10 = "2345NNN*6789NNNN:;<="
        $s11 = "VirtualProtect"
        $s12 = "lrKMoBNc{R"
        $s13 = "XR(Di1!+WP"
        $s14 = "*{]|N&}e~q"
        $s15 = " 0*a+,d&-o"
        $s16 = "s#v6f,h5Pb"
        $s17 = "4.`!|9@r\""
        $s18 = "rom th&GNU"
        $s19 = "LVhp%PW\"M"
        $s20 = "Oe<47USt!J"
condition:
    uint16(0) == 0x5a4d and filesize < 1094KB and
    4 of them
}
    
rule dffcbbceeeabacafdaecec_dll {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "bad function call"
        $s4 = "`vector destructor iterator'"
        $s5 = "Runtime Error!"
        $s6 = "SetConsoleCtrlHandler"
        $s7 = "GetConsoleOutputCP"
        $s8 = "LC_MONETARY"
        $s9 = "LoadStringA"
        $s10 = "english-jamaica"
        $s11 = "`local vftable'"
        $s12 = "spanish-venezuela"
        $s13 = "TerminateProcess"
        $s14 = "SetFilePointerEx"
        $s15 = "DispatchMessageA"
        $s16 = "SetThreadStackGuarantee"
        $s17 = "EnterCriticalSection"
        $s18 = "PathToRegion"
        $s19 = "&Meta Region"
        $s20 = "UpdateWindow"
condition:
    uint16(0) == 0x5a4d and filesize < 431KB and
    4 of them
}
    
rule eaebacccedfbabbdccfdbaff_exe {
strings:
        $s1 = "cross device link"
        $s2 = "english-caribbean"
        $s3 = "CreateThreadpoolTimer"
        $s4 = "7 7$7(7,7074787<7@7D7H7L7P7\\=d=l=t=|="
        $s5 = "executable format error"
        $s6 = "result out of range"
        $s7 = "directory not empty"
        $s8 = "invalid string position"
        $s9 = "ios_base::failbit set"
        $s10 = "invalid distance code"
        $s11 = "operation canceled"
        $s12 = "LC_MONETARY"
        $s13 = "HowZ)WI3/2j"
        $s14 = "k$w#Q~Pfzy:"
        $s15 = ";K(7d:tqxQ_"
        $s16 = "`local vftable'"
        $s17 = "english-jamaica"
        $s18 = "spanish-venezuela"
        $s19 = "GetModuleHandleW"
        $s20 = "RemoveDirectoryA"
condition:
    uint16(0) == 0x5a4d and filesize < 3038KB and
    4 of them
}
    
rule eefecacfcdbbaeddbbebfebdb_exe {
strings:
        $s1 = "ProductName"
        $s2 = "xUAE@XZ?e7s"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "zlhmr];mcpX)"
        $s6 = "OLEAUT32.dll"
        $s7 = "PrivateBuild"
        $s8 = "FFormazBaguMZ"
        $s9 = "InstallShield"
        $s10 = "VirtualProtect"
        $s11 = "T * FROM cc'VO5"
        $s12 = "LegalTrademarks"
        $s13 = "ExitProcess"
        $s14 = "baiduConnec"
        $s15 = "SpecialBuild"
        $s16 = "GetProcAddress"
        $s17 = "OriginalFilename"
        $s18 = "y(,0222248<@2222DHLP"
        $s19 = "MSVCRT.dll"
        $s20 = "GetModuleH"
condition:
    uint16(0) == 0x5a4d and filesize < 73KB and
    4 of them
}
    
rule ebcbdcfebfdecebffeabcfc_dll {
strings:
        $s1 = "XmlSchemaParticle"
        $s2 = "set_MainMenuStrip"
        $s3 = "GetSchemaSerializable"
        $s4 = "set_membersTableAdapter"
        $s5 = "ToolboxItemAttribute"
        $s6 = "TableAdapterManager"
        $s7 = "e579x5OzA5O5WZOpye1"
        $s8 = "FlagsAttribute"
        $s9 = "$this.GridSize"
        $s10 = "set_FixedValue"
        $s11 = "RuntimeHelpers"
        $s12 = "GetTypedDataSetSchema"
        $s13 = "System.Data.Common"
        $s14 = "STAThreadAttribute"
        $s15 = "V+zv5Dx,ou&"
        $s16 = "op_Equality"
        $s17 = "ComputeHash"
        $s18 = "get_Columns"
        $s19 = "ProductName"
        $s20 = "VarFileInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 690KB and
    4 of them
}
    
rule dcfffbdceffbdfbdbeeeadfbdedbe_exe {
strings:
        $s1 = "get_algeria_32972"
        $s2 = "Music.Expressions"
        $s3 = "ParserBridgeStatus"
        $s4 = "STAThreadAttribute"
        $s5 = "_CorExeMain"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "ResolveEventArgs"
        $s10 = "m_c4b4329b0a8042c6a0232c16292c3492"
        $s11 = "Geqrtxo.Properties"
        $s12 = "Synchronized"
        $s13 = "set_TabIndex"
        $s14 = "brazil_32937"
        $s15 = "bhutan_32931"
        $s16 = "CloneProduct"
        $s17 = "bouvet_33156"
        $s18 = "angola_32914"
        $s19 = "System.Resources"
        $s20 = "    </metadata></svg>"
condition:
    uint16(0) == 0x5a4d and filesize < 1194KB and
    4 of them
}
    
rule bafcadbeccedff_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "System.Linq"
        $s3 = "_CorExeMain"
        $s4 = "ComputeHash"
        $s5 = "+6hv.-z7`sO"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "PixelOffsetMode"
        $s10 = "ImageAttributes"
        $s11 = "CompositingMode"
        $s12 = "ResolveEventArgs"
        $s13 = "DebuggerHiddenAttribute"
        $s14 = "Eqsqvvmso.d.resources"
        $s15 = "Synchronized"
        $s16 = "GraphicsUnit"
        $s17 = "get_CurrentThread"
        $s18 = "System.Resources"
        $s19 = "AutoScaleMode"
        $s20 = "get_ManagedThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 598KB and
    4 of them
}
    
rule bbddeaeedccafcedaacdeafcfd_exe {
strings:
        $s1 = "get_algeria_32972"
        $s2 = "m_42dec28da3dc4080aecae30d922c1322"
        $s3 = "m_421110128c054a20980cd1992c994af5"
        $s4 = "STAThreadAttribute"
        $s5 = "_CorExeMain"
        $s6 = "ProductName"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "ValidateFactory"
        $s10 = "ResolveEventArgs"
        $s11 = "Synchronized"
        $s12 = "set_TabIndex"
        $s13 = "brazil_32937"
        $s14 = "bhutan_32931"
        $s15 = "bouvet_33156"
        $s16 = "angola_32914"
        $s17 = "System.Resources"
        $s18 = "    </metadata></svg>"
        $s19 = "AutoScaleMode"
        $s20 = "PerformLayout"
condition:
    uint16(0) == 0x5a4d and filesize < 1219KB and
    4 of them
}
    