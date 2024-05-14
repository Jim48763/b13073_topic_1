import pe
rule dcddbefbfedcbdeaccadfdeecf_exe {
strings:
        $s1 = "(ch != _T('\\0'))"
        $s2 = "`vector destructor iterator'"
        $s3 = "CreateIoCompletionPort"
        $s4 = "divapebinumumibelabigiweyiwi"
        $s5 = "Directory not empty"
        $s6 = "punutobobibulidiburazayuzicu"
        $s7 = "<file unknown>"
        $s8 = "Runtime Error!"
        $s9 = "No child processes"
        $s10 = "CopyFileExW"
        $s11 = "VarFileInfo"
        $s12 = "`local vftable'"
        $s13 = "SetThreadLocale"
        $s14 = "ranuzokakepayig"
        $s15 = "GetThreadPriority"
        $s16 = "GetModuleHandleW"
        $s17 = "Operation not permitted"
        $s18 = "GetCurrentDirectoryW"
        $s19 = "WriteProfileStringW"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 247KB and
    4 of them
}
    
rule adceaddecfebcdfbfeffaaffebbaf_exe {
strings:
        $s1 = "AutoPropertyValue"
        $s2 = "RegisteredChannel"
        $s3 = " Current process name "
        $s4 = "RuntimeHelpers"
        $s5 = "My.WebServices"
        $s6 = "get_ModuleName"
        $s7 = "RegexCon.Types"
        $s8 = "STAThreadAttribute"
        $s9 = "ProductName"
        $s10 = "_CorExeMain"
        $s11 = "VarFileInfo"
        $s12 = "AlgorithmID"
        $s13 = "DefaultMemberAttribute"
        $s14 = "ThreadStaticAttribute"
        $s15 = "TOKEN_PRIVILEGE"
        $s16 = "FileDescription"
        $s17 = "GetExportedTypes"
        $s18 = "DebuggerHiddenAttribute"
        $s19 = " Email contact information "
        $s20 = "RegexOptions"
condition:
    uint16(0) == 0x5a4d and filesize < 130KB and
    4 of them
}
    
rule aaadddedbcfceecebfcfbbabfe_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "Directory not empty"
        $s3 = "SetConsoleCtrlHandler"
        $s4 = "No child processes"
        $s5 = "$=|LG)Mm;Tr"
        $s6 = "nRG Sf,`$58"
        $s7 = "HZi7;CG6Fl="
        $s8 = "()J8@G^t<j#"
        $s9 = "AV&,[MmpDag"
        $s10 = "A(3;RE1vP,'"
        $s11 = "F1;?)S~b&DL"
        $s12 = "Vq]JWYr*kh#"
        $s13 = "a5vCP|&hRB4"
        $s14 = "pIaV&w4K\"|"
        $s15 = "=-}c?RiEzul"
        $s16 = "q\"D|: b8$1"
        $s17 = "i^G<sRKz<GnG>']"
        $s18 = "`local vftable'"
        $s19 = "SetFilePointerEx"
        $s20 = "TerminateProcess"
condition:
    uint16(0) == 0x5a4d and filesize < 5157KB and
    4 of them
}
    
rule cfcefddeaaddaddaaaabbfcba_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "bsqyqEqUquqMqmq]q}1[\"+"
        $s3 = "Directory not empty"
        $s4 = "unittest._log)"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "No child processes"
        $s7 = "h')5:L_XM?;"
        $s8 = "A=m%of]\">C"
        $s9 = "E9R>Gx\"Qe^"
        $s10 = "2ao?(xvDt7g"
        $s11 = "V]0qCxSTbur"
        $s12 = "W67VSvyh^~1"
        $s13 = "nF[3'X2oLud"
        $s14 = " )LN%EIqr:9"
        $s15 = "z>V{,`\"^P8"
        $s16 = "XmDI!G3w2>4"
        $s17 = "`'v1(KpOC6["
        $s18 = "MEZ679_)-tH"
        $s19 = "s6qJ9[8FN\""
        $s20 = "6J!R=Xk,5$N"
condition:
    uint16(0) == 0x5a4d and filesize < 6707KB and
    4 of them
}
    
rule cdfdeaeafbecbcdacaabeee_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "Directory not empty"
        $s3 = "unittest._log)"
        $s4 = "requests.__version__)"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "No child processes"
        $s7 = "4d\"?%(O5jP"
        $s8 = "d}!(xKBvE&3"
        $s9 = "MCfFx'LKXi5"
        $s10 = "UA8o!Gr&0LW"
        $s11 = "2ao?(xvDt7g"
        $s12 = "f>D]dPJo.N!"
        $s13 = "V]0qCxSTbur"
        $s14 = "Az&}ICXtq:r"
        $s15 = "{IBj-?Z'crk"
        $s16 = "lvf%PJwd;r("
        $s17 = "MEZ679_)-tH"
        $s18 = "*VO;^E<}Zfq"
        $s19 = "AyvYU_1&E[u"
        $s20 = "Hf8\"x=-rp<"
condition:
    uint16(0) == 0x5a4d and filesize < 7206KB and
    4 of them
}
    
rule ebafebcefecbaafcdfc_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "Directory not empty"
        $s3 = "unittest._log)"
        $s4 = "requests.__version__)"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "No child processes"
        $s7 = "4d\"?%(O5jP"
        $s8 = "d}!(xKBvE&3"
        $s9 = "&4dCu/YoJM0"
        $s10 = "MCfFx'LKXi5"
        $s11 = "UA8o!Gr&0LW"
        $s12 = "2ao?(xvDt7g"
        $s13 = "f>D]dPJo.N!"
        $s14 = "V]0qCxSTbur"
        $s15 = "{IBj-?Z'crk"
        $s16 = "lvf%PJwd;r("
        $s17 = "K0VnB6F`G Z"
        $s18 = "MEZ679_)-tH"
        $s19 = "*VO;^E<}Zfq"
        $s20 = "AyvYU_1&E[u"
condition:
    uint16(0) == 0x5a4d and filesize < 8033KB and
    4 of them
}
    
rule aedbdbceabbdccbedfcfacd_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "bsqyqEqUquqMqmq]q}1[\"+"
        $s3 = "Directory not empty"
        $s4 = "unittest._log)"
        $s5 = "SetConsoleCtrlHandler"
        $s6 = "No child processes"
        $s7 = "h')5:L_XM?;"
        $s8 = "A=m%of]\">C"
        $s9 = "Az6}ICXtq:r"
        $s10 = "E9R>Gx\"Qe^"
        $s11 = "2ao?(xvDt7g"
        $s12 = "V]0qCxSTbur"
        $s13 = "W67VSvyh^~1"
        $s14 = "nF[3'X2oLud"
        $s15 = " )LN%EIqr:9"
        $s16 = "z>V{,`\"^P8"
        $s17 = "`'v1(KpOC6["
        $s18 = "MEZ679_)-tH"
        $s19 = "s6qJ9[8FN\""
        $s20 = "6J!R=Xk,5$N"
condition:
    uint16(0) == 0x5a4d and filesize < 6777KB and
    4 of them
}
    
rule caccbbbbbcefbdacddebedcaadf_exe {
strings:
        $s1 = "Py_SetProgramName"
        $s2 = "Directory not empty"
        $s3 = "unittest._log)"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "No child processes"
        $s6 = "4d\"?%(O5jP"
        $s7 = "MCfFx'LKXi5"
        $s8 = "2ao?(xvDt7g"
        $s9 = "f>D]dPJo.N!"
        $s10 = "V]0qCxSTbur"
        $s11 = "W67VSvyh^~1"
        $s12 = "{IBj-?Z'crk"
        $s13 = "lvf%PJwd;r("
        $s14 = "MEZ679_)-tH"
        $s15 = "*VO;^E<}Zfq"
        $s16 = "AyvYU_1&E[u"
        $s17 = "Hf8\"x=-rp<"
        $s18 = "F#bgn?MwN|%"
        $s19 = "hMdsl(Rp~&t"
        $s20 = "eM>4,2O}(#n"
condition:
    uint16(0) == 0x5a4d and filesize < 7098KB and
    4 of them
}
    
rule beacdfbfbcbcaccefcbcbeeaba_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetDefaultDllDirectories"
        $s3 = "More information at:"
        $s4 = "RegSetValueExA"
        $s5 = "DialogBoxParamA"
        $s6 = "GetShortPathNameA"
        $s7 = "DispatchMessageA"
        $s8 = "GetModuleHandleA"
        $s9 = "SHBrowseForFolderA"
        $s10 = "EnableWindow"
        $s11 = "GetTickCount"
        $s12 = "IIDFromString"
        $s13 = "RegEnumValueA"
        $s14 = "SysListView32"
        $s15 = "InvalidateRect"
        $s16 = "SHAutoComplete"
        $s17 = "CloseClipboard"
        $s18 = "LoadLibraryExA"
        $s19 = "RegCreateKeyExA"
        $s20 = "CoTaskMemFree"
condition:
    uint16(0) == 0x5a4d and filesize < 456KB and
    4 of them
}
    
rule fcbabdfbbaebcedd_exe {
strings:
        $s1 = "DeserializeObject"
        $s2 = "EnsureFloatFormat"
        $s3 = "additionalProperties"
        $s4 = "WriteConstructorDate"
        $s5 = "validationEventHandler"
        $s6 = "JsonConverterAttribute"
        $s7 = "XmlNamespaceManager"
        $s8 = "set_DefaultSettings"
        $s9 = "FallbackDeleteIndex"
        $s10 = "FulfillFromLeftover"
        $s11 = "InternalFlagsFormat"
        $s12 = "BinderTypeName"
        $s13 = "<GetId>b__26_1"
        $s14 = "RuntimeHelpers"
        $s15 = "StringComparer"
        $s16 = "EnsureDateTime"
        $s17 = "ValidateNotDisallowed"
        $s18 = "CanReadMemberValue"
        $s19 = "_genericDictionary"
        $s20 = "System.Xml.XmlNode"
condition:
    uint16(0) == 0x5a4d and filesize < 770KB and
    4 of them
}
    
rule dbffebdccfdeabbfdedbddd_exe {
strings:
        $s1 = ".ClassLibrary1.dll"
        $s2 = "STAThreadAttribute"
        $s3 = "ProductName"
        $s4 = "op_Equality"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "ResolveEventArgs"
        $s8 = "Synchronized"
        $s9 = "DigiCert1%0#"
        $s10 = "d..igHkqx!OQ"
        $s11 = "E%RP/:^E9XK~"
        $s12 = "GeneratedCodeAttribute"
        $s13 = "GetTotalMemory"
        $s14 = "Fzhygpyikjnfzf"
        $s15 = "CallSiteBinder"
        $s16 = "GzipDecompress"
        $s17 = "San Francisco1"
        $s18 = "defaultInstance"
        $s19 = "DebuggingModes"
        $s20 = "LegalTrademarks"
condition:
    uint16(0) == 0x5a4d and filesize < 223KB and
    4 of them
}
    
rule ffaafcbeedfedcedfbfedbeafabff_exe {
strings:
        $s1 = "SpecificationSetterException"
        $s2 = "ThreadErrorDescriptor"
        $s3 = "STAThreadAttribute"
        $s4 = "indexOf_col"
        $s5 = "ProductName"
        $s6 = "_CorExeMain"
        $s7 = "FlushBridge"
        $s8 = "]|$ul\"wGQ<"
        $s9 = "VarFileInfo"
        $s10 = "FileDescription"
        $s11 = "ResolveEventArgs"
        $s12 = "DebuggerHiddenAttribute"
        $s13 = "PoolInstanceMessage"
        $s14 = "Dictionary`2"
        $s15 = "Synchronized"
        $s16 = "DigiCert1%0#"
        $s17 = "CancelBridge"
        $s18 = "d..igHkqx!OQ"
        $s19 = "indexOfsetup"
        $s20 = "EnableBridge"
condition:
    uint16(0) == 0x5a4d and filesize < 231KB and
    4 of them
}
    
rule ebbeafedabfbcaceeded_exe {
strings:
        $s1 = "cross device link"
        $s2 = "`vector destructor iterator'"
        $s3 = "CreateIoCompletionPort"
        $s4 = "executable format error"
        $s5 = "directory not empty"
        $s6 = "4=.8**.6+={y*<+0850"
        $s7 = "result out of range"
        $s8 = "invalid string position"
        $s9 = "On tree page %d cell %d: "
        $s10 = "operation canceled"
        $s11 = "GetConsoleOutputCP"
        $s12 = "`local vftable'"
        $s13 = "SetFilePointerEx"
        $s14 = "%z WITH INDEX %s"
        $s15 = "GetModuleHandleW"
        $s16 = "GetCurrentDirectoryW"
        $s17 = "destination address required"
        $s18 = "CreateCompatibleDC"
        $s19 = "connection refused"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 551KB and
    4 of them
}
    
rule abfddcdcefffabafeb_exe {
strings:
        $s1 = "N%})/Mr TKt"
        $s2 = "D[-g&bt=nv "
        $s3 = "C\"NvrVgMw{"
        $s4 = ",.;(Lk_V}PA"
        $s5 = "l,4=zK5NQ{F"
        $s6 = "u^4{P/-FH!U"
        $s7 = "_\"K2Z(Ac#-"
        $s8 = "PYw}\"SCj0r"
        $s9 = "eZn Tt=8R_."
        $s10 = "|RZ4z-~!*pv"
        $s11 = "vC&\"3dX-U4"
        $s12 = "QwXe1+7{haE"
        $s13 = "^T-w:eCF`IG"
        $s14 = "5e)sZ7?b:M6"
        $s15 = "q~tFC)YI_14"
        $s16 = "f9W4+K@\"eb"
        $s17 = "^XuDEU&g|j_"
        $s18 = "&h;IJ|z:Dn'"
        $s19 = "Mgrm;Zy?_Gc"
        $s20 = "GetModuleHandleA"
condition:
    uint16(0) == 0x5a4d and filesize < 5859KB and
    4 of them
}
    
rule dacbaafcceebebededcc_exe {
strings:
        $s1 = "SetConsoleCtrlHandler"
        $s2 = "RemoveDirectoryW"
        $s3 = "UnregisterClassW"
        $s4 = "DispatchMessageW"
        $s5 = "TerminateProcess"
        $s6 = "Integer overflow"
        $s7 = "GetModuleHandleW"
        $s8 = "GetCurrentDirectoryW"
        $s9 = "TranslateAcceleratorW"
        $s10 = "incorrect length check"
        $s11 = "Misaligned data access"
        $s12 = "SHBrowseForFolderW"
        $s13 = "EnableWindow"
        $s14 = "Division by zero "
        $s15 = "invalid window size"
        $s16 = "RtlGetVersion"
        $s17 = "InitCommonControlsEx"
        $s18 = "SetWindowLongW"
        $s19 = "need dictionary"
        $s20 = "invalid distances set"
condition:
    uint16(0) == 0x5a4d and filesize < 97KB and
    4 of them
}
    
rule fcebefcaedebfefadfdddefddcfe_exe {
strings:
        $s1 = "SAMP\\servers.fav"
        $s2 = "cross device link"
        $s3 = "english-caribbean"
        $s4 = "CreateThreadpoolTimer"
        $s5 = "`vector destructor iterator'"
        $s6 = "30:8:@:T:8;@;D;H;L;P;T;X;\\;`;d;h;l;p;t;x;"
        $s7 = "CreateIoCompletionPort"
        $s8 = "Software\\Valve\\Steam"
        $s9 = "executable format error"
        $s10 = "directory not empty"
        $s11 = "result out of range"
        $s12 = "invalid string position"
        $s13 = "\\Exodus\\exodus.wallet\\"
        $s14 = "On tree page %d cell %d: "
        $s15 = "operation canceled"
        $s16 = "LC_MONETARY"
        $s17 = "english-jamaica"
        $s18 = "`local vftable'"
        $s19 = "| System ver: ?"
        $s20 = "spanish-venezuela"
condition:
    uint16(0) == 0x5a4d and filesize < 908KB and
    4 of them
}
    
rule bdeddeefceedbfeeefbbeddcaee_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "RuntimeHelpers"
        $s3 = "System.Data.Common"
        $s4 = "RuntimeFieldHandle"
        $s5 = "Select User First."
        $s6 = "STAThreadAttribute"
        $s7 = "get_Columns"
        $s8 = "_CorExeMain"
        $s9 = "ExecuteNonQuery"
        $s10 = "DataRowCollection"
        $s11 = "get_DarkSlateGray"
        $s12 = "ConfigurationManager"
        $s13 = "DEPARTMENT STORE MANAGEMENT SYSTEM"
        $s14 = "InitializeComponent"
        $s15 = "get_Discount"
        $s16 = "Synchronized"
        $s17 = "AddWithValue"
        $s18 = "InventoryDAL"
        $s19 = "DialogResult"
        $s20 = "set_ReadOnly"
condition:
    uint16(0) == 0x5a4d and filesize < 226KB and
    4 of them
}
    
rule eadefccbdcdaabbfcfbeabbae_exe {
strings:
        $s1 = "cross device link"
        $s2 = "`vector destructor iterator'"
        $s3 = "CreateIoCompletionPort"
        $s4 = "executable format error"
        $s5 = "directory not empty"
        $s6 = "4=.8**.6+={y*<+0850"
        $s7 = "result out of range"
        $s8 = "invalid string position"
        $s9 = "On tree page %d cell %d: "
        $s10 = "operation canceled"
        $s11 = "GetConsoleOutputCP"
        $s12 = "`local vftable'"
        $s13 = "SetFilePointerEx"
        $s14 = "%z WITH INDEX %s"
        $s15 = "GetModuleHandleW"
        $s16 = "GetCurrentDirectoryW"
        $s17 = "destination address required"
        $s18 = "CreateCompatibleDC"
        $s19 = "connection refused"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 551KB and
    4 of them
}
    
rule cbeebaceaeabecadebba_exe {
strings:
        $s1 = "cross device link"
        $s2 = "`vector destructor iterator'"
        $s3 = "CreateIoCompletionPort"
        $s4 = "executable format error"
        $s5 = "directory not empty"
        $s6 = "4=.8**.6+={y*<+0850"
        $s7 = "result out of range"
        $s8 = "invalid string position"
        $s9 = "On tree page %d cell %d: "
        $s10 = "operation canceled"
        $s11 = "GetConsoleOutputCP"
        $s12 = "`local vftable'"
        $s13 = "SetFilePointerEx"
        $s14 = "%z WITH INDEX %s"
        $s15 = "GetModuleHandleW"
        $s16 = "GetCurrentDirectoryW"
        $s17 = "destination address required"
        $s18 = "CreateCompatibleDC"
        $s19 = "connection refused"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 752KB and
    4 of them
}
    
rule bffaacadacfcabcceea_exe {
strings:
        $s1 = "MetadataReferenceProperties"
        $s2 = "ConditionalAttribute"
        $s3 = "XamlGeneratedNamespace"
        $s4 = "get_ObjectFormatter"
        $s5 = "set_PlacementTarget"
        $s6 = "GetLastWriteTimeUtc"
        $s7 = "set_IsParallelEntry"
        $s8 = "millisecondsTimeout"
        $s9 = "RuntimeHelpers"
        $s10 = "RelativeSource"
        $s11 = "StringComparer"
        $s12 = "get_IsCanceled"
        $s13 = "'$$method0x6000003-1'"
        $s14 = "set_CustomCategory"
        $s15 = "RuntimeFieldHandle"
        $s16 = "STAThreadAttribute"
        $s17 = "#\"&5'74632"
        $s18 = "+f$H^XbVS!r"
        $s19 = "W=#uY2BrUI1"
        $s20 = "tumblr_sign"
condition:
    uint16(0) == 0x5a4d and filesize < 1250KB and
    4 of them
}
    
rule efcebaeebaacccddcfdf_exe {
strings:
        $s1 = "cross device link"
        $s2 = "`vector destructor iterator'"
        $s3 = "CreateIoCompletionPort"
        $s4 = "executable format error"
        $s5 = "directory not empty"
        $s6 = "4=.8**.6+={y*<+0850"
        $s7 = "result out of range"
        $s8 = "invalid string position"
        $s9 = "On tree page %d cell %d: "
        $s10 = "operation canceled"
        $s11 = "GetConsoleOutputCP"
        $s12 = "`local vftable'"
        $s13 = "SetFilePointerEx"
        $s14 = "%z WITH INDEX %s"
        $s15 = "GetModuleHandleW"
        $s16 = "GetCurrentDirectoryW"
        $s17 = "destination address required"
        $s18 = "CreateCompatibleDC"
        $s19 = "connection refused"
        $s20 = "GetCurrentThreadId"
condition:
    uint16(0) == 0x5a4d and filesize < 551KB and
    4 of them
}
    
rule aefefacdebdfdedabbcf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "glock-crosshair-small"
        $s3 = "RuntimeFieldHandle"
        $s4 = "STAThreadAttribute"
        $s5 = "'/7?GOW_gow"
        $s6 = "O jb'w_x#U/"
        $s7 = "_CorExeMain"
        $s8 = "r`@C\"Wn6bq"
        $s9 = "SoundPlayer"
        $s10 = "VY$Xby_eE,I"
        $s11 = "ProductName"
        $s12 = "PT (6pl1QH}"
        $s13 = "VarFileInfo"
        $s14 = "pictureBox1"
        $s15 = "Dqs0&\"CVPp"
        $s16 = "4BzqLmI*~ce"
        $s17 = "FileDescription"
        $s18 = "p:8\\1}p]948o;8-"
        $s19 = "InitializeComponent"
        $s20 = "get_FlatAppearance"
condition:
    uint16(0) == 0x5a4d and filesize < 1276KB and
    4 of them
}
    
rule fffabbfabeabbcdaacaacbdacfceeeeacbb_exe {
strings:
        $s1 = "german-luxembourg"
        $s2 = "spanish-guatemala"
        $s3 = "english-caribbean"
        $s4 = "CoInitializeEx"
        $s5 = "invalid string position"
        $s6 = "LC_MONETARY"
        $s7 = "GetWindowDC"
        $s8 = "english-jamaica"
        $s9 = "`local vftable'"
        $s10 = "spanish-venezuela"
        $s11 = "chinese-singapore"
        $s12 = "RemoveDirectoryA"
        $s13 = "TerminateProcess"
        $s14 = "GetCurrentDirectoryW"
        $s15 = "GetCurrentThreadId"
        $s16 = "CreateCompatibleDC"
        $s17 = "GetLocalTime"
        $s18 = "south-africa"
        $s19 = "SetEndOfFile"
        $s20 = "FindFirstFileExA"
condition:
    uint16(0) == 0x5a4d and filesize < 281KB and
    4 of them
}
    
rule fdbdbaebbcfbdcffdeeefcebccbbdbcfed_exe {
strings:
        $s1 = "</assembly>P"
        $s2 = "VirtualProtect"
        $s3 = "SHLWAPI.dll"
        $s4 = "ExitProcess"
        $s5 = "COMCTL32.dll"
        $s6 = "GetProcAddress"
        $s7 = "ShellExecuteExA"
        $s8 = "CoInitialize"
        $s9 = "VirtualAlloc"
        $s10 = "        language=\"*\" />"
        $s11 = "InitCommonControls"
        $s12 = "SetBkColor"
        $s13 = "MSVCRT.dll"
        $s14 = "GN#<-#%C?A"
        $s15 = "SHELL32.dll"
        $s16 = "VirtualFree"
        $s17 = "LoadLibraryA"
        $s18 = "  <dependency>"
        $s19 = "KERNEL32.DLL"
        $s20 = "8!SDWj g@"
condition:
    uint16(0) == 0x5a4d and filesize < 215KB and
    4 of them
}
    
rule bdcbddcdfefabcbcbaccae_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "GetSystemPowerStatus"
        $s3 = "Runtime Error!"
        $s4 = "SetConsoleCtrlHandler"
        $s5 = "LC_MONETARY"
        $s6 = "VarFileInfo"
        $s7 = "r,TP;\"i.$w"
        $s8 = "english-jamaica"
        $s9 = "spanish-venezuela"
        $s10 = "chinese-singapore"
        $s11 = "AFX_DIALOG_LAYOUT"
        $s12 = "SetComputerNameW"
        $s13 = "TerminateProcess"
        $s14 = "GetModuleHandleW"
        $s15 = "GetCurrentDirectoryA"
        $s16 = "SetConsoleCursorInfo"
        $s17 = "ContinueDebugEvent"
        $s18 = "SetLocalTime"
        $s19 = "south africa"
        $s20 = "GetTickCount"
condition:
    uint16(0) == 0x5a4d and filesize < 445KB and
    4 of them
}
    
rule ccdbebbefcfcdecffeedadb_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "VirtualLock"
        $s3 = "CopyFileExA"
        $s4 = "NL^Z*:'/SWz"
        $s5 = "JN$ VTLi7%R"
        $s6 = "?@B:cCL*bn-"
        $s7 = "VarFileInfo"
        $s8 = "AFX_DIALOG_LAYOUT"
        $s9 = "GetComputerNameA"
        $s10 = "TerminateProcess"
        $s11 = "GetModuleHandleW"
        $s12 = "SetSystemTimeAdjustment"
        $s13 = "WriteProfileStringW"
        $s14 = "GetConsoleCursorInfo"
        $s15 = "ContinueDebugEvent"
        $s16 = "GetCurrentThreadId"
        $s17 = "GetLocalTime"
        $s18 = "mIcQ%{J\\-vM"
        $s19 = "wXMT;W/_}A  "
        $s20 = "GetTickCount"
condition:
    uint16(0) == 0x5a4d and filesize < 404KB and
    4 of them
}
    
rule dbfccdabebcfaacceaaa_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "FlagsAttribute"
        $s3 = "GetProcessesByName"
        $s4 = "SB1XWZHwHPBGZWQWwY"
        $s5 = "GKoF43F3PaIkGno3vI"
        $s6 = "RuntimeFieldHandle"
        $s7 = "STAThreadAttribute"
        $s8 = "ProductName"
        $s9 = "_CorExeMain"
        $s10 = "ComputeHash"
        $s11 = "op_Equality"
        $s12 = "VarFileInfo"
        $s13 = "FileDescription"
        $s14 = "FlushFinalBlock"
        $s15 = "ResolveEventArgs"
        $s16 = "get_ModuleHandle"
        $s17 = "http://localhost:8000/"
        $s18 = "Synchronized"
        $s19 = "DialogResult"
        $s20 = "Expression`1"
condition:
    uint16(0) == 0x5a4d and filesize < 830KB and
    4 of them
}
    
rule ceffdebaeecedfecceee_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "Directory not empty"
        $s3 = "Runtime Error!"
        $s4 = "GetConsoleOutputCP"
        $s5 = "No child processes"
        $s6 = "ProductName"
        $s7 = "[?YGQj{>VxL"
        $s8 = ":t-joLFE'ds"
        $s9 = "VarFileInfo"
        $s10 = "%4ufAx],wj:"
        $s11 = "qc{F&1w3X0J"
        $s12 = "2OJ|vrMpXy6"
        $s13 = "`local vftable'"
        $s14 = "FileDescription"
        $s15 = "TerminateProcess"
        $s16 = "GetModuleHandleW"
        $s17 = "Operation not permitted"
        $s18 = "Microsoft Corporation"
        $s19 = "GetCurrentThreadId"
        $s20 = "No locks available"
condition:
    uint16(0) == 0x5a4d and filesize < 1029KB and
    4 of them
}
    
rule eeefddaeecbcdcccedefdaffefd_exe {
strings:
        $s1 = "IdnAllDataATtVVrN"
        $s2 = "get_ProductPrivatePart"
        $s3 = "RuntimeHelpers"
        $s4 = "$this.GridSize"
        $s5 = "EnumerateFiles"
        $s6 = "FlagsAttribute"
        $s7 = "GetSubKeyNames"
        $s8 = "RuntimeFieldHandle"
        $s9 = "RLJGJSBAPX2RPP62aA"
        $s10 = "_CNMnRIvFaK"
        $s11 = "_tOKjzQEgxq"
        $s12 = "_zswnpyPYSo"
        $s13 = "_JzhBSucfmY"
        $s14 = "_sCVSgJrEXU"
        $s15 = "_jgXDaZrPqW"
        $s16 = "ProductName"
        $s17 = "_CorExeMain"
        $s18 = "ComputeHash"
        $s19 = "_SqVTteCDAs"
        $s20 = "*n>+2)V\"_c"
condition:
    uint16(0) == 0x5a4d and filesize < 362KB and
    4 of them
}
    
rule afefbaefbafaeeaeffdddcccdcbbb_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "`vector destructor iterator'"
        $s3 = "GetSystemPowerStatus"
        $s4 = "Runtime Error!"
        $s5 = "invalid string position"
        $s6 = "SetConsoleCtrlHandler"
        $s7 = "VirtualLock"
        $s8 = "CopyFileExA"
        $s9 = ":I%BMaZC*'r"
        $s10 = "LC_MONETARY"
        $s11 = "VarFileInfo"
        $s12 = "english-jamaica"
        $s13 = "`local vftable'"
        $s14 = "spanish-venezuela"
        $s15 = "ProductionVersion"
        $s16 = "chinese-singapore"
        $s17 = "AFX_DIALOG_LAYOUT"
        $s18 = "TerminateProcess"
        $s19 = "GetModuleHandleW"
        $s20 = "south africa"
condition:
    uint16(0) == 0x5a4d and filesize < 386KB and
    4 of them
}
    
rule eebeeebfbadefaebefbcaaccbaa_exe {
strings:
        $s1 = "SystemNetMailMessagex"
        $s2 = "_CorExeMain"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "lpApplicationName"
        $s6 = "PointerToRawData"
        $s7 = "IAsyncResult"
        $s8 = "ContextFlags"
        $s9 = "lpCommandLine"
        $s10 = "StringBuilder"
        $s11 = "lpStartupInfo"
        $s12 = "SecurityAction"
        $s13 = "VirtualAddress"
        $s14 = "MetroSetUIFormsMetroSetFormn"
        $s15 = "System.Security"
        $s16 = "lpEnvironment"
        $s17 = "SizeOfRawData"
        $s18 = "SizeOfHeaders"
        $s19 = "DebuggingModes"
        $s20 = "dwFillAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 23KB and
    4 of them
}
    
rule aabcefcafbfccbdeaccbccbbcf_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "Runtime Error!"
        $s3 = "GetConsoleOutputCP"
        $s4 = "< <$<(<,<0<4<8<<<@<D<H<L<P<T<X<\\<`<d<h<l<\\>`>h>l>p>t>"
        $s5 = "J&s]|Lc}/F8"
        $s6 = "VarFileInfo"
        $s7 = "`local vftable'"
        $s8 = "AFX_DIALOG_LAYOUT"
        $s9 = "TerminateProcess"
        $s10 = "GetModuleHandleW"
        $s11 = "GetCurrentThreadId"
        $s12 = "WriteProcessMemory"
        $s13 = "&lhaVW?$t8p8"
        $s14 = "GetTickCount"
        $s15 = "Zoh cegobires"
        $s16 = "Z0.24292?2F2X2@3Q3l3v3"
        $s17 = "Unknown exception"
        $s18 = "SetHandleCount"
        $s19 = "`udt returning'"
        $s20 = "GetSystemTimeAsFileTime"
condition:
    uint16(0) == 0x5a4d and filesize < 696KB and
    4 of them
}
    
rule ffaafecfcbbccdeddefaf_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "$this.GridSize"
        $s3 = "FlagsAttribute"
        $s4 = "dnXsIuIl331X6v1LXn"
        $s5 = "JXjhUjjsxV3ZjSVVoN"
        $s6 = "RuntimeFieldHandle"
        $s7 = "STAThreadAttribute"
        $s8 = "ProductName"
        $s9 = "_CorExeMain"
        $s10 = "ComputeHash"
        $s11 = ";y3`s!{TV1b"
        $s12 = "]-;'N\"zW)M"
        $s13 = "|z:;$D8hnCk"
        $s14 = "op_Equality"
        $s15 = "VarFileInfo"
        $s16 = "FileDescription"
        $s17 = "FlushFinalBlock"
        $s18 = "customCultureName"
        $s19 = "get_ModuleHandle"
        $s20 = "numberGroupSeparator"
condition:
    uint16(0) == 0x5a4d and filesize < 2053KB and
    4 of them
}
    
rule afcfbbeffeaadcc_exe {
strings:
        $s1 = "lpszFileExtension"
        $s2 = "Yandex\\YandexBrowser"
        $s3 = "ManagementBaseObject"
        $s4 = "EnumerateDirectories"
        $s5 = "Software\\Valve\\Steam"
        $s6 = "BraveSoftware\\Brave-Browser"
        $s7 = "ValidateRemoteCertificate"
        $s8 = "RuntimeHelpers"
        $s9 = "SystemInfo.txt"
        $s10 = "GetSubKeyNames"
        $s11 = "\\Exodus\\exodus.wallet\\"
        $s12 = "GetProcessesByName"
        $s13 = "Stream cannot seek"
        $s14 = "NormalizedFilename"
        $s15 = "RuntimeFieldHandle"
        $s16 = "VolumeSerialNumber"
        $s17 = "MarshalAsAttribute"
        $s18 = "_CorExeMain"
        $s19 = "user.config"
        $s20 = "XmlNodeList"
condition:
    uint16(0) == 0x5a4d and filesize < 106KB and
    4 of them
}
    
rule fdeeebfcbebacbacbcabbedfa_exe {
strings:
        $s1 = "client handshake "
        $s2 = "encoded window_update"
        $s3 = "`at` split index (is "
        $s4 = "schedule_pending_open"
        $s5 = "PushPromisepromised_id"
        $s6 = "CreateIoCompletionPort"
        $s7 = "send body user stream error: "
        $s8 = "starting new connection: "
        $s9 = "sized write, len = "
        $s10 = "FramedWrite::bufferframe"
        $s11 = "SymInitializeW"
        $s12 = "header map reserve overflowed"
        $s13 = "checkout dropped for "
        $s14 = "RtlNtStatusToDosError"
        $s15 = "GetConsoleOutputCP"
        $s16 = "encoding chunked B"
        $s17 = "CONNECT : HTTP/1.1"
        $s18 = "sending data frame"
        $s19 = "Internal Hyper error, please report "
        $s20 = "0123456789:"
condition:
    uint16(0) == 0x5a4d and filesize < 2521KB and
    4 of them
}
    
rule faaadddffaecabcecbcbdeeadd_exe {
strings:
        $s1 = "peer misbehaved: "
        $s2 = "invalid header '`"
        $s3 = "rename columns of"
        $s4 = "last_insert_rowid"
        $s5 = "AC RAIZ FNMT-RCM0"
        $s6 = "Bad redirection: "
        $s7 = "duplicate field `"
        $s8 = "CharEmptyLooklook"
        $s9 = "`at` split index (is "
        $s10 = "fatal runtime error: "
        $s11 = "rustls::msgs::handshake"
        $s12 = "server varied selected ciphersuite"
        $s13 = "fxf gfi_i8iNibiqi?iEiji9iBiWiYiziHiIi5ili3i=iei"
        $s14 = "onoffalseyestruextrafull"
        $s15 = "testserver: in read_request: "
        $s16 = "AlertMessagePayloadlevel"
        $s17 = "wrong # of entries in index "
        $s18 = "t$t&t(t)t*t+t,t-t.t/t0t1t9t@tCtDtFtGtKtMtQtRtWt]tbtftgthtktmtntqtrt"
        $s19 = "notification message"
        $s20 = "authorization denied"
condition:
    uint16(0) == 0x5a4d and filesize < 3103KB and
    4 of them
}
    
rule ffadcbaecbccebaeefcbcdcea_exe {
strings:
        $s1 = "GetCurrentThreadId"
        $s2 = "VirtualProtect"
        $s3 = "GetCurrentProcess"
        $s4 = "GetProcAddress"
        $s5 = "VirtualAlloc"
        $s6 = "InitCommonControls"
        $s7 = "ZE\"(@ TP("
        $s8 = "VirtualFree"
        $s9 = "msimg32.dll"
        $s10 = "LoadLibraryA"
        $s11 = "OleInitialize"
        $s12 = "comctl32.dll"
        $s13 = "kernel32.dll"
        $s14 = ">P(tD(~E(~A"
        $s15 = "E(<Q(6A(vA(^"
        $s16 = "Q\"T@ 4@("
        $s17 = "(\"@*j@*j@"
        $s18 = "P(LP(lD(DD(d"
        $s19 = "ole32.dll"
        $s20 = "PQRVW=<)"
condition:
    uint16(0) == 0x5a4d and filesize < 381KB and
    4 of them
}
    
rule bdaabfefbfaeaabebacbbbdaef_exe {
strings:
        $s1 = "german-luxembourg"
        $s2 = "spanish-guatemala"
        $s3 = "english-caribbean"
        $s4 = "Runtime Error!"
        $s5 = "invalid string position"
        $s6 = "GetConsoleOutputCP"
        $s7 = "VarFileInfo"
        $s8 = "LC_MONETARY"
        $s9 = "SetVolumeLabelA"
        $s10 = "english-jamaica"
        $s11 = "`local vftable'"
        $s12 = "spanish-venezuela"
        $s13 = "GetThreadPriority"
        $s14 = "chinese-singapore"
        $s15 = "TerminateProcess"
        $s16 = "GetModuleHandleA"
        $s17 = "GetCurrentThreadId"
        $s18 = "GetLocalTime"
        $s19 = "south-africa"
        $s20 = " qN\\Z;zd>v!"
condition:
    uint16(0) == 0x5a4d and filesize < 282KB and
    4 of them
}
    
rule ebcfbeefcbdaebdcddae_exe {
strings:
        $s1 = "!RPYMT&\"&MY#!XMW!R:&&\"!"
        $s2 = "mENpw}vnj9T|jj"
        $s3 = "Chpotihkchr<&H"
        $s4 = "invalid string position"
        $s5 = "I?[~vxrp{/s"
        $s6 = "z)5<.-;(?&7"
        $s7 = "`local vftable'"
        $s8 = "SetFilePointerEx"
        $s9 = "TerminateProcess"
        $s10 = "Eqpvgpv/V{rg<\"c7gggg7(((7gggg7d"
        $s11 = "GetCurrentThreadId"
        $s12 = "dyr%xzg4hdG]"
        $s13 = ";.=885{azdt|"
        $s14 = ".?AVImageC@@"
        $s15 = "FindFirstFileExW"
        $s16 = "I?vQYPMR^KVPQ"
        $s17 = "N}}]||yiN}!}`TUIX"
        $s18 = "Unknown exception"
        $s19 = "CorExitProcess"
        $s20 = "LoadLibraryExW"
condition:
    uint16(0) == 0x5a4d and filesize < 342KB and
    4 of them
}
    
rule ffdcfbeddcaaaafdbcfeb_exe {
strings:
        $s1 = "GetModuleHandleA"
        $s2 = "VirtualProtect"
        $s3 = "GetCurrentThread"
        $s4 = "GetProcAddress"
        $s5 = "VirtualAlloc"
        $s6 = "vD E(#@(gP"
        $s7 = "msimg32.dll"
        $s8 = "VirtualFree"
        $s9 = "LoadLibraryA"
        $s10 = "shlwapi.dll"
        $s11 = "comctl32.dll"
        $s12 = "kernel32.dll"
        $s13 = "DllInitialize"
        $s14 = "Q\"T@ 4@("
        $s15 = "StrChrNIW"
        $s16 = "(\"@*j@*j@"
        $s17 = "@(FA(DQ(d"
        $s18 = "ole32.dll"
        $s19 = "T*2P\"NA"
        $s20 = "lstrcmpA"
condition:
    uint16(0) == 0x5a4d and filesize < 438KB and
    4 of them
}
    
rule ffdbfabafadbbbefcaf_exe {
strings:
        $s1 = "german-luxembourg"
        $s2 = "spanish-guatemala"
        $s3 = "english-caribbean"
        $s4 = "GetEnvironmentStrings"
        $s5 = "Runtime Error!"
        $s6 = "invalid string position"
        $s7 = "GetConsoleOutputCP"
        $s8 = "VarFileInfo"
        $s9 = "LC_MONETARY"
        $s10 = "SetVolumeLabelW"
        $s11 = "english-jamaica"
        $s12 = "`local vftable'"
        $s13 = "_gekelberifin@8"
        $s14 = "spanish-venezuela"
        $s15 = "chinese-singapore"
        $s16 = "AFX_DIALOG_LAYOUT"
        $s17 = "SetThreadPriority"
        $s18 = "TerminateProcess"
        $s19 = "GetModuleHandleA"
        $s20 = "CreateJobObjectW"
condition:
    uint16(0) == 0x5a4d and filesize < 276KB and
    4 of them
}
    
rule acadecfebfabdcdebedecceeae_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "  Caption = Bmwkieaaiaat"
        $s3 = "Game@Trelokme.game1"
        $s4 = "CoInitializeEx"
        $s5 = "UY]9Qtw?'Xp"
        $s6 = ",/:~rzUY5Q;"
        $s7 = "9YpyVu^_>rK"
        $s8 = "-GFh;IdeE^n"
        $s9 = "G2-*k~YAD_["
        $s10 = "@tX}C(duqJ!"
        $s11 = "/forcse)un9"
        $s12 = "AG}t\"wY4S>"
        $s13 = "`zU{<Ru>S'5"
        $s14 = "QFLCPEOTDSB"
        $s15 = "BJk`}C^8]O9"
        $s16 = "GetModuleHandleA"
        $s17 = "K+]]4c'QR$\""
        $s18 = " jJT^(CVjg]W"
        $s19 = "MSVCP140.dll"
        $s20 = "Description:"
condition:
    uint16(0) == 0x5a4d and filesize < 1996KB and
    4 of them
}
    
rule dadceceebffecfbcdfdececdddfb_exe {
strings:
        $s1 = "ResolveTypeHandle"
        $s2 = "get_IsTerminating"
        $s3 = "GCNotificationStatus"
        $s4 = "RuntimeHelpers"
        $s5 = "SendingReportStep1"
        $s6 = "RuntimeFieldHandle"
        $s7 = "STAThreadAttribute"
        $s8 = "get_ProcessorCount"
        $s9 = "$Copyright "
        $s10 = "@u|-?$!Eax'"
        $s11 = "_CorExeMain"
        $s12 = "ComputeHash"
        $s13 = ".XU!*#+o2\""
        $s14 = "u!Uc7md1':j"
        $s15 = "ProductName"
        $s16 = "\"M%k6S]#7n"
        $s17 = "VarFileInfo"
        $s18 = "LastIndexOf"
        $s19 = "XmlNodeList"
        $s20 = "*WD4w@u7nS1"
condition:
    uint16(0) == 0x5a4d and filesize < 1315KB and
    4 of them
}
    
rule cefabdafbbcaeefdeafecbfafde_exe {
strings:
        $s1 = "$0086e4fb-e603-4c03-bef6-fd8b6e700367"
        $s2 = "RuntimeHelpers"
        $s3 = "RuntimeFieldHandle"
        $s4 = "ProductName"
        $s5 = "_CorExeMain"
        $s6 = "K7P;T=]a#[V"
        $s7 = ", \"a8.XOM6"
        $s8 = "VarFileInfo"
        $s9 = "+Lgb6Pqza@_"
        $s10 = "FileDescription"
        $s11 = "FlushFinalBlock"
        $s12 = "get_IsBrowserHosted"
        $s13 = "SecurityCriticalAttribute"
        $s14 = "Synchronized"
        $s15 = "Durbanville1"
        $s16 = "BBd',N^R}_ %"
        $s17 = "']aeCKr#\\O$"
        $s18 = "IAsyncResult"
        $s19 = "System.Resources"
        $s20 = "StringBuilder"
condition:
    uint16(0) == 0x5a4d and filesize < 813KB and
    4 of them
}
    
rule cbabaaeaffaeddeffafbdabaafbfc_exe {
strings:
        $s1 = "ManagementBaseObject"
        $s2 = "RuntimeHelpers"
        $s3 = "Runtime Error!"
        $s4 = "GetSubKeyNames"
        $s5 = "get_ProcessorArchitecture"
        $s6 = "Stream cannot seek"
        $s7 = "RuntimeFieldHandle"
        $s8 = "STAThreadAttribute"
        $s9 = "ProductName"
        $s10 = "ComputeHash"
        $s11 = "LastIndexOf"
        $s12 = "ConvertBack"
        $s13 = "get_MachineName"
        $s14 = "FileDescription"
        $s15 = "IFormatProvider"
        $s16 = "get_ProcessName"
        $s17 = "PhysicalAddress"
        $s18 = "FlushFinalBlock"
        $s19 = "OrderByDescending"
        $s20 = "ResolveEventArgs"
condition:
    uint16(0) == 0x5a4d and filesize < 237KB and
    4 of them
}
    