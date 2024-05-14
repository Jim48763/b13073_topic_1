import pe
rule Bonzify_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "~zwxuy|xvypr{xy{}tx~|"
        $s3 = "{y{~|{sv{ywuwvxtqrz~y"
        $s4 = " instituer tout litige qui pourrait d"
        $s5 = "What did the beaver say to the tree?"
        $s6 = "~}vy|wqqwumtz{wtyyz|wyxz"
        $s7 = "065CB?11:;1.(&"
        $s8 = "yutvutpprqquywvsxyz|z"
        $s9 = "F]#$eyo'GRg"
        $s10 = "[F@y:f2DQab"
        $s11 = "h:R2CY!=V(+"
        $s12 = "MEU-_B5w]=T"
        $s13 = "5[aN2*:MJ8%"
        $s14 = "TXr1@Y)]qaI"
        $s15 = "ProductName"
        $s16 = "$6rx]h8\"sC"
        $s17 = "}Zu8&@yJF{I"
        $s18 = "Idle1_9 (3)"
        $s19 = "%=Tfqsl^J5 "
        $s20 = "oQ:-1DMu*cP"
condition:
    uint16(0) == 0x5a4d and filesize < 6549KB and
    4 of them
}
    
rule Email_Worm_Magistr_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "msctls_progress32"
        $s3 = "GetEnvironmentStrings"
        $s4 = "RegSetValueExA"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "Switzerland"
        $s8 = "LC_MONETARY"
        $s9 = "english-jamaica"
        $s10 = "FileDescription"
        $s11 = "UpgrdHlpSatellite"
        $s12 = "spanish-venezuela"
        $s13 = "PN Upgrade Helper"
        $s14 = "TerminateProcess"
        $s15 = "GetModuleHandleA"
        $s16 = "DispatchMessageA"
        $s17 = "Symbol not found"
        $s18 = "RemoveDirectoryA"
        $s19 = "GetCurrentDirectoryA"
        $s20 = "InitializeCriticalSection"
condition:
    uint16(0) == 0x5a4d and filesize < 112KB and
    4 of them
}
    
rule Email_Worm_MyDoom_A_exe {
strings:
        $s1 = "pqrstNwxyzg"
        $s2 = "-tvey-2.0oqp"
        $s3 = "op)NamLSPoG%"
        $s4 = "notepad %s"
        $s5 = "GSizeZClos"
        $s6 = "ExitProcess"
        $s7 = "NB;788=EP^o"
        $s8 = "ADVAPI32.dll"
        $s9 = "\\Jvaqbjf\\Phe"
        $s10 = "GetProcAddress"
        $s11 = "USER32.dll"
        $s12 = "MSVCRT.dll"
        $s13 = "5vmb/xH*.*"
        $s14 = "HByt\"nAdn"
        $s15 = "gkF0Sgnfxz"
        $s16 = "D\"veTyp$v"
        $s17 = "6[pl93foo/["
        $s18 = "LoadLibraryA"
        $s19 = "RegCloseKey"
        $s20 = "-TRG / UGGC/V"
condition:
    uint16(0) == 0x5a4d and filesize < 27KB and
    4 of them
}
    
rule Email_Worm_MyDoom_L_exe {
strings:
        $s1 = "Subject: %s"
        $s2 = "SetThreadPriority"
        $s3 = "GetModuleHandleA"
        $s4 = "GetLocalTime"
        $s5 = "GetTickCount"
        $s6 = "SetEndOfFile"
        $s7 = "MapViewOfFile"
        $s8 = "X-Priority: 3"
        $s9 = "CharUpperBuffA"
        $s10 = "GetTempFileNameA"
        $s11 = "ShareReactor.com"
        $s12 = "RegCreateKeyExA"
        $s13 = "GetDriveTypeA"
        $s14 = "charset=us-ascii"
        $s15 = "rctrl_renwnd32"
        $s16 = "GetProcessHeap"
        $s17 = "ExitThread"
        $s18 = "wvsprintfA"
        $s19 = "DnsQuery_A"
        $s20 = "gold-certs"
condition:
    uint16(0) == 0x5a4d and filesize < 80KB and
    4 of them
}
    
rule Email_Worm_MyDoom_M_exe {
strings:
        $s1 = "Subject: %s"
        $s2 = "FMPWDHOUEJQ"
        $s3 = "SetThreadPriority"
        $s4 = "GetModuleHandleA"
        $s5 = "GetLocalTime"
        $s6 = "GetTickCount"
        $s7 = "MapViewOfFile"
        $s8 = "X-Priority: 3"
        $s9 = "CharUpperBuffA"
        $s10 = "GetTempFileNameA"
        $s11 = "RegCreateKeyExA"
        $s12 = "GetDriveTypeA"
        $s13 = "$8AAA6213(/5'"
        $s14 = "charset=us-ascii"
        $s15 = "rctrl_renwnd32"
        $s16 = "GetProcessHeap"
        $s17 = "cd2cFdoy9od\"@A"
        $s18 = "ExitThread"
        $s19 = "wvsprintfA"
        $s20 = "DnsQuery_A"
condition:
    uint16(0) == 0x5a4d and filesize < 45KB and
    4 of them
}
    
rule Email_Worm_MyDoom_NF_exe {
strings:
        $s1 = "ABCDEFGHIJK"
        $s2 = "bFO><:t9.5"
        $s3 = "23456789+/"
        $s4 = "ExitProcess"
        $s5 = "ADVAPI32.dll"
        $s6 = "~E< r8<=t4<+t0<"
        $s7 = "GetProcAddress"
        $s8 = "USER32.dll"
        $s9 = "MSVCRT.dll"
        $s10 = "K?GOGSU~m3"
        $s11 = "}d4H1A|(}."
        $s12 = "comhdeRe$t"
        $s13 = "USERPROFILE"
        $s14 = "LoadLibraryA"
        $s15 = "RegCloseKey"
        $s16 = "KERNEL32.DLL"
        $s17 = "rctrl_renwn"
        $s18 = "W0RAR.v.3Z."
        $s19 = "&!Vo<SDj="
        $s20 = "wsprintfA"
condition:
    uint16(0) == 0x5a4d and filesize < 49KB and
    4 of them
}
    
rule Email_Worm_MyDoom_Q_exe {
strings:
        $s1 = "Subject: %s"
        $s2 = "SetThreadPriority"
        $s3 = "GetModuleHandleA"
        $s4 = "GetLocalTime"
        $s5 = "GetTickCount"
        $s6 = "SetEndOfFile"
        $s7 = "MapViewOfFile"
        $s8 = "X-Priority: 3"
        $s9 = "CharUpperBuffA"
        $s10 = "GetTempFileNameA"
        $s11 = "ShareReactor.com"
        $s12 = "RegCreateKeyExA"
        $s13 = "GetDriveTypeA"
        $s14 = "charset=us-ascii"
        $s15 = "rctrl_renwnd32"
        $s16 = "GetProcessHeap"
        $s17 = "ExitThread"
        $s18 = "wvsprintfA"
        $s19 = "DnsQuery_A"
        $s20 = "gold-certs"
condition:
    uint16(0) == 0x5a4d and filesize < 74KB and
    4 of them
}
    
rule Joke_ChilledWindows_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "RuntimeFieldHandle"
        $s4 = "[D.k\"TiA8L"
        $s5 = "T.*{u7ncV^j"
        $s6 = "YV1\"8T_j2v"
        $s7 = "Lwz\">f`&'S"
        $s8 = ">2:@91h[As3"
        $s9 = "X5@y\"}qQHL"
        $s10 = "vl_oE7a`)@2"
        $s11 = "ProductName"
        $s12 = ">VBxzrTa<]R"
        $s13 = "kw\"S!*=LJs"
        $s14 = "C\"XzOZ-nMQ"
        $s15 = "sA&.m=ZpxI6"
        $s16 = "k}>Y,AS<.{q"
        $s17 = ">\"XI8/$9ru"
        $s18 = "_CorExeMain"
        $s19 = "IXRd_^jyGT1"
        $s20 = "Lk-|B] t8F1"
condition:
    uint16(0) == 0x5a4d and filesize < 4476KB and
    4 of them
}
    
rule Joke_SnowAtDestkop_exe {
strings:
        $s1 = "VarFileInfo"
        $s2 = "ProductName"
        $s3 = "IsWindowVisible"
        $s4 = "FileDescription"
        $s5 = "GetModuleHandleA"
        $s6 = "CreateCompatibleDC"
        $s7 = "EnableWindow"
        $s8 = "SysListView32"
        $s9 = "InvalidateRgn"
        $s10 = "WinSnow98.EXE"
        $s11 = "CheckMenuItem"
        $s12 = "S&nowflake"
        $s13 = "_XcptFilter"
        $s14 = "EnumWindows"
        $s15 = "DestroyIcon"
        $s16 = "KERNEL32.dll"
        $s17 = "_adjust_fdiv"
        $s18 = "COMCTL32.dll"
        $s19 = "GetClassNameA"
        $s20 = "__getmainargs"
condition:
    uint16(0) == 0x5a4d and filesize < 33KB and
    4 of them
}
    
rule Locky_exe {
strings:
        $s1 = "GarrisonsNematode"
        $s2 = "GetKeyboardLayout"
        $s3 = "IntenseFigurehead"
        $s4 = "MagnetisationInterfacing"
        $s5 = "InstillsImprovements"
        $s6 = "MeltedFundamentalism"
        $s7 = "OutclassedGreengages"
        $s8 = "FilletModernisation"
        $s9 = "OptimistMarginality"
        $s10 = "IntimatesInterplays"
        $s11 = "NonparticipationFreezer"
        $s12 = "RegSetValueExA"
        $s13 = "JabInterviewed"
        $s14 = "FixingMortices"
        $s15 = "MercenariesInfinitesimals"
        $s16 = "OutlayIntercountry"
        $s17 = "MetaboliseMuscadel"
        $s18 = "InsurgentFireguard"
        $s19 = "OralNovices"
        $s20 = "ProductName"
condition:
    uint16(0) == 0x5a4d and filesize < 185KB and
    4 of them
}
    
rule Net_Worm_Sasser_exe {
strings:
        $s1 = "dynamic link lib"
        $s2 = "OGRAM 1.X0"
        $s3 = "geXtMic_m:m"
        $s4 = " located in the "
        $s5 = "GetProcAddress"
        $s6 = "Entry Point Not"
        $s7 = "rary %s.Qord"
        $s8 = "#tSy`oemSYhS"
        $s9 = "VirtualAlloc"
        $s10 = "VirtualFree"
        $s11 = "LoadLibraryA"
        $s12 = "kernel32.dll"
        $s13 = "wsprintfA"
        $s14 = "%,Xklw3n>"
        $s15 = "V7\\.-p%u"
        $s16 = "The proce"
        $s17 = "I0#\"uc%"
        $s18 = ">cmd.ftp"
        $s19 = "adq!ckj/"
        $s20 = "ageBoxAX"
condition:
    uint16(0) == 0x5a4d and filesize < 20KB and
    4 of them
}
    
rule Ransomware_evn_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "cross device link"
        $s4 = "english-caribbean"
        $s5 = "\\AppData\\Local\\bcd1.bat"
        $s6 = "executable format error"
        $s7 = "result out of range"
        $s8 = "directory not empty"
        $s9 = "invalid string position"
        $s10 = "operation canceled"
        $s11 = "LC_MONETARY"
        $s12 = "english-jamaica"
        $s13 = "`local vftable'"
        $s14 = "spanish-venezuela"
        $s15 = "TerminateProcess"
        $s16 = "SetFilePointerEx"
        $s17 = "DispatchMessageW"
        $s18 = "destination address required"
        $s19 = "connection refused"
        $s20 = "EventWriteTransfer"
condition:
    uint16(0) == 0x5a4d and filesize < 320KB and
    4 of them
}
    
rule Ransomware_BadRabbit_exe {
strings:
        $s1 = "invalid distance code"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "FileDescription"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleW"
        $s7 = "51=o>g7RxQj="
        $s8 = "Durbanville1"
        $s9 = "invalid window size"
        $s10 = "FlashUtil.exe"
        $s11 = "\\rundll32.exe"
        $s12 = "need dictionary"
        $s13 = "    </security>"
        $s14 = "header crc mismatch"
        $s15 = "Western Cape1"
        $s16 = "%\\4*<b\"]q2-"
        $s17 = "incorrect header check"
        $s18 = "GetProcessHeap"
        $s19 = "LegalTrademarks"
        $s20 = "~MU`?#7\"a"
condition:
    uint16(0) == 0x5a4d and filesize < 436KB and
    4 of them
}
    
rule Ransomware_CoronaVirus_exe {
strings:
        $s1 = "Min: (%.2f, %.2f)"
        $s2 = "ESCAPE to revert."
        $s3 = "\"imgui\" letters"
        $s4 = "DialboxSerialPort"
        $s5 = " NavEnableGamepad"
        $s6 = "GetEnvironmentStrings"
        $s7 = "click on a button to set focus"
        $s8 = "(%6.1f,%6.1f) (%6.1f,%6.1f) Size (%6.1f,%6.1f) %s"
        $s9 = "%s: %d entries, %d bytes"
        $s10 = "Disable tree indentation"
        $s11 = "Cannot create window"
        $s12 = "I am a fancy tooltip"
        $s13 = "Hovering me sets the"
        $s14 = "input text (w/ hint)"
        $s15 = "Don't ask me next time"
        $s16 = "glutInitContextFunc"
        $s17 = "glutLeaveFullScreen"
        $s18 = "SelectableTextAlign"
        $s19 = "Text baseline:"
        $s20 = "TabBar (%d tabs)%s"
condition:
    uint16(0) == 0x5a4d and filesize < 1043KB and
    4 of them
}
    
rule Ransomware_CryptoLocker_exe {
strings:
        $s1 = "msctls_progress32"
        $s2 = "SetWindowTheme"
        $s3 = "CoInitializeEx"
        $s4 = "GdipGetImageHeight"
        $s5 = "IsWindowVisible"
        $s6 = "DialogBoxParamW"
        $s7 = "SetThreadPriority"
        $s8 = "PathAddBackslashW"
        $s9 = "UnregisterClassW"
        $s10 = "SetFilePointerEx"
        $s11 = "GetModuleHandleW"
        $s12 = "GetComputerNameW"
        $s13 = "DispatchMessageW"
        $s14 = "CreateCompatibleDC"
        $s15 = "GetCurrentThreadId"
        $s16 = "GetTickCount"
        $s17 = "+be IuwBRyR-"
        $s18 = "UpdateWindow"
        $s19 = "SysListView32"
        $s20 = "RegEnumKeyExW"
condition:
    uint16(0) == 0x5a4d and filesize < 343KB and
    4 of them
}
    
rule Ransomware_CryptoWall_exe {
strings:
        $s1 = "5#505A5G5P5W5`5i5$6*666?6E6P6W6`6g6q6v6}6"
        $s2 = "Connection: close"
        $s3 = "C:\\out.png"
        $s4 = ")\"Oa\"Pc%?Q"
        $s5 = "eyea-a&u\""
        $s6 = "x9jSeq@gP"
        $s7 = "?-?-9-=7}["
        $s8 = "2E3L3\\3c3t3z3"
        $s9 = "F36[&?);)"
        $s10 = ":12r04Q&Q"
        $s11 = " AtUawwBW"
        $s12 = ":p\"TaT%g"
        $s13 = "6hehbz4fp"
        $s14 = "3;4K4d4q4{4"
        $s15 = "9\"~M\":!"
        $s16 = "! !<!de\""
        $s17 = "!'.\"\\k`"
        $s18 = "0 Rl1MQ&"
        $s19 = "oWaTl 3."
        $s20 = "Z)`bIBQG"
condition:
    uint16(0) == 0x5a4d and filesize < 137KB and
    4 of them
}
    
rule Ransomware_GoldenEye_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "english-caribbean"
        $s4 = "SetDefaultDllDirectories"
        $s5 = ".bmp;*.dib;*.png;*.jpg;*.jpeg;*.jpe;*.jfif;*.gif)"
        $s6 = "RegSetValueExA"
        $s7 = "SetConsoleCtrlHandler"
        $s8 = "GIF (*.gif)"
        $s9 = "LC_MONETARY"
        $s10 = "PNG (*.png)"
        $s11 = "english-jamaica"
        $s12 = "`local vftable'"
        $s13 = "MagnifierWindow"
        $s14 = "IsWindowVisible"
        $s15 = "DialogBoxParamA"
        $s16 = "SetThreadPriority"
        $s17 = "All Picture Files"
        $s18 = "spanish-venezuela"
        $s19 = "ZoominSliderLevel"
        $s20 = "magnification.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 259KB and
    4 of them
}
    
rule Ransomware_Jigsaw_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "All you have to do..."
        $s3 = "BitcoinBlackmailer"
        $s4 = "RuntimeFieldHandle"
        $s5 = "ImposeRestrictions"
        $s6 = "STAThreadAttribute"
        $s7 = "GetProcessesByName"
        $s8 = "ReadFromEmbeddedResources"
        $s9 = "System.Linq"
        $s10 = "ProductName"
        $s11 = "_CorExeMain"
        $s12 = "op_Equality"
        $s13 = "AssemblyVersion"
        $s14 = "set_MinimizeBox"
        $s15 = "IFormatProvider"
        $s16 = "FileDescription"
        $s17 = "ResolveEventArgs"
        $s18 = "InitializeComponent"
        $s19 = "AssemblyTitleAttribute"
        $s20 = "GraphicsUnit"
condition:
    uint16(0) == 0x5a4d and filesize < 288KB and
    4 of them
}
    
rule Ransomware_Mischa_exe {
strings:
        $s1 = "LoadAcceleratorsW"
        $s2 = "GetKeyboardLayout"
        $s3 = "msctls_progress32"
        $s4 = "Can't create control."
        $s5 = "REG_RESOURCE_REQUIREMENTS_LIST"
        $s6 = "AHK_ATTACH_DEBUGGER"
        $s7 = "msctls_statusbar321"
        $s8 = "VirtualAllocEx"
        $s9 = "SetWindowTheme"
        $s10 = "RegSetValueExW"
        $s11 = "MyDocuments"
        $s12 = "ProductName"
        $s13 = "Invalid `%."
        $s14 = "Link Source"
        $s15 = "Old_Persian"
        $s16 = "u38D$xt!f9G"
        $s17 = "&Window Spy"
        $s18 = "NumpadEnter"
        $s19 = "VarFileInfo"
        $s20 = "AlwaysOnTop"
condition:
    uint16(0) == 0x5a4d and filesize < 883KB and
    4 of them
}
    
rule Ransomware_Mischa_v_exe {
strings:
        $s1 = "spanish-guatemala"
        $s2 = "german-luxembourg"
        $s3 = "cross device link"
        $s4 = "english-caribbean"
        $s5 = "SetDefaultDllDirectories"
        $s6 = "executable format error"
        $s7 = "result out of range"
        $s8 = "directory not empty"
        $s9 = "CoInitializeEx"
        $s10 = "@WM_ATLGETHOST"
        $s11 = "OleLockRunning"
        $s12 = "invalid string position"
        $s13 = "operation canceled"
        $s14 = "getHostDescription"
        $s15 = ".?AVbad_cast@std@@"
        $s16 = "LC_MONETARY"
        $s17 = "_WriteLog@4"
        $s18 = "english-jamaica"
        $s19 = "`local vftable'"
        $s20 = "getScreenBounds"
condition:
    uint16(0) == 0x5a4d and filesize < 284KB and
    4 of them
}
    
rule Ransomware_NotPetya_exe {
strings:
        $s1 = "@\\perfc.dat"
        $s2 = "\\rundll32.exe"
        $s3 = "    </security>"
        $s4 = "IYZ/[JLu`a"
        $s5 = "e`+DbVHs*."
        $s6 = "Washington1"
        $s7 = "ExitProcess"
        $s8 = "JRN}jN|x>|c8"
        $s9 = "KERNEL32.dll"
        $s10 = "%6RWWXa P]]^"
        $s11 = "100427180659Z0#"
        $s12 = "CreateProcessW"
        $s13 = "N<v]zo<n?M"
        $s14 = "3\\.c,naL'"
        $s15 = "rt\\=4v?*["
        $s16 = "pi`'irQfB_"
        $s17 = "z'VIBk\\m."
        $s18 = "(?'`ipfQri"
        $s19 = "USER32.dll"
        $s20 = "b''Lv\\^]3d"
condition:
    uint16(0) == 0x5a4d and filesize < 371KB and
    4 of them
}
    
rule Ransomware_Petya_A_exe {
strings:
        $s1 = "cross device link"
        $s2 = "UnloadUserProfile"
        $s3 = "SetDefaultDllDirectories"
        $s4 = "CreateWindowStationW"
        $s5 = "executable format error"
        $s6 = "4 4$4(4,4044484D4H4L4P4T4`4d4h4L5P5T5X6\\6`6d6"
        $s7 = "result out of range"
        $s8 = "directory not empty"
        $s9 = "RegSetValueExW"
        $s10 = "invalid string position"
        $s11 = "operation canceled"
        $s12 = "AHKEY_CLASSES_ROOT"
        $s13 = "LogFilePath"
        $s14 = "`local vftable'"
        $s15 = "IsWindowVisible"
        $s16 = "DeviceIoControl"
        $s17 = "NetWkstaGetInfo"
        $s18 = "ReadProcessMemory"
        $s19 = "RemoveDirectoryW"
        $s20 = "ClientCustomData"
condition:
    uint16(0) == 0x5a4d and filesize < 230KB and
    4 of them
}
    
rule Ransomware_Satana_exe {
strings:
        $s1 = "hcqzqdnqhvfbsrryd"
        $s2 = "GetLocalTime"
        $s3 = "Dtheyk[p{olp"
        $s4 = "mtkedgildxvj"
        $s5 = "Veu[qljtotrrP"
        $s6 = "bapbjfrknvrsmfmrn"
        $s7 = "on_tls_callback2"
        $s8 = "glPointSize"
        $s9 = "faasulcmnej"
        $s10 = "glLineWidth"
        $s11 = "tydqcgfwwka"
        $s12 = "KERNEL32.dll"
        $s13 = "UWRjyZZ_]PP|"
        $s14 = "yaqrbysjaqmdw"
        $s15 = "<*<5<@<O=X=R>j>o>"
        $s16 = "qwvywvszdcvle"
        $s17 = "USER32.dll"
        $s18 = "Bg~[`jkaM~"
        $s19 = "glVertex3d"
        $s20 = "MessageBoxA"
condition:
    uint16(0) == 0x5a4d and filesize < 54KB and
    4 of them
}
    
rule Ransomware_WannaCryptr_v_exe {
strings:
        $s1 = "__CxxFrameHandler"
        $s2 = "            processorArchitecture=\"*\""
        $s3 = "CryptReleaseContext"
        $s4 = "invalid distance code"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "FileDescription"
        $s8 = "GetModuleHandleA"
        $s9 = "GetCurrentDirectoryA"
        $s10 = "InitializeCriticalSection"
        $s11 = "Microsoft Corporation"
        $s12 = "OLEAUT32.dll"
        $s13 = "invalid window size"
        $s14 = "k?44@K!H>!dL1"
        $s15 = "_local_unwind2"
        $s16 = "    </security>"
        $s17 = "need dictionary"
        $s18 = "        <assemblyIdentity"
        $s19 = "incorrect header check"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 229KB and
    4 of them
}
    
rule Ransomware_WannaCryptr_v_exe {
strings:
        $s1 = "cmd.exe /c \"%s\""
        $s2 = "__CxxFrameHandler"
        $s3 = "            processorArchitecture=\"*\""
        $s4 = "RegSetValueExA"
        $s5 = "invalid distance code"
        $s6 = "xLjDJa'SHvZ"
        $s7 = "XyS\"'wK@Y="
        $s8 = "CUip0,Yes8v"
        $s9 = "|HDA$5.*r/j"
        $s10 = "ma\"3`&BF#W"
        $s11 = "}9zf]A\"g 0"
        $s12 = "VarFileInfo"
        $s13 = "dQe`5yO_$%;"
        $s14 = "ProductName"
        $s15 = "S*91q$4\"FD"
        $s16 = "BqZ=(JjQ:cS"
        $s17 = "fg|tLRKVj`Q"
        $s18 = "]p,-WTj6Bg("
        $s19 = "*d19_Zxp(Js"
        $s20 = "FileDescription"
condition:
    uint16(0) == 0x5a4d and filesize < 3437KB and
    4 of them
}
    
rule Trojan__exe {
strings:
        $s1 = "shutdown /f /r /t 0"
        $s2 = "STAThreadAttribute"
        $s3 = "ProductName"
        $s4 = "VarFileInfo"
        $s5 = "_CorExeMain"
        $s6 = "PB_WindowID"
        $s7 = "dwExtraInfo"
        $s8 = "ThreadStaticAttribute"
        $s9 = "IsWindowVisible"
        $s10 = "KeyEventHandler"
        $s11 = "FileDescription"
        $s12 = "FrameworkElement"
        $s13 = "TerminateProcess"
        $s14 = "GetModuleHandleA"
        $s15 = "DispatchMessageA"
        $s16 = "Integer overflow"
        $s17 = "RemoveDirectoryA"
        $s18 = "AutoRestartShell"
        $s19 = "GetCurrentDirectoryA"
        $s20 = "InitializeCriticalSection"
condition:
    uint16(0) == 0x5a4d and filesize < 6825KB and
    4 of them
}
    
rule Trojan_Anti_VM_ANA_exe {
strings:
        $s1 = "ALERT_VIRUS_NAMES"
        $s2 = "TreeViewEventArgs"
        $s3 = "GetEnvironmentStrings"
        $s4 = "EnableButtonsDelegate"
        $s5 = "DescriptionAttribute"
        $s6 = "ManagementBaseObject"
        $s7 = "set_SelectedImageIndex"
        $s8 = "SafariChromeFirefox"
        $s9 = "FlagsAttribute"
        $s10 = "Runtime Error!"
        $s11 = "SFGAO_VALIDATE"
        $s12 = "invalid string position"
        $s13 = "MarshalAsAttribute"
        $s14 = "InstallCertificate"
        $s15 = "SFGAO_CONTENTSMASK"
        $s16 = "STAThreadAttribute"
        $s17 = "VolumeSerialNumber"
        $s18 = "&X_f1Ay`QLp"
        $s19 = "LPx`/>h(;Di"
        $s20 = "('*vF<Xix~%"
condition:
    uint16(0) == 0x5a4d and filesize < 2128KB and
    4 of them
}
    
rule Trojan_BossDaMajor_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "P-v2edecompile"
        $s3 = "My.WebServices"
        $s4 = "v2eprogrampathname"
        $s5 = "AuthenticationMode"
        $s6 = "STAThreadAttribute"
        $s7 = "DesignerGeneratedAttribute"
        $s8 = "%LU\")ArItP"
        $s9 = "My.Computer"
        $s10 = "\"X~i])8'xD"
        $s11 = "DV{lh4w9XYM"
        $s12 = "v\"pEX(m4fJ"
        $s13 = "xi#M\"hq7o`"
        $s14 = "PB_WindowID"
        $s15 = "VarFileInfo"
        $s16 = "/?W~_7qs%fb"
        $s17 = "ProductName"
        $s18 = "_CorExeMain"
        $s19 = "=sBv&?H>1%C"
        $s20 = "ThreadStaticAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 1972KB and
    4 of them
}
    
rule Trojan_BUG_exe {
strings:
        $s1 = "if dongu = 6 then"
        $s2 = "  For Each file in files"
        $s3 = "set_TransparencyKey"
        $s4 = "v2eprogrampathname"
        $s5 = "STAThreadAttribute"
        $s6 = "No ways to escape!"
        $s7 = "pictureBox3"
        $s8 = "5B-\"1(%{)h"
        $s9 = "ProductName"
        $s10 = "80K:T\"-9y$"
        $s11 = "ksXaDO2=\"."
        $s12 = "+W&[,@-u2#7"
        $s13 = "2!>+J:UObho"
        $s14 = "PB_WindowID"
        $s15 = "+k/G'f-.#4*"
        $s16 = "XUMPQ9=qB?/"
        $s17 = "7\"B-Q<aNsb"
        $s18 = "#c1w.k=|6!D"
        $s19 = "6(9:<OAcFvL"
        $s20 = "PKDmFW8 60*"
condition:
    uint16(0) == 0x5a4d and filesize < 3122KB and
    4 of them
}
    
rule Trojan_ColorBug_exe {
strings:
        $s1 = "LoadStringA"
        $s2 = "WindowFrame"
        $s3 = "GetKeyboardType"
        $s4 = "GetThreadLocale"
        $s5 = "GetModuleHandleA"
        $s6 = "Division by zero"
        $s7 = "InitializeCriticalSection"
        $s8 = "GetCurrentThreadId"
        $s9 = "EInvalidCast"
        $s10 = "SetEndOfFile"
        $s11 = "FPUMaskValue"
        $s12 = "EOutOfMemory"
        $s13 = "THandleStream"
        $s14 = "File not found"
        $s15 = "FormatMessageA"
        $s16 = "LoadLibraryExA"
        $s17 = "Invalid filename"
        $s18 = "RegCreateKeyExA"
        $s19 = "ButtonAlternateFace"
        $s20 = "Read beyond end of file"
condition:
    uint16(0) == 0x5a4d and filesize < 58KB and
    4 of them
}
    
rule Trojan_MrsMajor__exe {
strings:
        $s1 = "@\\DFlDG4C4$?5dCG"
        $s2 = "majordared.Properties"
        $s3 = "[iyWisZjn_pniunszms"
        $s4 = "x.run \"\"\"\"&buhu&\"\\notmuch.exe\"\"\""
        $s5 = "set_TransparencyKey"
        $s6 = "Gt0\\)H27I*i\""
        $s7 = "CD?s&pB,lBRSB8"
        $s8 = "rj!l@!4b!#TA0I"
        $s9 = "0\"!/.l!@,A!~)"
        $s10 = "y[ysZnpVlf^yeT"
        $s11 = "Ab8\"Ao7iAy6vB"
        $s12 = "SetConsoleCtrlHandler"
        $s13 = "v2eprogrampathname"
        $s14 = "STAThreadAttribute"
        $s15 = ",!D(Ws] @_I"
        $s16 = "&}zTfV_8#- "
        $s17 = "CK9-A28~>X7"
        $s18 = "Cd4_Vu%`Gn "
        $s19 = "&R+-Lb1Tk0X"
        $s20 = "<+862>*G\"N"
condition:
    uint16(0) == 0x5a4d and filesize < 26265KB and
    4 of them
}
    
rule Trojan_MrsMajor__exe {
strings:
        $s1 = "invalid distance code"
        $s2 = "ProductName"
        $s3 = "VarFileInfo"
        $s4 = "IsWindowVisible"
        $s5 = "FileDescription"
        $s6 = "PathAddBackslashW"
        $s7 = "RemoveDirectoryW"
        $s8 = "UnregisterClassW"
        $s9 = "TerminateProcess"
        $s10 = "GetModuleHandleW"
        $s11 = "Integer overflow"
        $s12 = "DispatchMessageW"
        $s13 = "GetCurrentDirectoryW"
        $s14 = "TranslateAcceleratorW"
        $s15 = "Misaligned data access"
        $s16 = "GetCurrentThreadId"
        $s17 = "SHBrowseForFolderW"
        $s18 = "EnableWindow"
        $s19 = "Division by zero "
        $s20 = "invalid window size"
condition:
    uint16(0) == 0x5a4d and filesize < 386KB and
    4 of them
}
    
rule Trojan_NoEscape_exe {
strings:
        $s1 = "ProductName"
        $s2 = "+hPg,96xuV{"
        $s3 = "Hgw|M8k)%rI"
        $s4 = "\"HS%G(k6|J"
        $s5 = "VarFileInfo"
        $s6 = "=8YMzOb!{F/"
        $s7 = "paEt2[k_,b4"
        $s8 = "FileDescription"
        $s9 = "GetModuleHandleA"
        $s10 = "38lju==g64,U"
        $s11 = "NETAPI32.dll"
        $s12 = "RtlGetVersion"
        $s13 = "    </security>"
        $s14 = "CoTaskMemFree"
        $s15 = "S\"{UkAntC"
        $s16 = "<SQ2aph%y/"
        $s17 = "a\"wN6WDpZ"
        $s18 = "09AZtvJ7)E"
        $s19 = "SOm^/(a'J-"
        $s20 = ":g<6tbh]2w"
condition:
    uint16(0) == 0x5a4d and filesize < 671KB and
    4 of them
}
    
rule Trojan_RegFuck_exe {
strings:
        $s1 = ")\\=D81aC4h\"B"
        $s2 = "2z@j\"@SVE@[1="
        $s3 = "`!2Fk_?\"EnW\\"
        $s4 = "STAThreadAttribute"
        $s5 = "`4JrH]/B@m$"
        $s6 = "7b?E*+pGKRV"
        $s7 = "9\"NqUS',Oh"
        $s8 = "9s%4UyEe3qY"
        $s9 = "\"_=aD,q5]x"
        $s10 = "L`'v\"5Dq4_"
        $s11 = "0/1!vdgf~VY"
        $s12 = "/X{r%Wai\"V"
        $s13 = "6Xa@Tfhc{$A"
        $s14 = "bog(_z1A^Q-"
        $s15 = "jx\"VUGdB#q"
        $s16 = "NXADz!%ZTi7"
        $s17 = "ProductName"
        $s18 = "1Dt_jF\"vW7"
        $s19 = ":BSn)*rk[,G"
        $s20 = "OK#[qfkVI5b"
condition:
    uint16(0) == 0x5a4d and filesize < 12385KB and
    4 of them
}
    
rule Trojan_Stuxnet_exe {
strings:
        $s1 = "it [:)7Cuos"
        $s2 = "LS|#AQ-v;KM"
        $s3 = "ZwCreateSection"
        $s4 = "GetModuleHandleW"
        $s5 = "GetCurrentThreadId"
        $s6 = "GetTickCount"
        $s7 = "Ud':aDH:*b0-"
        $s8 = "VirtualProtect"
        $s9 = "yVN6~F'?\""
        $s10 = ":hBV/?^mi."
        $s11 = "nk(&5_ sSo"
        $s12 = "d<Bmk'QVR+"
        $s13 = "<N;V@$i-UL"
        $s14 = "VKH`oPy~ql"
        $s15 = "GetCurrentProcess"
        $s16 = "A<4H#(mx(Kr"
        $s17 = "~9tgkJ\\NF0"
        $s18 = "ExitProcess"
        $s19 = "KERNEL32.dll"
        $s20 = "GetProcAddress"
condition:
    uint16(0) == 0x5a4d and filesize < 506KB and
    4 of them
}
    
rule VBS_LoveLetter_txt_vbs {
strings:
        $s1 = "dim lines,n,dta1,dta2,dt1,dt2,dt3,dt4,l1,dt5,dt6"
        $s2 = "elseif num = 3 then"
        $s3 = "sub listadriv"
        $s4 = " odpowiedz.\""
        $s5 = "fileexist = msg"
        $s6 = "for each f1 in sf"
        $s7 = "eq=folderspec"
        $s8 = "set fc = f.Files"
        $s9 = "scriptini.close"
        $s10 = "sub main()"
        $s11 = "listadriv()"
        $s12 = "downread=\"\""
        $s13 = "end function"
        $s14 = "ext=lcase(ext)"
        $s15 = "att.attributes=att.attributes+2"
        $s16 = "d.write dt6"
        $s17 = "dim wscr,rr"
        $s18 = "regad=\"\""
        $s19 = "Dim d,dc,s"
        $s20 = "dim f,f1,sf"
condition:
    uint16(0) == 0x5a4d and filesize < 14KB and
    4 of them
}
    
rule Virus_CIH_exe {
strings:
        $s1 = "  Internet Address      Physical Address      Type"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "FileDescription"
        $s5 = "Microsoft Corporation"
        $s6 = "                with the Physical address eth_addr.  The Physical address is"
        $s7 = "0f2/33373;3?3C3G3K3O3S3\\7a7g7t7"
        $s8 = "FormatMessageA"
        $s9 = "_local_unwind2"
        $s10 = "  -s            Adds the host and associates the Internet address inet_addr"
        $s11 = "GetProcessHeap"
        $s12 = "CharToOemA"
        $s13 = "Copyright "
        $s14 = "_XcptFilter"
        $s15 = "KERNEL32.dll"
        $s16 = "inetmib1.dll"
        $s17 = "GetProcAddress"
        $s18 = "OriginalFilename"
        $s19 = "8:#:':+:/:3:7:;:?:C:G:K:O:S:W:[:_:c:g:k:o:"
        $s20 = "7 8&8,82888>8D8J8P8V8\\8b8h8D9J9P9V9"
condition:
    uint16(0) == 0x5a4d and filesize < 24KB and
    4 of them
}
    
rule Virus_Win_CIH_exe {
strings:
        $s1 = "3\\lkcX=\"JS-+"
        $s2 = "VarFileInfo"
        $s3 = "ProductName"
        $s4 = "Wv/rCu{KZI9"
        $s5 = "FileDescription"
        $s6 = "Microsoft Corporation"
        $s7 = "    </security>"
        $s8 = "OpenProcessToken"
        $s9 = "VirtualProtect"
        $s10 = "WiG{k#UxM1"
        $s11 = "_FOidToStr"
        $s12 = "]QageBox1Ug"
        $s13 = "ADVAPI32.dll"
        $s14 = "s program can"
        $s15 = "GetProcAddress"
        $s16 = "OriginalFilename"
        $s17 = "]}=%8d oB="
        $s18 = "VS_VERSION_INFO"
        $s19 = "Translation"
        $s20 = "CompanyName"
condition:
    uint16(0) == 0x5a4d and filesize < 30KB and
    4 of them
}
    
rule Worm_CodeRed_A_exe {
strings:
        $s1 = "VirtualProtect"
        $s2 = "HOST:www.worm.com"
        $s3 = "TcpSockSend"
        $s4 = "c:\\notworm"
        $s5 = "infocomm.dll"
        $s6 = "LoadLibraryA"
        $s7 = " Accept: */*"
        $s8 = "CreateFileA"
        $s9 = "GetSystemTime"
        $s10 = "  HTTP/1.0"
        $s11 = "WS2_32.dll"
        $s12 = "CreateThread"
        $s13 = "closesocket"
        $s14 = "GET /default.ida?NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u6858%ucbd3%u7801%u9090%u9090%u8190%u00c3%u0003%u8b00%u531b%u53ff%u0078%u0000%u00=a  HTTP/1.0"
        $s15 = "w3svc.dll"
        $s16 = "UWSVPj<"
        $s17 = "connect"
        $s18 = "socket"
        $s19 = ":LMTHu"
        $s20 = "X^[_]"
condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    4 of them
}
    