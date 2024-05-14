import pe
rule bbcbecffcfdbedceffbefcacaa_exe {
strings:
        $s1 = "OnContextPopupDBD"
        $s2 = "TControlCanvasT;D"
        $s3 = "rfCommonStartMenu"
        $s4 = "Unable to insert an item"
        $s5 = " 2001, 2002 Mike Lischke"
        $s6 = "CoInitializeEx"
        $s7 = "CoCreateInstanceEx"
        $s8 = "rfDesktopDirectory"
        $s9 = "TContextPopupEvent"
        $s10 = "Window Text"
        $s11 = "LoadStringA"
        $s12 = "TBrushStyle"
        $s13 = "GetWindowDC"
        $s14 = "TListColumn"
        $s15 = "Interval4YA"
        $s16 = "VarFileInfo"
        $s17 = "ProductName"
        $s18 = "Medium Gray"
        $s19 = "fsStayOnTop"
        $s20 = "TMenuMeasureItemEvent"
condition:
    uint16(0) == 0x5a4d and filesize < 751KB and
    4 of them
}
    
rule bbdcfabbdbbadfdfdfaeebfdbe_exe {
strings:
        $s1 = "PlaceCommandProcessor"
        $s2 = "008%0c%fd%ff%ff%00*%00v%2b%09(%03l%15%3f%14%16%9a%26%16-%f9%"
        $s3 = "c3%a1%d1%f6%9a%7c%d6%f9%eeP%b4%b4v%8cQ%dd%18%ca%da%a4%d9%cf%a4e%bci%ab%bf%d9%9e%"
        $s4 = "2b%09(%80S%02%3b%14%16%9a%26%16-%f9s%8b%"
        $s5 = "c0%07%bfO%d2A%fe%0c0%00vl%5b%fe%0c0%00vlXm%fe%0e%12%00+%1c%fa%ab%"
        $s6 = "set_ForegroundColor"
        $s7 = "RuntimeHelpers"
        $s8 = "a6%059%02%02%10%b4%05!%03%e6%18%bd%02!%03%ee%18%bd%02!%03%f5%18%c6%059%02%05%19%cc%059%02%0b%197%00)%02%f3%11%d4%05%19%01%88%19%ed%05Y%03%b5%19%f4%059%02%d7%19%"
        $s9 = "STAThreadAttribute"
        $s10 = "OrangeGhost"
        $s11 = "_CorExeMain"
        $s12 = "op_Equality"
        $s13 = "VarFileInfo"
        $s14 = "~#ir)ms?\"4"
        $s15 = "ProductName"
        $s16 = "DefaultMemberAttribute"
        $s17 = "PacmanSimulator"
        $s18 = "FileDescription"
        $s19 = "set_CursorVisible"
        $s20 = "02%02%8ei%17Y%91%1fpa%0b+%07%"
condition:
    uint16(0) == 0x5a4d and filesize < 811KB and
    4 of them
}
    
rule befcfebebfcdecebdfaffbccc_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "remove_PayRent"
        $s3 = "settings/upgrade/rent"
        $s4 = "getPossibleActions"
        $s5 = "STAThreadAttribute"
        $s6 = "[39u~>R_Kh)"
        $s7 = "pictureBox1"
        $s8 = "OnThisGroup"
        $s9 = "op_Equality"
        $s10 = "_CorExeMain"
        $s11 = "VarFileInfo"
        $s12 = "ProductName"
        $s13 = "XmlNodeList"
        $s14 = "DefaultMemberAttribute"
        $s15 = "set_WindowState"
        $s16 = "FileDescription"
        $s17 = "get_PositionField"
        $s18 = "TableLayoutPanel"
        $s19 = "Card_UseFreeJail"
        $s20 = "get_CreditHouses"
condition:
    uint16(0) == 0x5a4d and filesize < 417KB and
    4 of them
}
    
rule fbfbffadfdadcbffabbadcca_exe {
strings:
        $s1 = "msctls_trackbar32"
        $s2 = "TrailingTextColor"
        $s3 = "TOnGetMonthInfoEvent"
        $s4 = "OnStartDock8tC"
        $s5 = "DriveComboBox1"
        $s6 = "OnMouseWheelUp"
        $s7 = "TContextPopupEvent"
        $s8 = "LoadStringA"
        $s9 = "TBrushStyle"
        $s10 = "DockSite<jC"
        $s11 = "GetWindowDC"
        $s12 = "TOFNotifyEx"
        $s13 = "TOpenDialog"
        $s14 = "DirLabel<jC"
        $s15 = "VarFileInfo"
        $s16 = "AutoSize4~C"
        $s17 = "ProductName"
        $s18 = "fsStayOnTop"
        $s19 = "TMenuMeasureItemEvent"
        $s20 = "TMenuAnimations"
condition:
    uint16(0) == 0x5a4d and filesize < 663KB and
    4 of them
}
    
rule dacededccfacabdcabdfccccfadfa_exe {
strings:
        $s1 = "<Decodu>b__9_1"
        $s2 = "RuntymeHelpers"
        $s3 = "cymmetricAlworithm"
        $s4 = "Comf{sibleA"
        $s5 = "~t|megypxHa"
        $s6 = "Sa-DBF.XTUK"
        $s7 = "YOException"
        $s8 = "_^o}DwlXatn"
        $s9 = "VarFileInfo"
        $s10 = "ProductName"
        $s11 = "}~czrpe9dwl"
        $s12 = "set_WintowStyle"
        $s13 = "n |n WOc3mowe. "
        $s14 = "FileDescription"
        $s15 = "ELoggerEventArgsJ"
        $s16 = "lpQpplication^ame"
        $s17 = "InitializeComponent"
        $s18 = "set_RedirestStandardO"
        $s19 = "AssemblyTitleAttribute"
        $s20 = "pac{ageCount"
condition:
    uint16(0) == 0x5a4d and filesize < 338KB and
    4 of them
}
    
rule febeeeedfdeadecddaaffeec_exe {
strings:
        $s1 = "AssemblyBuilderAccess"
        $s2 = "ManagementBaseObject"
        $s3 = "FlagsAttribute"
        $s4 = "get_ModuleName"
        $s5 = "RuntimeHelpers"
        $s6 = "GetProcessesByName"
        $s7 = "PixelFormat"
        $s8 = "F&XSIHRMKAP"
        $s9 = "IOException"
        $s10 = "VarFileInfo"
        $s11 = "ProductName"
        $s12 = "IFormatProvider"
        $s13 = "FileDescription"
        $s14 = "8e0f7a12-bfb=5fe"
        $s15 = "InitializeComponent"
        $s16 = "AssemblyTitleAttribute"
        $s17 = "ImageToBytes"
        $s18 = "IEquatable`1"
        $s19 = "yToken=b77a5"
        $s20 = "DialogResult"
condition:
    uint16(0) == 0x5a4d and filesize < 321KB and
    4 of them
}
    
rule bfcddcecbcadaafdcddbbcac_exe {
strings:
        $s1 = "CazlingCo|ventio|"
        $s2 = "AssemplyBuilrerAcce"
        $s3 = "   .<securwty>"
        $s4 = "CreatsMember`efsDelsgates"
        $s5 = "Assembzy.Deleuates"
        $s6 = "__StoticArroyInitT"
        $s7 = "(.NEfFromew"
        $s8 = "\"G#StringY"
        $s9 = ".NETbramewo"
        $s10 = "Syste{.Xaml"
        $s11 = "IOExce~tion"
        $s12 = "op_Equality"
        $s13 = "_CorExsMain"
        $s14 = "VarFileInfo"
        $s15 = "QomV{sipleA"
        $s16 = "namicMsthod"
        $s17 = "CocheStrwng"
        $s18 = "A~plicatwon"
        $s19 = "_InnerSxcepti}n"
        $s20 = "GetTromRes}urce"
condition:
    uint16(0) == 0x5a4d and filesize < 462KB and
    4 of them
}
    
rule eabdebdaebdefcdbdcddcb_exe {
strings:
        $s1 = "ResolveTypeHandle"
        $s2 = "RuntimeHelpers"
        $s3 = "get_ModuleName"
        $s4 = "GetProcessesByName"
        $s5 = "STAThreadAttribute"
        $s6 = "VDLAsh.FW,P"
        $s7 = "ProductName"
        $s8 = "op_Equality"
        $s9 = "ComputeHash"
        $s10 = "_CorExeMain"
        $s11 = "VarFileInfo"
        $s12 = "MemberRefsProxy"
        $s13 = "FlushFinalBlock"
        $s14 = "FileDescription"
        $s15 = "ResolveEventArgs"
        $s16 = "lpDebugEvent"
        $s17 = "ObjectHandle"
        $s18 = "Dictionary`2"
        $s19 = "Synchronized"
        $s20 = "IAsyncResult"
condition:
    uint16(0) == 0x5a4d and filesize < 341KB and
    4 of them
}
    
rule bfbcbaceeafbfedaefedadad_exe {
strings:
        $s1 = "User Registration"
        $s2 = "TreeViewEventArgs"
        $s3 = "set_SplitterDistance"
        $s4 = "set_TransparencyKey"
        $s5 = "My.WebServices"
        $s6 = "RuntimeHelpers"
        $s7 = "System.Data.Common"
        $s8 = "Available Services"
        $s9 = "STAThreadAttribute"
        $s10 = "AuthenticationMode"
        $s11 = "DesignerGeneratedAttribute"
        $s12 = "-Lrwqtvmaop"
        $s13 = "9q>lj-b}xQP"
        $s14 = ")B\"L'(@#D+"
        $s15 = "System Info"
        $s16 = "Ynuq~JE}yp+"
        $s17 = " vq~pYI_<aZ"
        $s18 = "get_Columns"
        $s19 = "Slot Number"
        $s20 = "<zwt2-K9]WG"
condition:
    uint16(0) == 0x5a4d and filesize < 892KB and
    4 of them
}
    
rule cfafddfefedddfafbbefbafeaebafaebee_exe {
strings:
        $s1 = "get_ModuleName"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "get_Columns"
        $s5 = "L[`Kge53kJ?"
        $s6 = "_CorExeMain"
        $s7 = "VarFileInfo"
        $s8 = "ProductName"
        $s9 = "wP+Y'6W[bZ)"
        $s10 = "#o}x`!0{nT)"
        $s11 = "FileDescription"
        $s12 = "ResolveEventArgs"
        $s13 = "AssemblyTitleAttribute"
        $s14 = "Microsoft Corporation"
        $s15 = "set_TabIndex"
        $s16 = "KeyEventArgs"
        $s17 = "ColumnHeader"
        $s18 = "Dictionary`2"
        $s19 = "bGlzdFZpZXcx"
        $s20 = "Synchronized"
condition:
    uint16(0) == 0x5a4d and filesize < 430KB and
    4 of them
}
    
rule defdbbfadcffdeacd_exe {
strings:
        $s1 = "z1rqrEjxrIqjtjJRrg7"
        $s2 = "STAThreadAttribute"
        $s3 = "]q+GlAr!a(~"
        $s4 = "Rb7wOkE:n+c"
        $s5 = "_CorExeMain"
        $s6 = "VarFileInfo"
        $s7 = "ProductName"
        $s8 = "7wZ+C?3~\"#"
        $s9 = "FileDescription"
        $s10 = "QQgI44J44Nci4utkkYy"
        $s11 = "AssemblyTitleAttribute"
        $s12 = "]cp6g g?xv#("
        $s13 = "Synchronized"
        $s14 = "System.Resources"
        $s15 = "Customers.xml"
        $s16 = "customer_list"
        $s17 = "AutoScaleMode"
        $s18 = "    </application>"
        $s19 = "IiCLOHMBICBdi0XiNi"
        $s20 = "GeneratedCodeAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 589KB and
    4 of them
}
    
rule dcfddffeefeaafccddedcdbcd_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "a\":z`K{F/*"
        $s4 = "9g]Hp06L<v;"
        $s5 = "_CorExeMain"
        $s6 = "VarFileInfo"
        $s7 = "ProductName"
        $s8 = "ThreadStaticAttribute"
        $s9 = "FileDescription"
        $s10 = "GetExportedTypes"
        $s11 = "fwkbpmakwlazbzkwpwwoieejw"
        $s12 = "InitializeComponent"
        $s13 = "AssemblyTitleAttribute"
        $s14 = "Qamecaeliconezhopeli"
        $s15 = "Synchronized"
        $s16 = "IAsyncResult"
        $s17 = "System.Resources"
        $s18 = "StringBuilder"
        $s19 = "GeneratedCodeAttribute"
        $s20 = "EncryptedBytes"
condition:
    uint16(0) == 0x5a4d and filesize < 703KB and
    4 of them
}
    
rule fafcdbcfdcedbcaccfececadab_exe {
strings:
        $s1 = "SeProfileSingleProcessPrivilege"
        $s2 = "FlagsAttribute"
        $s3 = "get_ModuleName"
        $s4 = "RuntimeHelpers"
        $s5 = "SeLoadDriverPrivilege"
        $s6 = "GetProcessesByName"
        $s7 = "PixelFormat"
        $s8 = "Oz\"TJ'k)G?"
        $s9 = "op_Equality"
        $s10 = "_CorExeMain"
        $s11 = "VarFileInfo"
        $s12 = "ProductName"
        $s13 = "FileDescription"
        $s14 = "PropagationFlags"
        $s15 = "AccessControlSections"
        $s16 = "AssemblyTitleAttribute"
        $s17 = "SecurityIdentifier"
        $s18 = "GCHandleType"
        $s19 = "DialogResult"
        $s20 = "Dictionary`2"
condition:
    uint16(0) == 0x5a4d and filesize < 800KB and
    4 of them
}
    
rule bdebeebffdbfbdaaaeafecdaf_exe {
strings:
        $s1 = "Enter your choice"
        $s2 = "cross device link"
        $s3 = "GetColorProfileElement"
        $s4 = "executable format error"
        $s5 = "result out of range"
        $s6 = "directory not empty"
        $s7 = "invalid string position"
        $s8 = "FINE DAY FOR FRIENDS."
        $s9 = "operation canceled"
        $s10 = "LIES TODAY."
        $s11 = "LC_MONETARY"
        $s12 = "`local vftable'"
        $s13 = "YOU NEED SOME FUN IN LIFE."
        $s14 = "spanish-venezuela"
        $s15 = "CreateJobObjectA"
        $s16 = "SetFilePointerEx"
        $s17 = "TerminateProcess"
        $s18 = "waveOutGetVolume"
        $s19 = "GetModuleHandleW"
        $s20 = "destination address required"
condition:
    uint16(0) == 0x5a4d and filesize < 1033KB and
    4 of them
}
    
rule ceecdfcbdecacaebcfcbab_exe {
strings:
        $s1 = "ManagementBaseObject"
        $s2 = "FlagsAttribute"
        $s3 = "<Getip>b__13_0"
        $s4 = "GetSubKeyNames"
        $s5 = "RuntimeHelpers"
        $s6 = "GetProcessesByName"
        $s7 = "DownloaderFilename"
        $s8 = "get_ProcessorCount"
        $s9 = "ReadFromEmbeddedResources"
        $s10 = ",'e AWl\"tN"
        $s11 = "ComputeHash"
        $s12 = "EmailSendTo"
        $s13 = "GetWindowDC"
        $s14 = "dwMaxLength"
        $s15 = "LastIndexOf"
        $s16 = "_CorExeMain"
        $s17 = "ProductName"
        $s18 = "XmlNodeList"
        $s19 = "SerializeObject"
        $s20 = "FlushFinalBlock"
condition:
    uint16(0) == 0x5a4d and filesize < 553KB and
    4 of them
}
    
rule ecfeffcdfabbbfbfdecbcaa_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "LIuhMUi77ewcMqIwIu"
        $s4 = "_CorExeMain"
        $s5 = "VarFileInfo"
        $s6 = "ProductName"
        $s7 = "FileDescription"
        $s8 = "JBjs7smm1sh9JhawAJj"
        $s9 = "AssemblyTitleAttribute"
        $s10 = "nACCLlVivGaGXdvXCG"
        $s11 = "set_TabIndex"
        $s12 = "ColumnHeader"
        $s13 = "Dictionary`2"
        $s14 = "Synchronized"
        $s15 = "PerformClick"
        $s16 = "get_CurrentThread"
        $s17 = "System.Resources"
        $s18 = "AutoScaleMode"
        $s19 = "StringBuilder"
        $s20 = "PerformLayout"
condition:
    uint16(0) == 0x5a4d and filesize < 808KB and
    4 of them
}
    
rule eddbaceebbcbfeabccacbeeb_exe {
strings:
        $s1 = "STAThreadAttribute"
        $s2 = "ProductName"
        $s3 = "31.lSfgApat"
        $s4 = "_CorExeMain"
        $s5 = "VarFileInfo"
        $s6 = "FileDescription"
        $s7 = "eyPermissionChec"
        $s8 = "set_TabIndex"
        $s9 = "DialogResult"
        $s10 = "Synchronized"
        $s11 = "System.Resources"
        $s12 = "Invalid grade"
        $s13 = "AutoScaleMode"
        $s14 = "MethodInvoker"
        $s15 = "c06CLZZ5aNduN"
        $s16 = "GeneratedCodeAttribute"
        $s17 = "ObjectCollection"
        $s18 = "defaultInstance"
        $s19 = "ReferenceEquals"
        $s20 = "ResourceManager"
condition:
    uint16(0) == 0x5a4d and filesize < 1186KB and
    4 of them
}
    
rule edadbfabeccbbdaaabeeccdaddbc_exe {
strings:
        $s1 = "TokenizerBaseRole"
        $s2 = "AttributeExceptionAnnotation"
        $s3 = "IteratorConsumerListener"
        $s4 = "STAThreadAttribute"
        $s5 = "PushFactory"
        $s6 = "CountThread"
        $s7 = "ProductName"
        $s8 = "GotNvDsIy68"
        $s9 = "g5eQqzdmWhF"
        $s10 = "5JG6TdivLsU"
        $s11 = "wt0Q74ykEWh"
        $s12 = "_CorExeMain"
        $s13 = "VarFileInfo"
        $s14 = "UtilsSerializerLicense"
        $s15 = "ChangeAttribute"
        $s16 = "m_Specification"
        $s17 = "FileDescription"
        $s18 = "MethodReaderClass"
        $s19 = "ListenerSerializerID"
        $s20 = "Microsoft Corporation"
condition:
    uint16(0) == 0x5a4d and filesize < 1385KB and
    4 of them
}
    
rule fcfcaddaabfeccfebebaffcea_exe {
strings:
        $s1 = "VirtualAllocEx"
        $s2 = "STAThreadAttribute"
        $s3 = "sC}-QUnhP+T"
        $s4 = "op_Equality"
        $s5 = "_CorExeMain"
        $s6 = "VarFileInfo"
        $s7 = "ProductName"
        $s8 = "FileDescription"
        $s9 = "dKCnOxbbW7xx0xVWp5x"
        $s10 = "AssemblyTitleAttribute"
        $s11 = "WriteProcessMemory"
        $s12 = "Ij, \"o.118t"
        $s13 = "Synchronized"
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
    
rule aefcadacddacdffdadcefde_exe {
strings:
        $s1 = "_vsnprintf_helper"
        $s2 = "(ch != _T('\\0'))"
        $s3 = "CreateIoCompletionPort"
        $s4 = "dipemugotatumupikas"
        $s5 = "<file unknown>"
        $s6 = "omsphfoiokba`]"
        $s7 = "Runtime Error!"
        $s8 = "tufovotisuheladelo"
        $s9 = "GetConsoleOutputCP"
        $s10 = "Process32FirstW"
        $s11 = "`local vftable'"
        $s12 = "AFX_DIALOG_LAYOUT"
        $s13 = "GetModuleHandleA"
        $s14 = "TerminateProcess"
        $s15 = "SetCurrentDirectoryW"
        $s16 = "SetNamedPipeHandleState"
        $s17 = "GetConsoleCursorInfo"
        $s18 = "(((_Src))) != NULL"
        $s19 = "GetCurrentThreadId"
        $s20 = "SetLocalTime"
condition:
    uint16(0) == 0x5a4d and filesize < 388KB and
    4 of them
}
    
rule fbafbeefcfdebdcceebfbdbabd_exe {
strings:
        $s1 = "_vsnprintf_helper"
        $s2 = "(ch != _T('\\0'))"
        $s3 = "2024282T7X7\\7d>h>l>p>t>"
        $s4 = "<file unknown>"
        $s5 = "Runtime Error!"
        $s6 = "Kugutabejonu jotino toguti bige"
        $s7 = "BackupWrite"
        $s8 = "`local vftable'"
        $s9 = "legipekewoculosas"
        $s10 = "CreateJobObjectA"
        $s11 = "GetModuleHandleA"
        $s12 = "GetComputerNameA"
        $s13 = "SetCurrentDirectoryA"
        $s14 = "mepohuyolomezomixitaxo"
        $s15 = "Tikiliximum fihewev"
        $s16 = "GetConsoleCursorInfo"
        $s17 = "(((_Src))) != NULL"
        $s18 = "GetCurrentThreadId"
        $s19 = "SetLocalTime"
        $s20 = "Expression: "
condition:
    uint16(0) == 0x5a4d and filesize < 343KB and
    4 of them
}
    
rule bebbcbdaefcddbcfcaaffabdfca_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "VarFileInfo"
        $s3 = "LocalShrink"
        $s4 = "GetComputerNameW"
        $s5 = "TerminateProcess"
        $s6 = "GetModuleHandleW"
        $s7 = "GetCurrentThreadId"
        $s8 = "GetLocalTime"
        $s9 = "GetTickCount"
        $s10 = "IsBadWritePtr"
        $s11 = "WriteConsoleA"
        $s12 = "GlobalGetAtomNameW"
        $s13 = "VerifyVersionInfoA"
        $s14 = "SetHandleCount"
        $s15 = "CancelTimerQueueTimer"
        $s16 = "GetSystemTimeAsFileTime"
        $s17 = "InterlockedDecrement"
        $s18 = "SetConsoleTitleA"
        $s19 = "VirtualProtect"
        $s20 = "AreFileApisANSI"
condition:
    uint16(0) == 0x5a4d and filesize < 205KB and
    4 of them
}
    
rule aeeeecadecbdafbfcaf_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "GetConsoleProcessList"
        $s3 = "GetConsoleOutputCP"
        $s4 = "FoldStringA"
        $s5 = "VarFileInfo"
        $s6 = "TerminateProcess"
        $s7 = "GetModuleHandleW"
        $s8 = "GetComputerNameA"
        $s9 = "GetCurrentThreadId"
        $s10 = "SetEndOfFile"
        $s11 = "GetTickCount"
        $s12 = "SetHandleCount"
        $s13 = "ProjectVersion"
        $s14 = "SetFileAttributesW"
        $s15 = "GetSystemTimeAsFileTime"
        $s16 = "InterlockedDecrement"
        $s17 = "hasizodinugij"
        $s18 = "GetConsoleTitleA"
        $s19 = "VirtualProtect"
        $s20 = "GetProcessHeap"
condition:
    uint16(0) == 0x5a4d and filesize < 289KB and
    4 of them
}
    
rule feadddeddaeebdfcabdbbddbaaa_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "GetConsoleProcessList"
        $s3 = "GetConsoleOutputCP"
        $s4 = "VarFileInfo"
        $s5 = "GetComputerNameW"
        $s6 = "TerminateProcess"
        $s7 = "JDF:DOOOK>;:@PN5"
        $s8 = "GetModuleHandleW"
        $s9 = "GetCurrentThreadId"
        $s10 = "GetTickCount"
        $s11 = "bomgveoci.iwa"
        $s12 = "C:\\xetel.pdb"
        $s13 = "VpTTRQPPMHHLHLHSw,"
        $s14 = "SetHandleCount"
        $s15 = "ProjectVersion"
        $s16 = "GetSystemTimeAsFileTime"
        $s17 = "InterlockedDecrement"
        $s18 = "GetConsoleTitleW"
        $s19 = ")',857\"75 107"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 356KB and
    4 of them
}
    
rule debcaeccadabdadbfdcebd_exe {
strings:
        $s1 = "TInterfacedPersistent"
        $s2 = "EVariantBadVarTypeError"
        $s3 = " 2001, 2002 Mike Lischke"
        $s4 = "ckRunningOrNew"
        $s5 = "CoInitializeEx"
        $s6 = "OnMouseWheelUp"
        $s7 = "Database Login"
        $s8 = "TWinControlActionLink"
        $s9 = "CoCreateInstanceEx"
        $s10 = "TContextPopupEvent"
        $s11 = "TabsPerRowH"
        $s12 = "Window Text"
        $s13 = "LoadStringA"
        $s14 = "TBrushStyle"
        $s15 = "TStringDesc"
        $s16 = "GetWindowDC"
        $s17 = "TBoundLabel"
        $s18 = "TOleGraphic"
        $s19 = "TDragObject"
        $s20 = "Medium Gray"
condition:
    uint16(0) == 0x5a4d and filesize < 651KB and
    4 of them
}
    
rule ddedbaddeacafacdadebfadca_exe {
strings:
        $s1 = "TInterfacedPersistent"
        $s2 = "TSilentPaintPanelX,C"
        $s3 = " 2001, 2002 Mike Lischke"
        $s4 = "CoInitializeEx"
        $s5 = "CoCreateInstanceEx"
        $s6 = "TMSDOMNamedNodeMap"
        $s7 = "TContextPopupEvent"
        $s8 = "Window Text"
        $s9 = "LoadStringA"
        $s10 = "MaxWidth`zC"
        $s11 = "TBrushStyle"
        $s12 = "GetWindowDC"
        $s13 = "TOFNotifyEx"
        $s14 = "DragKind yC"
        $s15 = "TDragObject"
        $s16 = "Interval|VA"
        $s17 = "Medium Gray"
        $s18 = "fsStayOnTop"
        $s19 = "TMenuMeasureItemEvent"
        $s20 = "TMenuAnimations"
condition:
    uint16(0) == 0x5a4d and filesize < 632KB and
    4 of them
}
    
rule debfccfeabfcdaefadadb_ps {
strings:
        $s1 = "    # open logger file in Notepad"
        $s2 = "          # get keyboard state for virtual keys"
        $s3 = "  # create output file"
        $s4 = "        if ($state -eq -32767) {"
        $s5 = "Start-KeyLogger"
        $s6 = "          # translate virtual key"
        $s7 = "          # translate scan code to real code"
        $s8 = "        # get current key state"
        $s9 = "            # add key to logger file"
        $s10 = "        # is key pressed?"
        $s11 = "    $Runner = 0"
        $s12 = "$RunTimeP = 1                       # Time in minutes"
        $s13 = "          if ($success) "
        $s14 = "  finally"
        $s15 = "exit 1"
        $s16 = "          {"
        $s17 = "############################"
        $s18 = "  try"
        $s19 = "    }"
condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    4 of them
}
    
rule deefbfdecfebcfdaddbcacbe_ps {
strings:
        $s1 = "echo 'Running on %%x'"
        $s2 = "GOTO processargs"
        $s3 = "if !ERRORLEVEL! == 0 ("
        $s4 = "IF \"%FLAG%\"==\"-\" ("
        $s5 = "SET ARG=%1"
        $s6 = "IF DEFINED ARG ("
        $s7 = "EXIT /B 1"
        $s8 = "@echo off"
        $s9 = "GOTO :EOF"
        $s10 = ":android"
        $s11 = ":windows"
        $s12 = ") else ("
        $s13 = ":linux"
        $s14 = "SHIFT"
condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    4 of them
}
    
rule aeecefffecafcabbebbaf_ps {
strings:

condition:
    uint16(0) == 0x5a4d and filesize < 8KB and
    4 of them
}
    
rule ddefbafcecbfacffafbaf_exe {
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
        $s14 = "GetFolderPath"
        $s15 = "SpecialFolder"
        $s16 = "CompareMethod"
        $s17 = "StringBuilder"
        $s18 = "DirectoryInfo"
        $s19 = "GetWindowText"
        $s20 = "GeneratedCodeAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 35KB and
    4 of them
}
    
rule cbcecbfbcdfefcaffdadddb_exe {
strings:
        $s1 = "get_ModuleName"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "k\"a:&v<$!."
        $s5 = "_CorExeMain"
        $s6 = "VarFileInfo"
        $s7 = "ProductName"
        $s8 = "FileDescription"
        $s9 = "QmpxdmNwc2Jwbw=="
        $s10 = "UGZnbG16ZmpzZw=="
        $s11 = "ResolveEventArgs"
        $s12 = "nme6RDg0mwgq3X3ee0m"
        $s13 = "AssemblyTitleAttribute"
        $s14 = "Tmp4YXl3amQ="
        $s15 = "QWtidWJyenM="
        $s16 = "RGFwZ210bQ=="
        $s17 = "Tnh4eXB6dHBl"
        $s18 = "VHJpdWNkcGd0"
        $s19 = "Wmh2bnBoZw=="
        $s20 = "RmhtZG1xaw=="
condition:
    uint16(0) == 0x5a4d and filesize < 646KB and
    4 of them
}
    
rule deabdaeebefdeaadccccace_exe {
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
        $s14 = "GetFolderPath"
        $s15 = "SpecialFolder"
        $s16 = "CompareMethod"
        $s17 = "StringBuilder"
        $s18 = "DirectoryInfo"
        $s19 = "GetWindowText"
        $s20 = "GeneratedCodeAttribute"
condition:
    uint16(0) == 0x5a4d and filesize < 35KB and
    4 of them
}
    
rule dcbddcbbfceffcbbaefefaeebabeafffcc_exe {
strings:
        $s1 = "VK_MEDIA_PREV_TRACK"
        $s2 = "?456789:;<="
        $s3 = "VK_LAUNCH_MAIL"
        $s4 = "\\rundll32.exe"
        $s5 = "VK_VOLUME_DOWN"
        $s6 = "VK_BROWSER_STOP"
        $s7 = "VK_NUMPAD9"
        $s8 = "VK_DECIMAL"
        $s9 = "displayName"
        $s10 = "VK_SUBTRACT"
        $s11 = "VK_MULTIPLY"
        $s12 = "M'/^G$A3uuI"
        $s13 = "VK_SNAPSHOT"
        $s14 = "VK_SEPARATOR"
        $s15 = "Advapi32.dll"
        $s16 = "SerialNumber"
        $s17 = "VK_BROWSER_REFRESH"
        $s18 = "oleaut32.dll"
        $s19 = "user32.dll"
        $s20 = "VK_MBUTTON"
condition:
    uint16(0) == 0x5a4d and filesize < 57KB and
    4 of them
}
    
rule fcccbbbedbcbcbeeebcfa_exe {
strings:
        $s1 = "F6 NDSPak:l"
        $s2 = "O|1CdbP3Z>t"
        $s3 = "ZESPMBW_r7K"
        $s4 = "1CSV86A2cqx"
        $s5 = "RMzLmyFGs6;"
        $s6 = "paR~n2\"|Ok"
        $s7 = "9UNemHOEfGx"
        $s8 = "GetConsoleWindow"
        $s9 = "R6d36UekOEKl"
        $s10 = "ElIAVv9gqA9w2"
        $s11 = "acmStreamClose"
        $s12 = "ImmDestroyIMCC"
        $s13 = "GetDeviceCaps"
        $s14 = "VirtualProtect"
        $s15 = "rXLo8q537D"
        $s16 = ":rB]E`)4QW"
        $s17 = "P{/@(#S}AW"
        $s18 = "\"Of>ym=El"
        $s19 = "2)zn%4~Y3="
        $s20 = "kB\"'7645E"
condition:
    uint16(0) == 0x5a4d and filesize < 503KB and
    4 of them
}
    
rule cabcaeadfdaeefcefedae_exe {
strings:
        $s1 = "Runtime Error!"
        $s2 = "O6`{1 oPRv4"
        $s3 = "V,o3 H4\"i+"
        $s4 = "{1MgKNJesQk"
        $s5 = "9eiImAV:J+("
        $s6 = "-YQ0?>\"JEV"
        $s7 = "waveOutSetVolume"
        $s8 = "TerminateProcess"
        $s9 = "GetModuleHandleW"
        $s10 = "GetCurrentThreadId"
        $s11 = "PathGetArgsW"
        $s12 = "GetTickCount"
        $s13 = "WNetCancelConnectionA"
        $s14 = "StringFromIID"
        $s15 = "SetHandleCount"
        $s16 = "DeleteCriticalSection"
        $s17 = "GetSystemTimeAsFileTime"
        $s18 = "InterlockedDecrement"
        $s19 = "GetDeviceCaps"
        $s20 = "VirtualProtect"
condition:
    uint16(0) == 0x5a4d and filesize < 1880KB and
    4 of them
}
    
rule daddedfbcfaabbefceddeeccfadc_exe {
strings:
        $s1 = "Transferred from (A/C no. )        : "
        $s2 = "+jom94Tw~/1"
        $s3 = "del LOG.DAT"
        $s4 = "rJp<aY-|0e>"
        $s5 = "GetModuleHandleA"
        $s6 = "A/C type <S/F>  : "
        $s7 = "Enter first name : "
        $s8 = "Total Balance   : %s"
        $s9 = "SetConsoleCursorPosition"
        $s10 = "CertGetCRLContextProperty"
        $s11 = "Transfered+to+"
        $s12 = "Received+from+"
        $s13 = "BANK MANAGEMENT SYSTEM"
        $s14 = ">~xLdD4%Q8"
        $s15 = "#\"_V1Lk9<"
        $s16 = "%X'+_.#)\""
        $s17 = "TMEkCXy(NF"
        $s18 = "A9ynwDK6aM"
        $s19 = "Do LK{5O2m"
        $s20 = "Page : %d out of %d"
condition:
    uint16(0) == 0x5a4d and filesize < 495KB and
    4 of them
}
    
rule dfcfacabafbfeafacaeec_exe {
strings:
        $s1 = "2kv*g<7iaqW"
        $s2 = "ld\";TQ2&w="
        $s3 = "ac'J$D&(FQl"
        $s4 = "G<\"|EB8oX "
        $s5 = "Q/Kwgz|8XyV"
        $s6 = "g0m\"j-LCK^"
        $s7 = "C Z\"j}z?tN"
        $s8 = "QwAjn?=O$qt"
        $s9 = "ZwlDrK(TkGL"
        $s10 = "X^KFW\"pU.b"
        $s11 = ">X<itj(hRK_"
        $s12 = "BfZ^I 2q'YT"
        $s13 = "7AEp3!<}(L|"
        $s14 = "`j\"8sB9-aE"
        $s15 = "jI$!V%\"dKf"
        $s16 = "8Wu2 #_0L'/"
        $s17 = "ReadProcessMemory"
        $s18 = "GetModuleHandleA"
        $s19 = "|EHeOG=e/lqW"
        $s20 = "bG[URe/C=euT"
condition:
    uint16(0) == 0x5a4d and filesize < 4994KB and
    4 of them
}
    
rule ecbcbfefcaecdebbcfaeed_exe {
strings:
        $s1 = ",;<ZqPn8ht'"
        $s2 = "w(9TD_@S75#"
        $s3 = "RDiy9GI1n\""
        $s4 = "A\"6,=K5d4O"
        $s5 = "v D_AFM;c]m"
        $s6 = "F= co-V3BfW"
        $s7 = "V9y#68mt+J`"
        $s8 = "t=3kd[\"G92"
        $s9 = "D /hQ1xvM5K"
        $s10 = "!}a]Ypg$W\""
        $s11 = "L/d$|g)4VH9"
        $s12 = "Gu*QRc-@Nhj"
        $s13 = "ReadProcessMemory"
        $s14 = "GetModuleHandleA"
        $s15 = "e-p&OH#,H%VA"
        $s16 = "1`KzvM~k\\$-"
        $s17 = "bpI\\xqN.;]L"
        $s18 = "Qx8V3NDVO1\""
        $s19 = "5~pMTi\\?nK#"
        $s20 = "WTSAPI32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 5008KB and
    4 of them
}
    
rule feeaaeaeeedfbcacdbacbcecddf_exe {
strings:
        $s1 = "Palatino Linotype"
        $s2 = "Add Selected File(s)"
        $s3 = "RegSetValueExA"
        $s4 = "28C4C820-401A-101B-A3C9-08002B2F49FB"
        $s5 = "__vbaLateMemCallLd"
        $s6 = "Save Archive As..."
        $s7 = "InsertByVal"
        $s8 = "|H)g]?M7x-J"
        $s9 = "EncryptFile"
        $s10 = "Version 5.2"
        $s11 = "TA|hofjband"
        $s12 = "VarFileInfo"
        $s13 = "5/>_v7RBUGW"
        $s14 = "File is Protected"
        $s15 = "GetComputerNameA"
        $s16 = "lblCopyright"
        $s17 = "Module32Next"
        $s18 = "Archiver 5.0"
        $s19 = "__vbaR8FixI4"
        $s20 = "__vbaPowerR8"
condition:
    uint16(0) == 0x5a4d and filesize < 742KB and
    4 of them
}
    
rule cbcecbfbcdfefcaffdadddb_exe {
strings:
        $s1 = "get_ModuleName"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "k\"a:&v<$!."
        $s5 = "_CorExeMain"
        $s6 = "VarFileInfo"
        $s7 = "ProductName"
        $s8 = "FileDescription"
        $s9 = "QmpxdmNwc2Jwbw=="
        $s10 = "UGZnbG16ZmpzZw=="
        $s11 = "ResolveEventArgs"
        $s12 = "nme6RDg0mwgq3X3ee0m"
        $s13 = "AssemblyTitleAttribute"
        $s14 = "Tmp4YXl3amQ="
        $s15 = "QWtidWJyenM="
        $s16 = "RGFwZ210bQ=="
        $s17 = "Tnh4eXB6dHBl"
        $s18 = "VHJpdWNkcGd0"
        $s19 = "Wmh2bnBoZw=="
        $s20 = "RmhtZG1xaw=="
condition:
    uint16(0) == 0x5a4d and filesize < 646KB and
    4 of them
}
    
rule dcbddcbbfceffcbbaefefaeebabeafffcc_exe {
strings:
        $s1 = "VK_MEDIA_PREV_TRACK"
        $s2 = "?456789:;<="
        $s3 = "VK_LAUNCH_MAIL"
        $s4 = "\\rundll32.exe"
        $s5 = "VK_VOLUME_DOWN"
        $s6 = "VK_BROWSER_STOP"
        $s7 = "VK_NUMPAD9"
        $s8 = "VK_DECIMAL"
        $s9 = "displayName"
        $s10 = "VK_SUBTRACT"
        $s11 = "VK_MULTIPLY"
        $s12 = "M'/^G$A3uuI"
        $s13 = "VK_SNAPSHOT"
        $s14 = "VK_SEPARATOR"
        $s15 = "Advapi32.dll"
        $s16 = "SerialNumber"
        $s17 = "VK_BROWSER_REFRESH"
        $s18 = "oleaut32.dll"
        $s19 = "user32.dll"
        $s20 = "VK_MBUTTON"
condition:
    uint16(0) == 0x5a4d and filesize < 57KB and
    4 of them
}
    