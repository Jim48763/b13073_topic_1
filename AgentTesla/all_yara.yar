import pe
rule cefabdafbbcaeefdeafecbfafde_exe {
strings:
        $s1 = "$0086e4fb-e603-4c03-bef6-fd8b6e700367"
        $s2 = "RuntimeHelpers"
        $s3 = ", \"a8.XOM6"
        $s4 = "K7P;T=]a#[V"
        $s5 = "_CorExeMain"
        $s6 = "ProductName"
        $s7 = "+Lgb6Pqza@_"
        $s8 = "VarFileInfo"
        $s9 = "FileDescription"
        $s10 = "FlushFinalBlock"
        $s11 = "get_IsBrowserHosted"
        $s12 = "SecurityCriticalAttribute"
        $s13 = "Synchronized"
        $s14 = "IAsyncResult"
        $s15 = "']aeCKr#\\O$"
        $s16 = "Durbanville1"
        $s17 = "BBd',N^R}_ %"
        $s18 = "StringBuilder"
        $s19 = "GeneratedCodeAttribute"
        $s20 = "System.Security"
condition:
    uint16(0) == 0x5a4d and filesize < 813KB and
    4 of them
}
    
rule dacebfafaafdeaacbccbcebcdea_exe {
strings:
        $s1 = "english-caribbean"
        $s2 = "spanish-guatemala"
        $s3 = "`vector destructor iterator'"
        $s4 = "invalid string position"
        $s5 = "ios_base::failbit set"
        $s6 = "GetConsoleOutputCP"
        $s7 = "6\"bh>nB*~N"
        $s8 = "LC_MONETARY"
        $s9 = "PrintDlgExW"
        $s10 = "english-jamaica"
        $s11 = "mixerGetNumDevs"
        $s12 = "`local vftable'"
        $s13 = "SetupFindNextLine"
        $s14 = "spanish-venezuela"
        $s15 = "TerminateProcess"
        $s16 = "GetModuleHandleW"
        $s17 = "EnterCriticalSection"
        $s18 = "=sDrZrcFEK*X"
        $s19 = "south-africa"
        $s20 = "COMDLG32.dll"
condition:
    uint16(0) == 0x5a4d and filesize < 416KB and
    4 of them
}
    
rule bacbdebfcaeebaacfbccacaceebaea_exe {
strings:
        $s1 = "ysYjjUzz]vvS^^kaa"
        $s2 = "underlineTopToolStrip"
        $s3 = "Do you want to save?"
        $s4 = "textBoxDescription"
        $s5 = "STAThreadAttribute"
        $s6 = "op_Equality"
        $s7 = "_CorExeMain"
        $s8 = "Version {0}"
        $s9 = "2lf,>mgqM;B"
        $s10 = "get_Company"
        $s11 = "First Name:"
        $s12 = "VarFileInfo"
        $s13 = "DFB.ko]'ce1"
        $s14 = "set_MinimizeBox"
        $s15 = "Open Text Files"
        $s16 = "tableLayoutPanel1"
        $s17 = "set_ShortcutKeys"
        $s18 = "add_SelectedIndexChanged"
        $s19 = "get_FlatAppearance"
        $s20 = "set_ReadOnly"
condition:
    uint16(0) == 0x5a4d and filesize < 500KB and
    4 of them
}
    
rule deebbecefefabaedadecfedaeaaeceb_exe {
strings:
        $s1 = "ysYjjUzz]vvS^^kaa"
        $s2 = "underlineTopToolStrip"
        $s3 = "Do you want to save?"
        $s4 = "textBoxDescription"
        $s5 = "STAThreadAttribute"
        $s6 = "eAH24O1>CpF"
        $s7 = "op_Equality"
        $s8 = "_CorExeMain"
        $s9 = "mZF*D{PB%!+"
        $s10 = "Version {0}"
        $s11 = "get_Company"
        $s12 = ",Ve{f6\"+ws"
        $s13 = "l\"{n<&qx/G"
        $s14 = "First Name:"
        $s15 = "VarFileInfo"
        $s16 = "set_MinimizeBox"
        $s17 = "Open Text Files"
        $s18 = "tableLayoutPanel1"
        $s19 = "set_ShortcutKeys"
        $s20 = "add_SelectedIndexChanged"
condition:
    uint16(0) == 0x5a4d and filesize < 504KB and
    4 of them
}
    
rule eadaebfadadacdafbfcfec_exe {
strings:
        $s1 = "RuntimeHelpers"
        $s2 = "STAThreadAttribute"
        $s3 = "op_Equality"
        $s4 = "_CorExeMain"
        $s5 = "ProductName"
        $s6 = "VarFileInfo"
        $s7 = "FileDescription"
        $s8 = "get_ProcessName"
        $s9 = "DealerLimitExceeded"
        $s10 = "Synchronized"
        $s11 = "set_TabIndex"
        $s12 = "GraphicsUnit"
        $s13 = "DialogResult"
        $s14 = "GetHINSTANCE"
        $s15 = "ShowFullHand"
        $s16 = "OutputDebugString"
        $s17 = "get_CurrentThread"
        $s18 = "System.Resources"
        $s19 = "AutoScaleMode"
        $s20 = "PerformLayout"
condition:
    uint16(0) == 0x5a4d and filesize < 479KB and
    4 of them
}
    