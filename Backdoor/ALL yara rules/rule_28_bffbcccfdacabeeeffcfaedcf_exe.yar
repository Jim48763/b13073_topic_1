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
    
