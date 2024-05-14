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
    
