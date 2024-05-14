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
    
