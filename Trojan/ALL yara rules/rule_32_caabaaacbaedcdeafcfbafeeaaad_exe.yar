rule caabaaacbaedcdeafcfbafeeaaad_exe {
strings:
        $s1 = "IllFormedPassword"
        $s2 = "set_Impersonation"
        $s3 = "ManagementBaseObject"
        $s4 = "SuspendCountExceeded"
        $s5 = "ES_DISPLAY_REQUIRED"
        $s6 = "TxfAttributeCorrupt"
        $s7 = "dllhost.g.resources"
        $s8 = "EnterDebugMode"
        $s9 = "RuntimeHelpers"
        $s10 = "$this.GridSize"
        $s11 = "UnableToFreeVm"
        $s12 = "FlagsAttribute"
        $s13 = "FileCheckedOut"
        $s14 = "Install_Folder"
        $s15 = "set_ReceiveBufferSize"
        $s16 = "TransactionalConflict"
        $s17 = "InsufficientResources"
        $s18 = "Ot8cclCIlfL3nl3TOT"
        $s19 = "RuntimeFieldHandle"
        $s20 = "oCikTyCoNnJ1T1HUnT"
condition:
    uint16(0) == 0x5a4d and filesize < 199KB and
    4 of them
}
    
