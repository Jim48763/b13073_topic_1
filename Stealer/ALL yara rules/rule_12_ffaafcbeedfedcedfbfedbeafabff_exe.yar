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
    
