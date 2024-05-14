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
    
