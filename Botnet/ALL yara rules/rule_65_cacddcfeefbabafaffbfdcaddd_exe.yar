rule cacddcfeefbabafaffbfdcaddd_exe {
strings:
        $s1 = "RegistryAuditRule"
        $s2 = "_explicitTextTags"
        $s3 = "GeneralizedTime6@"
        $s4 = "get_ShowHexViewer"
        $s5 = "ShowNodeContentEditor"
        $s6 = "This may take a while"
        $s7 = "add_SelectedItemChanged"
        $s8 = "FileSystemAccessRule"
        $s9 = "Original idea: Liping Dai"
        $s10 = "XamlGeneratedNamespace"
        $s11 = "mTag    : {0} (0x{0:X2}) : {1}"
        $s12 = "BooleanToVisibility"
        $s13 = "Open data converter"
        $s14 = "IsVirtualizing"
        $s15 = "get_Chanceries"
        $s16 = "RuntimeHelpers"
        $s17 = "RelativeSource"
        $s18 = "DataSourceProperty"
        $s19 = "MarshalAsAttribute"
        $s20 = "ApplyPropertyValue"
condition:
    uint16(0) == 0x5a4d and filesize < 344KB and
    4 of them
}
    
