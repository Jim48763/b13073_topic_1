rule cbdcaddddeacbfebdaedae_exe {
strings:
        $s1 = "set_InsertCommand"
        $s2 = "System.Data.OleDb"
        $s3 = "You have selected"
        $s4 = "IsDestinationNull"
        $s5 = "AutoPropertyValue"
        $s6 = "get_UpdateCommand"
        $s7 = "XmlSchemaParticle"
        $s8 = "columnPhoneNumber"
        $s9 = "ToolboxItemAttribute"
        $s10 = "get__Short_Long_Dist"
        $s11 = "Original_Destination"
        $s12 = "CollectionChangeAction"
        $s13 = "get_ClearBeforeFill"
        $s14 = "IsNull_Availability"
        $s15 = "TableAdapterManager"
        $s16 = "RuntimeHelpers"
        $s17 = "set_FixedValue"
        $s18 = "Reccobtn_Click"
        $s19 = "My.WebServices"
        $s20 = "InitCommandCollection"
condition:
    uint16(0) == 0x5a4d and filesize < 911KB and
    4 of them
}
    
