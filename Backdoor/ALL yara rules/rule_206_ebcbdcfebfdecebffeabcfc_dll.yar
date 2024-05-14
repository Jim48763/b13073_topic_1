rule ebcbdcfebfdecebffeabcfc_dll {
strings:
        $s1 = "XmlSchemaParticle"
        $s2 = "set_MainMenuStrip"
        $s3 = "GetSchemaSerializable"
        $s4 = "set_membersTableAdapter"
        $s5 = "ToolboxItemAttribute"
        $s6 = "TableAdapterManager"
        $s7 = "e579x5OzA5O5WZOpye1"
        $s8 = "FlagsAttribute"
        $s9 = "$this.GridSize"
        $s10 = "set_FixedValue"
        $s11 = "RuntimeHelpers"
        $s12 = "GetTypedDataSetSchema"
        $s13 = "System.Data.Common"
        $s14 = "STAThreadAttribute"
        $s15 = "V+zv5Dx,ou&"
        $s16 = "op_Equality"
        $s17 = "ComputeHash"
        $s18 = "get_Columns"
        $s19 = "ProductName"
        $s20 = "VarFileInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 690KB and
    4 of them
}
    
