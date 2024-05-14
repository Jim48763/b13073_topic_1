rule beebcbfebdadaaebbccabbcf_exe {
strings:
        $s1 = "AutoPropertyValue"
        $s2 = "Defensive rebound"
        $s3 = "SetDataGridDesign"
        $s4 = "Change chart type"
        $s5 = "Btn_AddParameters"
        $s6 = "set_Panel_Display"
        $s7 = "set_Btn_BasicInfo"
        $s8 = "TreeViewEventArgs"
        $s9 = "XmlSchemaParticle"
        $s10 = "Show me teams leaders"
        $s11 = "Move to add or update player"
        $s12 = "Choose help language"
        $s13 = "ToolboxItemAttribute"
        $s14 = "CheckPlayersParameters"
        $s15 = "CollectionChangeAction"
        $s16 = "Total PG In Hapoel Holon"
        $s17 = "Lbl_WhatManage"
        $s18 = "RuntimeHelpers"
        $s19 = "set_FixedValue"
        $s20 = "Btn_MouseLeave"
condition:
    uint16(0) == 0x5a4d and filesize < 1468KB and
    4 of them
}
    
