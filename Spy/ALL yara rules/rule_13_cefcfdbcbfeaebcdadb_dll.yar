rule cefcfdbcbfeaebcdadb_dll {
strings:
        $s1 = "CreateResFmtHelp'"
        $s2 = "ControlInterface,"
        $s3 = "GetKeyboardLayout"
        $s4 = "FCreatingMainForm"
        $s5 = "FRecreateChildren"
        $s6 = "FAlignControlList"
        $s7 = "StaticSynchronize"
        $s8 = "TMeasureItemEvent"
        $s9 = "EJclRegistryError"
        $s10 = "twMDISysButtonHot"
        $s11 = "MouseWheelHandler"
        $s12 = "TPacketAttribute "
        $s13 = "TJvPaletteChangeEvent"
        $s14 = "FInternalOpenComplete"
        $s15 = "comboBoxUnidadeMedida"
        $s16 = "tspMoreProgramsArrowHot"
        $s17 = "thHeaderItemRightHot"
        $s18 = "tbCheckBoxCheckedHot"
        $s19 = "FInternalPopupParent"
        $s20 = "Generics.Collections"
condition:
    uint16(0) == 0x5a4d and filesize < 2686KB and
    4 of them
}
    