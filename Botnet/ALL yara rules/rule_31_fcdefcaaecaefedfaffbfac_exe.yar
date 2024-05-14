rule fcdefcaaecaefedfaffbfac_exe {
strings:
        $s1 = "$this.GridSize"
        $s2 = "RuntimeHelpers"
        $s3 = "JPEG (*.JPG)|*.JPG|GIF (*.GIF)|*.GIF"
        $s4 = "Form1_KeyDown_Down"
        $s5 = "STAThreadAttribute"
        $s6 = "Form1_Paint"
        $s7 = "op_Equality"
        $s8 = "_CorExeMain"
        $s9 = "ProductName"
        $s10 = "F,E{\"gOBY("
        $s11 = "VarFileInfo"
        $s12 = "FileDescription"
        $s13 = "KeyEventHandler"
        $s14 = "frmCDAddon_Load"
        $s15 = "optionalCalendars"
        $s16 = "CheckForCollision"
        $s17 = "m_currentEraValue"
        $s18 = "customCultureName"
        $s19 = "GetExportedTypes"
        $s20 = "ObjectIdentifier"
condition:
    uint16(0) == 0x5a4d and filesize < 366KB and
    4 of them
}
    
