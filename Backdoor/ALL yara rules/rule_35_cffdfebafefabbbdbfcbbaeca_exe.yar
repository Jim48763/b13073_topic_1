rule cffdfebafefabbbdbfcbbaeca_exe {
strings:
        $s1 = "NUMBER_OF_SQUARES"
        $s2 = "btnStart_Click"
        $s3 = "STAThreadAttribute"
        $s4 = "ProductName"
        $s5 = "ShipDestroy"
        $s6 = "btnOK_Click"
        $s7 = "get_Crimson"
        $s8 = ".<5p|cfF?!^"
        $s9 = "VarFileInfo"
        $s10 = "_CorExeMain"
        $s11 = "KeyEventHandler"
        $s12 = "FileDescription"
        $s13 = "IFormatProvider"
        $s14 = "Division by Zero"
        $s15 = "GetImageFromFile"
        $s16 = " When an operator is read"
        $s17 = "InitializeComponent"
        $s18 = "KeyboardCtrl"
        $s19 = "Synchronized"
        $s20 = "IAsyncResult"
condition:
    uint16(0) == 0x5a4d and filesize < 233KB and
    4 of them
}
    
