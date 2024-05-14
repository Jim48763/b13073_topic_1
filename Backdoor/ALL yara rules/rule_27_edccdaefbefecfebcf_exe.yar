rule edccdaefbefecfebcf_exe {
strings:
        $s1 = "System.Data.OleDb"
        $s2 = "ratingComboBox"
        $s3 = "RuntimeHelpers"
        $s4 = "VideoGameForm_Load"
        $s5 = "STAThreadAttribute"
        $s6 = "DesignerGeneratedAttribute"
        $s7 = "IOException"
        $s8 = "MsgBoxStyle"
        $s9 = "=20R-@<z#?h"
        $s10 = "get_Columns"
        $s11 = "ProductName"
        $s12 = "+7Z mTN5a8,"
        $s13 = "F6Z %(g^a8X"
        $s14 = "_CorExeMain"
        $s15 = "Ta4;Uz&+w`{"
        $s16 = "VarFileInfo"
        $s17 = "q5Z }0>Ia8!"
        $s18 = "\"zBE;m30jo"
        $s19 = "op_Equality"
        $s20 = "mflgIsDirty"
condition:
    uint16(0) == 0x5a4d and filesize < 1899KB and
    4 of them
}
    
