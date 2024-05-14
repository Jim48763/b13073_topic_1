rule beefedeebbddacdaccefccbdbc_exe {
strings:
        $s1 = "set_MainMenuStrip"
        $s2 = "LogoPictureBox"
        $s3 = "RuntimeHelpers"
        $s4 = "My.WebServices"
        $s5 = "InternalPartitionEnumerator"
        $s6 = "passwordAdministrator"
        $s7 = "System.Data.Common"
        $s8 = "STAThreadAttribute"
        $s9 = "AuthenticationMode"
        $s10 = "DesignerGeneratedAttribute"
        $s11 = "My.Computer"
        $s12 = "PictureBox1"
        $s13 = "_CorExeMain"
        $s14 = "Version {0}"
        $s15 = "VarFileInfo"
        $s16 = "ThreadStaticAttribute"
        $s17 = "ExecuteNonQuery"
        $s18 = "set_MinimizeBox"
        $s19 = "FileDescription"
        $s20 = ";Initial Catalog="
condition:
    uint16(0) == 0x5a4d and filesize < 630KB and
    4 of them
}
    
