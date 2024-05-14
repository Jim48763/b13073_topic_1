rule faadfaceacabbfddcdecc_exe {
strings:
        $s1 = "ManagementBaseObject"
        $s2 = "RuntimeHelpers"
        $s3 = "STAThreadAttribute"
        $s4 = "RuntimeFieldHandle"
        $s5 = "VolumeSerialNumber"
        $s6 = "System.Linq"
        $s7 = "ProductName"
        $s8 = "VarFileInfo"
        $s9 = "_CorExeMain"
        $s10 = "GetVolumeSerial"
        $s11 = "IFormatProvider"
        $s12 = "FileDescription"
        $s13 = "position:fixed;"
        $s14 = "get_MachineName"
        $s15 = "Start_Encryption"
        $s16 = " -Sheets, Etc). "
        $s17 = "        font-weight: bold;"
        $s18 = "      ICON='msiexec.exe'"
        $s19 = "InitializeComponent"
        $s20 = "Synchronized"
condition:
    uint16(0) == 0x5a4d and filesize < 32KB and
    4 of them
}
    
