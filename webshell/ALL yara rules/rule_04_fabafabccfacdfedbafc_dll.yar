rule fabafabccfacdfedbafc_dll {
strings:
        $s1 = "::Windows Version"
        $s2 = "RuntimeHelpers"
        $s3 = "set_ReceiveBufferSize"
        $s4 = "lpVolumeNameBuffer"
        $s5 = "PixelFormat"
        $s6 = "ProductName"
        $s7 = "SocketFlags"
        $s8 = "op_Equality"
        $s9 = "VarFileInfo"
        $s10 = "ComputeHash"
        $s11 = "LastIndexOf"
        $s12 = "set_ErrorDialog"
        $s13 = "FileDescription"
        $s14 = "get_MachineName"
        $s15 = "get_ServicePack"
        $s16 = "nVolumeNameSize"
        $s17 = "lpFileSystemFlags"
        $s18 = "::Check UAC Level"
        $s19 = "Synchronized"
        $s20 = "ComputerInfo"
condition:
    uint16(0) == 0x5a4d and filesize < 49KB and
    4 of them
}
    