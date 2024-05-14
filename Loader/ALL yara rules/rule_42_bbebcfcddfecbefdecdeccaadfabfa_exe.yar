rule bbebcfcddfecbefdecdeccaadfabfa_exe {
strings:
        $s1 = "ToBase64Transform"
        $s2 = "REMISIONES - FILTRO"
        $s3 = "Clientes x Contrato"
        $s4 = "RuntimeHelpers"
        $s5 = "FrmAbonos_Load"
        $s6 = "get_txtUsuario"
        $s7 = "get_txtHoraIni"
        $s8 = "ControlBindingsCollection"
        $s9 = "AuthenticationMode"
        $s10 = "SerializationEntry"
        $s11 = "STAThreadAttribute"
        $s12 = "System.Data.Common"
        $s13 = "DesignerGeneratedAttribute"
        $s14 = "ProductName"
        $s15 = "eGT>pVU[\"$"
        $s16 = "dgvVehiculo"
        $s17 = "My.Computer"
        $s18 = "_CorExeMain"
        $s19 = "ComputeHash"
        $s20 = "F}dL|tq0U8s"
condition:
    uint16(0) == 0x5a4d and filesize < 1314KB and
    4 of them
}
    
