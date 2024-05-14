rule edadbfabeccbbdaaabeeccdaddbc_exe {
strings:
        $s1 = "TokenizerBaseRole"
        $s2 = "AttributeExceptionAnnotation"
        $s3 = "IteratorConsumerListener"
        $s4 = "STAThreadAttribute"
        $s5 = "PushFactory"
        $s6 = "CountThread"
        $s7 = "ProductName"
        $s8 = "GotNvDsIy68"
        $s9 = "g5eQqzdmWhF"
        $s10 = "5JG6TdivLsU"
        $s11 = "wt0Q74ykEWh"
        $s12 = "_CorExeMain"
        $s13 = "VarFileInfo"
        $s14 = "UtilsSerializerLicense"
        $s15 = "ChangeAttribute"
        $s16 = "m_Specification"
        $s17 = "FileDescription"
        $s18 = "MethodReaderClass"
        $s19 = "ListenerSerializerID"
        $s20 = "Microsoft Corporation"
condition:
    uint16(0) == 0x5a4d and filesize < 1385KB and
    4 of them
}
    
