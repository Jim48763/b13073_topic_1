rule dfdebfacfdbbbaeaacfefbfa_exe {
strings:
        $s1 = "StartAddressOfRawData"
        $s2 = "SizeOfInitializedData"
        $s3 = "IMAGE_DATA_DIRECTORY"
        $s4 = "RuntimeHelpers"
        $s5 = "GetMachineType"
        $s6 = "RuntimeFieldHandle"
        $s7 = "ProductName"
        $s8 = "op_Equality"
        $s9 = "VarFileInfo"
        $s10 = "ExportTable"
        $s11 = "SizeOfBlock"
        $s12 = "FileDescription"
        $s13 = "PhysicalAddress"
        $s14 = "PointerToRawData"
        $s15 = "FixedBufferAttribute"
        $s16 = "Unable to get managed delegate."
        $s17 = "SectionFinalizeData"
        $s18 = "Dll is not initialized."
        $s19 = "_isRelocated"
        $s20 = "GCHandleType"
condition:
    uint16(0) == 0x5a4d and filesize < 29KB and
    4 of them
}
    
