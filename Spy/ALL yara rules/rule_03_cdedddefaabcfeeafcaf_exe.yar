rule cdedddefaabcfeeafcaf_exe {
strings:
        $s1 = "Palatino Linotype"
        $s2 = "please Enter Leave Type"
        $s3 = "fnComboLoadTxt"
        $s4 = "RegSetValueExA"
        $s5 = "ReportFileName"
        $s6 = "fnRecordsetOpennew"
        $s7 = "ProductName"
        $s8 = "|H)g]?M7x-J"
        $s9 = "InsertByVal"
        $s10 = "VarFileInfo"
        $s11 = "mnusoftware"
        $s12 = "5/>_v7RBUGW"
        $s13 = "__vbaLateIdCallSt"
        $s14 = "__vbaVarLateMemSt"
        $s15 = "No | Month |Days"
        $s16 = "GetComputerNameA"
        $s17 = "Module32Next"
        $s18 = "MSFLXGRD.OCX"
        $s19 = "mntrRGB XYZ "
        $s20 = "__vbaLenBstr"
condition:
    uint16(0) == 0x5a4d and filesize < 820KB and
    4 of them
}
    
