rule faeebbbfbdaebfacea_exe {
strings:
        $s1 = "<==>;<<A;<<A677B-..j)**"
        $s2 = "Type not supported"
        $s3 = "LastIndexOf"
        $s4 = "System.Linq"
        $s5 = "op_Equality"
        $s6 = "_CorExeMain"
        $s7 = "VarFileInfo"
        $s8 = "FileDescription"
        $s9 = "expressionCache"
        $s10 = "IFormatProvider"
        $s11 = "ResetableLazy`1"
        $s12 = "IterationResult"
        $s13 = "OrderByDescending"
        $s14 = "DebuggerHiddenAttribute"
        $s15 = "ConstantExpression"
        $s16 = "nXf@[{hzHn`v"
        $s17 = "IfHasElement"
        $s18 = "NumberStyles"
        $s19 = "valueFactory"
        $s20 = "GetRuntimeMethod"
condition:
    uint16(0) == 0x5a4d and filesize < 671KB and
    4 of them
}
    
