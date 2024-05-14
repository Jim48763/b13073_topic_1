rule ebeedcebcccecfabfaffafabecffacadc_exe {
strings:
        $s1 = "deallocating None"
        $s2 = "s*|z:ascii_decode"
        $s3 = "PyDescr_NewMember"
        $s4 = "mon_decimal_point"
        $s5 = "method_descriptor"
        $s6 = "Py_SetProgramName"
        $s7 = "/4h7fpep#FapbpC4T"
        $s8 = "_PyTime_FloatTime"
        $s9 = "OSztuGCWdE|t}t{tC"
        $s10 = "PyType_GenericNew"
        $s11 = "S|z:escape_encode"
        $s12 = "Os|ii:DeleteKeyEx"
        $s13 = "PyErr_ProgramText"
        $s14 = "can't assign sys.argv"
        $s15 = "empty, returns start."
        $s16 = "The error setting of the decoder or encoder."
        $s17 = "9U:_:i:D;T;q;W=g=z="
        $s18 = "lllii|i:DuplicateHandle"
        $s19 = "can't concat %.100s to %.100s"
        $s20 = "can only join an iterable"
condition:
    uint16(0) == 0x5a4d and filesize < 2605KB and
    4 of them
}
    
