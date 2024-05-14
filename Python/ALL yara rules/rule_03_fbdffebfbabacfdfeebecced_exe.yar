rule fbdffebfbabacfdfeebecced_exe {
strings:
        $s1 = "              set through the setsampwidth() or setparams() method"
        $s2 = "        this function one or more times, before using"
        $s3 = "        Clear the cache for all loggers in loggerDict"
        $s4 = "        the second is not the last triple in the list, then i+n != i' or"
        $s5 = "   is used in the interactive interpreter to store the result of the"
        $s6 = "uVoidPointer_cffi.__init__"
        $s7 = "      0 - user site directory is enabled"
        $s8 = "    Returns an Element instance."
        $s9 = "z!_SafeQueue._on_queue_feeder_error)"
        $s10 = "          <marker ID> (2 bytes, must be > 0)"
        $s11 = "sqlite3_str_value"
        $s12 = "ApplyResult._set)"
        $s13 = "uCfbMode.__init__"
        $s14 = "_parse_optionalr$"
        $s15 = "doModuleCleanups`"
        $s16 = "mon_decimal_point"
        $s17 = "uIncorrect length"
        $s18 = "-yscrollincrement"
        $s19 = "WeakSet.__isub__c"
        $s20 = "PyType_GenericNew"
condition:
    uint16(0) == 0x5a4d and filesize < 26394KB and
    4 of them
}
    
