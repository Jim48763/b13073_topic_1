rule cebafcfecbaecdeddfedffad_exe {
strings:
        $s1 = "clInactiveCaption"
        $s2 = "GetKeyboardLayout"
        $s3 = "TSpinSpeedButtons"
        $s4 = "TrailingTextColor"
        $s5 = "RightClickSelect8"
        $s6 = "PositionGapColorT"
        $s7 = "CoAddRefServerProcess"
        $s8 = "TInterfacedPersistent"
        $s9 = "TCancelledChangeEvent"
        $s10 = "StatusStrings.NotStarted"
        $s11 = "Cannot assign object to "
        $s12 = "'%s' is not a valid date"
        $s13 = "TTodoItemSelectEvent"
        $s14 = "TDragOverHeaderEvent"
        $s15 = "TPersistenceLocation"
        $s16 = "Cannot get the format enumerator"
        $s17 = "8-848K8R8i8F:+;7;D;V;\\;l;|;"
        $s18 = "TPlannerDataBinding"
        $s19 = "EditOnSelectedClick"
        $s20 = "End game strategies"
condition:
    uint16(0) == 0x5a4d and filesize < 2853KB and
    4 of them
}
    
