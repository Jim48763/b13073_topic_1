rule aabcefcafbfccbdeaccbccbbcf_exe {
strings:
        $s1 = "`vector destructor iterator'"
        $s2 = "Runtime Error!"
        $s3 = "GetConsoleOutputCP"
        $s4 = "< <$<(<,<0<4<8<<<@<D<H<L<P<T<X<\\<`<d<h<l<\\>`>h>l>p>t>"
        $s5 = "J&s]|Lc}/F8"
        $s6 = "VarFileInfo"
        $s7 = "`local vftable'"
        $s8 = "AFX_DIALOG_LAYOUT"
        $s9 = "TerminateProcess"
        $s10 = "GetModuleHandleW"
        $s11 = "GetCurrentThreadId"
        $s12 = "WriteProcessMemory"
        $s13 = "&lhaVW?$t8p8"
        $s14 = "GetTickCount"
        $s15 = "Zoh cegobires"
        $s16 = "Z0.24292?2F2X2@3Q3l3v3"
        $s17 = "Unknown exception"
        $s18 = "SetHandleCount"
        $s19 = "`udt returning'"
        $s20 = "GetSystemTimeAsFileTime"
condition:
    uint16(0) == 0x5a4d and filesize < 696KB and
    4 of them
}
    
