rule eddaccceebefbfdcdffadebe_exe {
strings:
        $s1 = "VirtualAllocEx"
        $s2 = "RtlNtStatusToDosError"
        $s3 = "4%7!&,2( :>"
        $s4 = "ke,hvf{}*)Q"
        $s5 = "lmkYpeckmvx}k.-"
        $s6 = "GetModuleHandleA"
        $s7 = "WriteProcessMemory"
        $s8 = "$>9#2\"8~;21"
        $s9 = "<_\\uKSWUj[h"
        $s10 = "wine_get_unix_file_name"
        $s11 = "SuspendThread"
        $s12 = ":089/xsv1&:?s"
        $s13 = "3!;% w75*>;9%"
        $s14 = "=y>)?-?1?5?9?=?A?E?I?M?Q?U?Y?]?a?e?i?m?q?u?y?}?"
        $s15 = "SeSecurityPrivilege"
        $s16 = "NtCreateThreadEx"
        $s17 = "IsWow64Process"
        $s18 = "iick}mTijklods"
        $s19 = "GetProcessHeap"
        $s20 = "iz~ttq}zb2pqsgq"
condition:
    uint16(0) == 0x5a4d and filesize < 103KB and
    4 of them
}
    
