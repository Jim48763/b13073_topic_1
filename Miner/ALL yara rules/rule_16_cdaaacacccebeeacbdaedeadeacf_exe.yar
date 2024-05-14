rule cdaaacacccebeeacbdaedeadeacf_exe {
strings:
        $s1 = "Ep5/892446978580125789244697858012578924469785801257892adn"
        $s2 = "D<@1A;M=L0L1I1M8L<H1"
        $s3 = "78580Aa57(9244697:58012578924469"
        $s4 = "URL=\"file:///"
        $s5 = "n{?J1Jpm&G3JyR"
        $s6 = "NtResumeThread"
        $s7 = "RegSetValueExW"
        $s8 = ";u;q2p6t;}1q7p:p;};y2x6"
        $s9 = "l086450?=07>1=<;=8=>4=0'="
        $s10 = "!!\"..\"%&-%*&* )+m\""
        $s11 = "NtGetContextThread"
        $s12 = "vd{w?Y5p3R>"
        $s13 = "UqF=Qwtm,9P"
        $s14 = "+\"Dzt2(|j="
        $s15 = "kY0W:n7R6i!"
        $s16 = "fGt]48M>u<E"
        $s17 = "?^m<[IG1E0O"
        $s18 = "U#'6y$@OvQN"
        $s19 = "exdwtsq|azh"
        $s20 = "v3dE4ciCeZX"
condition:
    uint16(0) == 0x5a4d and filesize < 1862KB and
    4 of them
}
    