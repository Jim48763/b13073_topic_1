rule aabccbbdeebdacfbfccafbeebbcbefcc_exe {
strings:
        $s1 = "rectangleAsString"
        $s2 = "StartInFullscreen"
        $s3 = "GetFileLineNumber"
        $s4 = "DefaultResolution"
        $s5 = "ContentLoaderResolver"
        $s6 = "GenerateTriggerFromType"
        $s7 = "dAgGAnBQaAIHA5BAcA8GADBAbAEGAnBQZAwEABAgEAgE"
        $s8 = "ResolveContentLoader"
        $s9 = "GetInterpolatedValue"
        $s10 = "FieldOffsetAttribute"
        $s11 = "EnqueueWorkerThread"
        $s12 = "DoesNotMatchMetaDataType"
        $s13 = "RuntimeHelpers"
        $s14 = "AppDomainSetup"
        $s15 = "ContentNameMissing"
        $s16 = "RuntimeFieldHandle"
        $s17 = "CreateLookAtMatrix"
        $s18 = "QZA0GAhBgTAQHAjBQdAQGAvBgc"
        $s19 = "AtlasRegion"
        $s20 = "_CorExeMain"
condition:
    uint16(0) == 0x5a4d and filesize < 859KB and
    4 of them
}
    
