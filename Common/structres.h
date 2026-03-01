#pragma once
#include <windows.h>

#define PROCESSOR_FEATURE_MAX 64


static constexpr DWORD CV_SIGNATURE_RSDS = 'SDSR';
static constexpr DWORD CV_SIGNATURE_NB10 = '01BN';


struct UnwindCode {
    BYTE offset;
    BYTE op      : 4;
    BYTE op_info : 4;
};

struct UnwindInfo {
    BYTE       version      : 3;
    BYTE       flags        : 5;
    BYTE       prolog;
    BYTE       code_cnt;
    BYTE       frame_reg    : 4;
    BYTE       frame_offset : 4;
    UnwindCode codes[1];
};

enum class UwOp : BYTE {
    PushNonvol    = 0,
    AllocLarge    = 1,
    AllocSmall    = 2,
    SetFpReg      = 3,
    SaveNonvol    = 4,
    SaveNonvolFar = 5,
    SaveXmm128    = 8,
    SaveXmm128Far = 9,
    PushMachframe = 10,
};

static constexpr BYTE  k_chain_flag    = 0x04;
static constexpr ULONG k_machframe     = 0x28;
static constexpr ULONG k_machframe_err = 0x30;


struct _STRING64_2
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    ULONGLONG Buffer;                                                       //0x8
};

struct _UNICODE_STRING_2
{
    USHORT Length;                                                          //0x0
    USHORT MaximumLength;                                                   //0x2
    WCHAR* Buffer;                                                          //0x8
}; 


struct _CLIENT_ID64
{
    ULONGLONG UniqueProcess;                                                //0x0
    ULONGLONG UniqueThread;                                                 //0x8
}; 
struct _TEB64
{
    struct _NT_TIB64 NtTib;                                                 //0x0
    ULONGLONG EnvironmentPointer;                                           //0x38
    _CLIENT_ID64 client_id;												    //0x40   
    ULONGLONG ActiveRpcHandle;                                              //0x50
    ULONGLONG ThreadLocalStoragePointer;                                    //0x58
    ULONGLONG ProcessEnvironmentBlock;                                      //0x60
    ULONG LastErrorValue;                                                   //0x68
    ULONG CountOfOwnedCriticalSections;                                     //0x6c
    ULONGLONG CsrClientThread;                                              //0x70
    ULONGLONG Win32ThreadInfo;                                              //0x78
    ULONG User32Reserved[26];                                               //0x80
    ULONG UserReserved[5];                                                  //0xe8
    ULONGLONG WOW32Reserved;                                                //0x100
    ULONG CurrentLocale;                                                    //0x108
    ULONG FpSoftwareStatusRegister;                                         //0x10c
    ULONGLONG ReservedForDebuggerInstrumentation[16];                       //0x110
    ULONGLONG SystemReserved1[25];                                          //0x190
    ULONGLONG HeapFlsData;                                                  //0x258
    ULONGLONG RngState[4];                                                  //0x260
    CHAR PlaceholderCompatibilityMode;                                      //0x280
    UCHAR PlaceholderHydrationAlwaysExplicit;                               //0x281
    CHAR PlaceholderReserved[10];                                           //0x282
    ULONG ProxiedProcessId;                                                 //0x28c

    BYTE padding[40];

    UCHAR WorkingOnBehalfTicket[8];                                         //0x2b8
    LONG ExceptionCode;                                                     //0x2c0
    UCHAR Padding0[4];                                                      //0x2c4
    ULONGLONG ActivationContextStackPointer;                                //0x2c8
    ULONGLONG InstrumentationCallbackSp;                                    //0x2d0
    ULONGLONG InstrumentationCallbackPreviousPc;                            //0x2d8
    ULONGLONG InstrumentationCallbackPreviousSp;                            //0x2e0
    ULONG TxFsContext;                                                      //0x2e8
    UCHAR InstrumentationCallbackDisabled;                                  //0x2ec
    UCHAR UnalignedLoadStoreExceptions;                                     //0x2ed
    UCHAR Padding1[2];                                                      //0x2ee
    BYTE padding2[1272];
    ULONGLONG GdiCachedProcessHandle;                                       //0x7e8
    ULONG GdiClientPID;                                                     //0x7f0
    ULONG GdiClientTID;                                                     //0x7f4
    ULONGLONG GdiThreadLocalInfo;                                           //0x7f8
    ULONGLONG Win32ClientInfo[62];                                          //0x800
    ULONGLONG glDispatchTable[233];                                         //0x9f0
    ULONGLONG glReserved1[29];                                              //0x1138
    ULONGLONG glReserved2;                                                  //0x1220
    ULONGLONG glSectionInfo;                                                //0x1228
    ULONGLONG glSection;                                                    //0x1230
    ULONGLONG glTable;                                                      //0x1238
    ULONGLONG glCurrentRC;                                                  //0x1240
    ULONGLONG glContext;                                                    //0x1248
    ULONG LastStatusValue;                                                  //0x1250
    UCHAR Padding2[4];                                                      //0x1254
    struct _STRING64_2 StaticUnicodeString;                                   //0x1258
    WCHAR StaticUnicodeBuffer[261];                                         //0x1268
    UCHAR Padding3[6];                                                      //0x1472
    ULONGLONG DeallocationStack;                                            //0x1478
    ULONGLONG TlsSlots[64];                                                 //0x1480
    struct LIST_ENTRY64 TlsLinks;                                           //0x1680
    ULONGLONG Vdm;                                                          //0x1690
    ULONGLONG ReservedForNtRpc;                                             //0x1698
    ULONGLONG DbgSsReserved[2];                                             //0x16a0
    ULONG HardErrorMode;                                                    //0x16b0
    UCHAR Padding4[4];                                                      //0x16b4
    ULONGLONG Instrumentation[11];                                          //0x16b8
    struct _GUID ActivityId;                                                //0x1710
    ULONGLONG SubProcessTag;                                                //0x1720
    ULONGLONG PerflibData;                                                  //0x1728
    ULONGLONG EtwTraceData;                                                 //0x1730
    ULONGLONG WinSockData;                                                  //0x1738
    ULONG GdiBatchCount;                                                    //0x1740
    union
    {
        struct _PROCESSOR_NUMBER CurrentIdealProcessor;                     //0x1744
        ULONG IdealProcessorValue;                                          //0x1744
        struct
        {
            UCHAR ReservedPad0;                                             //0x1744
            UCHAR ReservedPad1;                                             //0x1745
            UCHAR ReservedPad2;                                             //0x1746
            UCHAR IdealProcessor;                                           //0x1747
        };
    };
    ULONG GuaranteedStackBytes;                                             //0x1748
    UCHAR Padding5[4];                                                      //0x174c
    ULONGLONG ReservedForPerf;                                              //0x1750
    ULONGLONG ReservedForOle;                                               //0x1758
    ULONG WaitingOnLoaderLock;                                              //0x1760
    UCHAR Padding6[4];                                                      //0x1764
    ULONGLONG SavedPriorityState;                                           //0x1768
    ULONGLONG ReservedForCodeCoverage;                                      //0x1770
    ULONGLONG ThreadPoolData;                                               //0x1778
    ULONGLONG TlsExpansionSlots;                                            //0x1780
    ULONGLONG ChpeV2CpuAreaInfo;                                            //0x1788
    ULONGLONG Unused;                                                       //0x1790
    ULONG MuiGeneration;                                                    //0x1798
    ULONG IsImpersonating;                                                  //0x179c
    ULONGLONG NlsCache;                                                     //0x17a0
    ULONGLONG pShimData;                                                    //0x17a8
    ULONG HeapData;                                                         //0x17b0
    UCHAR Padding7[4];                                                      //0x17b4
    ULONGLONG CurrentTransactionHandle;                                     //0x17b8
    ULONGLONG ActiveFrame;                                                  //0x17c0
    ULONGLONG FlsData;                                                      //0x17c8
    ULONGLONG PreferredLanguages;                                           //0x17d0
    ULONGLONG UserPrefLanguages;                                            //0x17d8
    ULONGLONG MergedPrefLanguages;                                          //0x17e0
    ULONG MuiImpersonation;                                                 //0x17e8
    union
    {
        volatile USHORT CrossTebFlags;                                      //0x17ec
        USHORT SpareCrossTebBits : 16;                                        //0x17ec
    };
    union
    {
        USHORT SameTebFlags;                                                //0x17ee
        struct
        {
            USHORT SafeThunkCall : 1;                                         //0x17ee
            USHORT InDebugPrint : 1;                                          //0x17ee
            USHORT HasFiberData : 1;                                          //0x17ee
            USHORT SkipThreadAttach : 1;                                      //0x17ee
            USHORT WerInShipAssertCode : 1;                                   //0x17ee
            USHORT RanProcessInit : 1;                                        //0x17ee
            USHORT ClonedThread : 1;                                          //0x17ee
            USHORT SuppressDebugMsg : 1;                                      //0x17ee
            USHORT DisableUserStackWalk : 1;                                  //0x17ee
            USHORT RtlExceptionAttached : 1;                                  //0x17ee
            USHORT InitialThread : 1;                                         //0x17ee
            USHORT SessionAware : 1;                                          //0x17ee
            USHORT LoadOwner : 1;                                             //0x17ee
            USHORT LoaderWorker : 1;                                          //0x17ee
            USHORT SkipLoaderInit : 1;                                        //0x17ee
            USHORT SkipFileAPIBrokering : 1;                                  //0x17ee
        };
    };
    ULONGLONG TxnScopeEnterCallback;                                        //0x17f0
    ULONGLONG TxnScopeExitCallback;                                         //0x17f8
    ULONGLONG TxnScopeContext;                                              //0x1800
    ULONG LockCount;                                                        //0x1808
    LONG WowTebOffset;                                                      //0x180c
    ULONGLONG ResourceRetValue;                                             //0x1810
    ULONGLONG ReservedForWdf;                                               //0x1818
    ULONGLONG ReservedForCrt;                                               //0x1820
    struct _GUID EffectiveContainerId;                                      //0x1828
    ULONGLONG LastSleepCounter;                                             //0x1838
    ULONG SpinCallCount;                                                    //0x1840
    UCHAR Padding8[4];                                                      //0x1844
    ULONGLONG ExtendedFeatureDisableMask;                                   //0x1848
    ULONGLONG SchedulerSharedDataSlot;                                      //0x1850
    ULONGLONG HeapWalkContext;                                              //0x1858
    struct _GROUP_AFFINITY64 PrimaryGroupAffinity;                          //0x1860
    ULONG Rcu[2];                                                           //0x1870
};


struct _PEB64_2
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    UCHAR BitField;                                                     //0x3
    UCHAR Padding0[4];                                                      //0x4
    ULONGLONG Mutant;                                                       //0x8
    ULONGLONG ImageBaseAddress;                                             //0x10
    ULONGLONG Ldr;                                                          //0x18
    ULONGLONG ProcessParameters;                                            //0x20
    ULONGLONG SubSystemData;                                                //0x28
    ULONGLONG ProcessHeap;                                                  //0x30
    ULONGLONG FastPebLock;                                                  //0x38
    ULONGLONG AtlThunkSListPtr;                                             //0x40
    ULONGLONG IFEOKey;                                                      //0x48
    ULONG CrossProcessFlags;                                            //0x50
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        ULONGLONG KernelCallbackTable;                                      //0x58
        ULONGLONG UserSharedInfoPtr;                                        //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    ULONGLONG ApiSetMap;                                                    //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    ULONGLONG TlsBitmap;                                                    //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    ULONGLONG ReadOnlySharedMemoryBase;                                     //0x88
    ULONGLONG SharedData;                                                   //0x90
    ULONGLONG ReadOnlyStaticServerData;                                     //0x98
    ULONGLONG AnsiCodePageData;                                             //0xa0
    ULONGLONG OemCodePageData;                                              //0xa8
    ULONGLONG UnicodeCaseTableData;                                         //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    ULONGLONG ProcessHeaps;                                                 //0xf0
    ULONGLONG GdiSharedHandleTable;                                         //0xf8
    ULONGLONG ProcessStarterHelper;                                         //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    ULONGLONG LoaderLock;                                                   //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    UCHAR Padding4[4];                                                      //0x134
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    ULONGLONG PostProcessInitRoutine;                                       //0x230
    ULONGLONG TlsExpansionBitmap;                                           //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    ULONGLONG pShimData;                                                    //0x2d8
    ULONGLONG AppCompatInfo;                                                //0x2e0
    struct _STRING64_2 CSDVersion;                                            //0x2e8
    ULONGLONG ActivationContextData;                                        //0x2f8
    ULONGLONG ProcessAssemblyStorageMap;                                    //0x300
    ULONGLONG SystemDefaultActivationContextData;                           //0x308
    ULONGLONG SystemAssemblyStorageMap;                                     //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    ULONGLONG SparePointers[2];                                             //0x320
    ULONGLONG PatchLoaderData;                                              //0x330
    ULONGLONG ChpeV2ProcessInfo;                                            //0x338
    ULONG AppModelFeatureState;                                             //0x340
    ULONG SpareUlongs[2];                                                   //0x344
    USHORT ActiveCodePage;                                                  //0x34c
    USHORT OemCodePage;                                                     //0x34e
    USHORT UseCaseMapping;                                                  //0x350
    USHORT UnusedNlsField;                                                  //0x352
    ULONGLONG WerRegistrationData;                                          //0x358
    ULONGLONG WerShipAssertPtr;                                             //0x360
    ULONGLONG EcCodeBitMap;                                                 //0x368
    ULONGLONG pImageHeaderHash;                                             //0x370
    ULONG TracingFlags;                                                 //0x378
    UCHAR Padding6[4];                                                      //0x37c
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
    ULONGLONG TppWorkerpListLock;                                           //0x388
    struct LIST_ENTRY64 TppWorkerpList;                                     //0x390
    ULONGLONG WaitOnAddressHashTable[128];                                  //0x3a0
    ULONGLONG TelemetryCoverageHeader;                                      //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    ULONGLONG LeapSecondData;                                               //0x7b8
    ULONG LeapSecondFlags;                                              //0x7c0
    ULONG NtGlobalFlag2;                                                    //0x7c4
    ULONGLONG ExtendedFeatureDisableMask;                                   //0x7c8
};


struct _PEB_LDR_DATA_2
{
    ULONG Length;                                                           //0x0
    UCHAR Initialized;                                                      //0x4
    VOID* SsHandle;                                                         //0x8
    struct _LIST_ENTRY InLoadOrderModuleList;                               //0x10
    struct _LIST_ENTRY InMemoryOrderModuleList;                             //0x20
    struct _LIST_ENTRY InInitializationOrderModuleList;                     //0x30
    VOID* EntryInProgress;                                                  //0x40
    UCHAR ShutdownInProgress;                                               //0x48
    VOID* ShutdownThreadId;                                                 //0x50
};

//0x138 bytes (sizeof)
struct _LDR_DATA_TABLE_ENTRY_2
{
    struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
    struct _LIST_ENTRY InMemoryOrderLinks;                                  //0x10
    struct _LIST_ENTRY InInitializationOrderLinks;                          //0x20
    VOID* DllBase;                                                          //0x30
    VOID* EntryPoint;                                                       //0x38
    ULONG SizeOfImage;                                                      //0x40
    struct _UNICODE_STRING_2 FullDllName;                                     //0x48
    struct _UNICODE_STRING_2 BaseDllName;                                     //0x58                                  //0x68
    ULONG Flags;                                                        //0x68
    USHORT ObsoleteLoadCount;                                               //0x6c
    USHORT TlsIndex;                                                        //0x6e
    struct _LIST_ENTRY HashLinks;                                           //0x70
    ULONG TimeDateStamp;                                                    //0x80
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;                //0x88
    VOID* Lock;                                                             //0x90
    struct _LDR_DDAG_NODE* DdagNode;                                        //0x98
    struct _LIST_ENTRY NodeModuleLink;                                      //0xa0
    struct _LDRP_LOAD_CONTEXT* LoadContext;                                 //0xb0
    VOID* ParentDllBase;                                                    //0xb8
    VOID* SwitchBackContext;                                                //0xc0
    BYTE padding1[24];        
    BYTE padding2[24];                       
    ULONGLONG OriginalBase;                                                 //0xf8
    union _LARGE_INTEGER LoadTime;                                          //0x100
    ULONG BaseNameHashValue;                                                //0x108
    enum _LDR_DLL_LOAD_REASON LoadReason;                                   //0x10c
    ULONG ImplicitPathOptions;                                              //0x110
    ULONG ReferenceCount;                                                   //0x114
    ULONG DependentLoadFlags;                                               //0x118
    UCHAR SigningLevel;                                                     //0x11c
    ULONG CheckSum;                                                         //0x120
    VOID* ActivePatchImageBase;                                             //0x128
    enum _LDR_HOT_PATCH_STATE HotPatchState;                                //0x130
};


enum class LdrLoadReason : ULONG{
    LDR_DLL_NOTIFICATION_REASON_LOADED = 1,
    LDR_DLL_NOTIFICATION_REASON_UNLOADED = 2

};


typedef struct _LDR_DLL_UNLOADED_NOTIFICATION_DATA {
    ULONG Flags;
    _UNICODE_STRING_2* FullDllName;
    _UNICODE_STRING_2* BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_UNLOADED_NOTIFICATION_DATA, *PLDR_DLL_UNLOADED_NOTIFICATION_DATA;

typedef struct _LDR_DLL_LOADED_NOTIFICATION_DATA {
    ULONG Flags;
    _UNICODE_STRING_2* FullDllName;
    _UNICODE_STRING_2* BaseDllName;
    PVOID DllBase;
    ULONG SizeOfImage;
} LDR_DLL_LOADED_NOTIFICATION_DATA, *PLDR_DLL_LOADED_NOTIFICATION_DATA;

typedef union _LDR_DLL_NOTIFICATION_DATA {
    LDR_DLL_LOADED_NOTIFICATION_DATA Loaded;
    LDR_DLL_UNLOADED_NOTIFICATION_DATA Unloaded;
} LDR_DLL_NOTIFICATION_DATA, *PLDR_DLL_NOTIFICATION_DATA;

using LdrDllNotification_t = VOID (CALLBACK)(
    _In_     ULONG                      NotificationReason,
    _In_     LDR_DLL_NOTIFICATION_DATA* NotificationData,
    _In_opt_ PVOID                      Context
);

using LdrRegisterDllNotification_t = NTSTATUS (NTAPI)(
    _In_     ULONG                  Flags,
    _In_     LdrDllNotification_t*  NotificationFunction,
    _In_opt_ PVOID                  Context,
    _Out_    PVOID*                 Cookie
);


typedef struct _KSYSTEM_TIME
{
     ULONG LowPart;
     LONG High1Time;
     LONG High2Time;
} KSYSTEM_TIME, *PKSYSTEM_TIME;

typedef enum _NT_PRODUCT_TYPE
{
         NtProductWinNt = 1,
         NtProductLanManNt = 2,
         NtProductServer = 3
} NT_PRODUCT_TYPE;

typedef enum _ALTERNATIVE_ARCHITECTURE_TYPE
{
         StandardDesign = 0,
         NEC98x86 = 1,
         EndAlternatives = 2
} ALTERNATIVE_ARCHITECTURE_TYPE;

typedef struct _KUSER_SHARED_DATA {
  ULONG                         TickCountLowDeprecated;
  ULONG                         TickCountMultiplier;
  KSYSTEM_TIME                  InterruptTime;
  KSYSTEM_TIME                  SystemTime;
  KSYSTEM_TIME                  TimeZoneBias;
  USHORT                        ImageNumberLow;
  USHORT                        ImageNumberHigh;
  WCHAR                         NtSystemRoot[260];
  ULONG                         MaxStackTraceDepth;
  ULONG                         CryptoExponent;
  ULONG                         TimeZoneId;
  ULONG                         LargePageMinimum;
  ULONG                         AitSamplingValue;
  ULONG                         AppCompatFlag;
  ULONGLONG                     RNGSeedVersion;
  ULONG                         GlobalValidationRunlevel;
  LONG                          TimeZoneBiasStamp;
  ULONG                         NtBuildNumber;
  NT_PRODUCT_TYPE               NtProductType;
  BOOLEAN                       ProductTypeIsValid;
  BOOLEAN                       Reserved0[1];
  USHORT                        NativeProcessorArchitecture;
  ULONG                         NtMajorVersion;
  ULONG                         NtMinorVersion;
  BOOLEAN                       ProcessorFeatures[PROCESSOR_FEATURE_MAX];
  ULONG                         Reserved1;
  ULONG                         Reserved3;
  ULONG                         TimeSlip;
  ALTERNATIVE_ARCHITECTURE_TYPE AlternativeArchitecture;
  ULONG                         BootId;
  LARGE_INTEGER                 SystemExpirationDate;
  ULONG                         SuiteMask;
  BOOLEAN                       KdDebuggerEnabled;
  union {
    UCHAR MitigationPolicies;
    struct {
      UCHAR NXSupportPolicy : 2;
      UCHAR SEHValidationPolicy : 2;
      UCHAR CurDirDevicesSkippedForDlls : 2;
      UCHAR Reserved : 2;
    };
  };
  USHORT                        CyclesPerYield;
  ULONG                         ActiveConsoleId;
  ULONG                         DismountCount;
  ULONG                         ComPlusPackage;
  ULONG                         LastSystemRITEventTickCount;
  ULONG                         NumberOfPhysicalPages;
  BOOLEAN                       SafeBootMode;
  union {
    UCHAR VirtualizationFlags;
    struct {
      UCHAR ArchStartedInEl2 : 1;
      UCHAR QcSlIsSupported : 1;
    };
  };
  UCHAR                         Reserved12[2];
  union {
    ULONG SharedDataFlags;
    struct {
      ULONG DbgErrorPortPresent : 1;
      ULONG DbgElevationEnabled : 1;
      ULONG DbgVirtEnabled : 1;
      ULONG DbgInstallerDetectEnabled : 1;
      ULONG DbgLkgEnabled : 1;
      ULONG DbgDynProcessorEnabled : 1;
      ULONG DbgConsoleBrokerEnabled : 1;
      ULONG DbgSecureBootEnabled : 1;
      ULONG DbgMultiSessionSku : 1;
      ULONG DbgMultiUsersInSessionSku : 1;
      ULONG DbgStateSeparationEnabled : 1;
      ULONG SpareBits : 21;
    } DUMMYSTRUCTNAME2;
  } DUMMYUNIONNAME2;
  ULONG                         DataFlagsPad[1];
  ULONGLONG                     TestRetInstruction;
  LONGLONG                      QpcFrequency;
  ULONG                         SystemCall;
  ULONG                         Reserved2;
  ULONGLONG                     FullNumberOfPhysicalPages;
  ULONGLONG                     SystemCallPad[1];
  union {
    KSYSTEM_TIME TickCount;
    ULONG64      TickCountQuad;
    struct {
      ULONG ReservedTickCountOverlay[3];
      ULONG TickCountPad[1];
    } DUMMYSTRUCTNAME;
  } DUMMYUNIONNAME3;
  ULONG                         Cookie;
  ULONG                         CookiePad[1];
  LONGLONG                      ConsoleSessionForegroundProcessId;
  ULONGLONG                     TimeUpdateLock;
  ULONGLONG                     BaselineSystemTimeQpc;
  ULONGLONG                     BaselineInterruptTimeQpc;
  ULONGLONG                     QpcSystemTimeIncrement;
  ULONGLONG                     QpcInterruptTimeIncrement;
  UCHAR                         QpcSystemTimeIncrementShift;
  UCHAR                         QpcInterruptTimeIncrementShift;
  USHORT                        UnparkedProcessorCount;
  ULONG                         EnclaveFeatureMask[4];
  ULONG                         TelemetryCoverageRound;
  USHORT                        UserModeGlobalLogger[16];
  ULONG                         ImageFileExecutionOptions;
  ULONG                         LangGenerationCount;
  ULONGLONG                     Reserved4;
  ULONGLONG                     InterruptTimeBias;
  ULONGLONG                     QpcBias;
  ULONG                         ActiveProcessorCount;
  UCHAR                         ActiveGroupCount;
  UCHAR                         Reserved9;
  union {
    USHORT QpcData;
    struct {
      UCHAR QpcBypassEnabled;
      UCHAR QpcReserved;
    };
  };
  LARGE_INTEGER                 TimeZoneBiasEffectiveStart;
  LARGE_INTEGER                 TimeZoneBiasEffectiveEnd;
  XSTATE_CONFIGURATION          XState;
  KSYSTEM_TIME                  FeatureConfigurationChangeStamp;
  ULONG                         Spare;
  ULONG64                       UserPointerAuthMask;
  XSTATE_CONFIGURATION          XStateArm64;
  ULONG                         Reserved10[210];
} KUSER_SHARED_DATA, *PKUSER_SHARED_DATA;


struct CV_INFO_PDB70 {
    DWORD CvSignature;
    GUID  Signature;
    DWORD Age;
    BYTE  PdbFileName[1];
};

struct CV_INFO_PDB20 {
    DWORD CvSignature;
    LONG  Offset;
    DWORD Signature;
    DWORD Age;
    BYTE  PdbFileName[1];
};
