#ifndef SYSCALL_ENUM_H
#define SYSCALL_ENUM_H

/* 
 *  The syscalls enum places all system calls in order by syscall number
 *  such that we may compare syscall number stored in RAX to the enum value
 *  and get a correct match.
 */

enum syscalls {
	NTACCEPTCONNECTPORT = 0x0,
	NTACCESSCHECK = 0x1,
	NTACCESSCHECKANDAUDITALARM = 0x2,
	NTACCESSCHECKBYTYPE = 0x3,
	NTACCESSCHECKBYTYPEANDAUDITALARM = 0x4,
	NTACCESSCHECKBYTYPERESULTLIST = 0x5,
	NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARM = 0x6,
	NTACCESSCHECKBYTYPERESULTLISTANDAUDITALARMBYHANDLE = 0x7,
	NTADDATOM = 0x8,
	NTADDBOOTENTRY = 0x9,
	NTADDDRIVERENTRY = 0xa,
	NTADJUSTGROUPSTOKEN = 0xb,
	NTADJUSTPRIVILEGESTOKEN = 0xc,
	NTALERTRESUMETHREAD = 0xd,
	NTALERTTHREAD = 0xe,
	NTALLOCATELOCALLYUNIQUEID = 0xf,
	NTALLOCATERESERVEOBJECT = 0x10,
	NTALLOCATEUSERPHYSICALPAGES = 0x11,
	NTALLOCATEUUIDS = 0x12,
	NTALLOCATEVIRTUALMEMORY = 0x13,
	NTALPCACCEPTCONNECTPORT = 0x14,
	NTALPCCANCELMESSAGE = 0x15,
	NTALPCCONNECTPORT = 0x16,
	NTALPCCREATEPORT = 0x17,
	NTALPCCREATEPORTSECTION = 0x18,
	NTALPCCREATERESOURCERESERVE = 0x19,
	NTALPCCREATESECTIONVIEW = 0x1a,
	NTALPCCREATESECURITYCONTEXT = 0x1b,
	NTALPCDELETEPORTSECTION = 0x1c,
	NTALPCDELETERESOURCERESERVE = 0x1d,
	NTALPCDELETESECTIONVIEW = 0x1e,
	NTALPCDELETESECURITYCONTEXT = 0x1f,
	NTALPCDISCONNECTPORT = 0x20,
	NTALPCIMPERSONATECLIENTOFPORT = 0x21,
	NTALPCOPENSENDERPROCESS = 0x22,
	NTALPCOPENSENDERTHREAD = 0x23,
	NTALPCQUERYINFORMATION = 0x24,
	NTALPCQUERYINFORMATIONMESSAGE = 0x25,
	NTALPCREVOKESECURITYCONTEXT = 0x26,
	NTALPCSENDWAITRECEIVEPORT = 0x27,
	NTALPCSETINFORMATION = 0x28,
	NTAPPHELPCACHECONTROL = 0x29,
	NTAREMAPPEDFILESTHESAME = 0x2a,
	NTASSIGNPROCESSTOJOBOBJECT = 0x2b,
	NTCALLBACKRETURN = 0x2c,
	NTCANCELIOFILE = 0x2d,
	NTCANCELIOFILEEX = 0x2e,
	NTCANCELSYNCHRONOUSIOFILE = 0x2f,
	NTCANCELTIMER = 0x30,
	NTCLEAREVENT = 0x31,
	NTCLOSE = 0x32,
	NTCLOSEOBJECTAUDITALARM = 0x33,
	NTCOMMITCOMPLETE = 0x34,
	NTCOMMITENLISTMENT = 0x35,
	NTCOMMITTRANSACTION = 0x36,
	NTCOMPACTKEYS = 0x37,
	NTCOMPARETOKENS = 0x38,
	NTCOMPLETECONNECTPORT = 0x39,
	NTCOMPRESSKEY = 0x3a,
	NTCONNECTPORT = 0x3b,
	NTCONTINUE = 0x3c,
	NTCREATEDEBUGOBJECT = 0x3d,
	NTCREATEDIRECTORYOBJECT = 0x3e,
	NTCREATEENLISTMENT = 0x3f,
	NTCREATEEVENT = 0x40,
	NTCREATEEVENTPAIR = 0x41,
	NTCREATEFILE = 0x42,
	NTCREATEIOCOMPLETION = 0x43,
	NTCREATEJOBOBJECT = 0x44,
	NTCREATEJOBSET = 0x45,
	NTCREATEKEY = 0x46,
	NTCREATEKEYTRANSACTED = 0x48,
	NTCREATEKEYEDEVENT = 0x47,
	NTCREATEMAILSLOTFILE = 0x49,
	NTCREATEMUTANT = 0x4a,
	NTCREATENAMEDPIPEFILE = 0x4b,
	NTCREATEPAGINGFILE = 0x4c,
	NTCREATEPORT = 0x4d,
	NTCREATEPRIVATENAMESPACE = 0x4e,
	NTCREATEPROCESS = 0x4f,
	NTCREATEPROCESSEX = 0x50,
	NTCREATEPROFILE = 0x51,
	NTCREATEPROFILEEX = 0x52,
	NTCREATERESOURCEMANAGER = 0x53,
	NTCREATESECTION = 0x54,
	NTCREATESEMAPHORE = 0x55,
	NTCREATESYMBOLICLINKOBJECT = 0x56,
	NTCREATETHREAD = 0x57,
	NTCREATETHREADEX = 0x58,
	NTCREATETIMER = 0x59,
	NTCREATETOKEN = 0x5a,
	NTCREATETRANSACTION = 0x5b,
	NTCREATETRANSACTIONMANAGER = 0x5c,
	NTCREATEUSERPROCESS = 0x5d,
	NTCREATEWAITABLEPORT = 0x5e,
	NTCREATEWORKERFACTORY = 0x5f,
	NTDEBUGACTIVEPROCESS = 0x60,
	NTDEBUGCONTINUE = 0x61,
	NTDELAYEXECUTION = 0x62,
	NTDELETEATOM = 0x63,
	NTDELETEBOOTENTRY = 0x64,
	NTDELETEDRIVERENTRY = 0x65,
	NTDELETEFILE = 0x66,
	NTDELETEKEY = 0x67,
	NTDELETEOBJECTAUDITALARM = 0x68,
	NTDELETEPRIVATENAMESPACE = 0x69,
	NTDELETEVALUEKEY = 0x6a,
	NTDEVICEIOCONTROLFILE = 0x6b,
	NTDISABLELASTKNOWNGOOD = 0x6c,
	NTDISPLAYSTRING = 0x6d,
	NTDRAWTEXT = 0x6e,
	NTDUPLICATEOBJECT = 0x6f,
	NTDUPLICATETOKEN = 0x70,
	NTENABLELASTKNOWNGOOD = 0x71,
	NTENUMERATEBOOTENTRIES = 0x72,
	NTENUMERATEDRIVERENTRIES = 0x73,
	NTENUMERATEKEY = 0x74,
	NTENUMERATESYSTEMENVIRONMENTVALUESEX = 0x75,
	NTENUMERATETRANSACTIONOBJECT = 0x76,
	NTENUMERATEVALUEKEY = 0x77,
	NTEXTENDSECTION = 0x78,
	NTFILTERTOKEN = 0x79,
	NTFINDATOM = 0x7a,
	NTFLUSHBUFFERSFILE = 0x7b,
	NTFLUSHINSTALLUILANGUAGE = 0x7c,
	NTFLUSHINSTRUCTIONCACHE = 0x7d,
	NTFLUSHKEY = 0x7e,
	NTFLUSHPROCESSWRITEBUFFERS = 0x7f,
	NTFLUSHVIRTUALMEMORY = 0x80,
	NTFLUSHWRITEBUFFER = 0x81,
	NTFREEUSERPHYSICALPAGES = 0x82,
	NTFREEVIRTUALMEMORY = 0x83,
	NTFREEZEREGISTRY = 0x84,
	NTFREEZETRANSACTIONS = 0x85,
	NTFSCONTROLFILE = 0x86,
	NTGETCONTEXTTHREAD = 0x87,
	NTGETCURRENTPROCESSORNUMBER = 0x88,
	NTGETDEVICEPOWERSTATE = 0x89,
	NTGETMUIREGISTRYINFO = 0x8a,
	NTGETNEXTPROCESS = 0x8b,
	NTGETNEXTTHREAD = 0x8c,
	NTGETNLSSECTIONPTR = 0x8d,
	NTGETNOTIFICATIONRESOURCEMANAGER = 0x8e,
	NTGETPLUGPLAYEVENT = 0x8f,
	NTGETWRITEWATCH = 0x90,
	NTIMPERSONATEANONYMOUSTOKEN = 0x91,
	NTIMPERSONATECLIENTOFPORT = 0x92,
	NTIMPERSONATETHREAD = 0x93,
	NTINITIALIZENLSFILES = 0x94,
	NTINITIALIZEREGISTRY = 0x95,
	NTINITIATEPOWERACTION = 0x96,
	NTISPROCESSINJOB = 0x97,
	NTISSYSTEMRESUMEAUTOMATIC = 0x98,
	NTISUILANGUAGECOMITTED = 0x99,
	NTLISTENPORT = 0x9a,
	NTLOADDRIVER = 0x9b,
	NTLOADKEY = 0x9c,
	NTLOADKEY2 = 0x9d,
	NTLOADKEYEX = 0x9e,
	NTLOCKFILE = 0x9f,
	NTLOCKPRODUCTACTIVATIONKEYS = 0xa0,
	NTLOCKREGISTRYKEY = 0xa1,
	NTLOCKVIRTUALMEMORY = 0xa2,
	NTMAKEPERMANENTOBJECT = 0xa3,
	NTMAKETEMPORARYOBJECT = 0xa4,
	NTMAPCMFMODULE = 0xa5,
	NTMAPUSERPHYSICALPAGES = 0xa6,
	NTMAPUSERPHYSICALPAGESSCATTER = 0xa7,
	NTMAPVIEWOFSECTION = 0xa8,
	NTMODIFYBOOTENTRY = 0xa9,
	NTMODIFYDRIVERENTRY = 0xaa,
	NTNOTIFYCHANGEDIRECTORYFILE = 0xab,
	NTNOTIFYCHANGEKEY = 0xac,
	NTNOTIFYCHANGEMULTIPLEKEYS = 0xad,
	NTNOTIFYCHANGESESSION = 0xae,
	NTOPENDIRECTORYOBJECT = 0xaf,
	NTOPENENLISTMENT = 0xb0,
	NTOPENEVENT = 0xb1,
	NTOPENEVENTPAIR = 0xb2,
	NTOPENFILE = 0xb3,
	NTOPENIOCOMPLETION = 0xb4,
	NTOPENJOBOBJECT = 0xb5,
	NTOPENKEY = 0xb6,
	NTOPENKEYEX = 0xb7,
	NTOPENKEYTRANSACTED = 0xb9,
	NTOPENKEYTRANSACTEDEX = 0xba,
	NTOPENKEYEDEVENT = 0xb8,
	NTOPENMUTANT = 0xbb,
	NTOPENOBJECTAUDITALARM = 0xbc,
	NTOPENPRIVATENAMESPACE = 0xbd,
	NTOPENPROCESS = 0xbe,
	NTOPENPROCESSTOKEN = 0xbf,
	NTOPENPROCESSTOKENEX = 0xc0,
	NTOPENRESOURCEMANAGER = 0xc1,
	NTOPENSECTION = 0xc2,
	NTOPENSEMAPHORE = 0xc3,
	NTOPENSESSION = 0xc4,
	NTOPENSYMBOLICLINKOBJECT = 0xc5,
	NTOPENTHREAD = 0xc6,
	NTOPENTHREADTOKEN = 0xc7,
	NTOPENTHREADTOKENEX = 0xc8,
	NTOPENTIMER = 0xc9,
	NTOPENTRANSACTION = 0xca,
	NTOPENTRANSACTIONMANAGER = 0xcb,
	NTPLUGPLAYCONTROL = 0xcc,
	NTPOWERINFORMATION = 0xcd,
	NTPREPREPARECOMPLETE = 0xd0,
	NTPREPREPAREENLISTMENT = 0xd1,
	NTPREPARECOMPLETE = 0xce,
	NTPREPAREENLISTMENT = 0xcf,
	NTPRIVILEGECHECK = 0xd2,
	NTPRIVILEGEOBJECTAUDITALARM = 0xd4,
	NTPRIVILEGEDSERVICEAUDITALARM = 0xd3,
	NTPROPAGATIONCOMPLETE = 0xd5,
	NTPROPAGATIONFAILED = 0xd6,
	NTPROTECTVIRTUALMEMORY = 0xd7,
	NTPULSEEVENT = 0xd8,
	NTQUERYATTRIBUTESFILE = 0xd9,
	NTQUERYBOOTENTRYORDER = 0xda,
	NTQUERYBOOTOPTIONS = 0xdb,
	NTQUERYDEBUGFILTERSTATE = 0xdc,
	NTQUERYDEFAULTLOCALE = 0xdd,
	NTQUERYDEFAULTUILANGUAGE = 0xde,
	NTQUERYDIRECTORYFILE = 0xdf,
	NTQUERYDIRECTORYOBJECT = 0xe0,
	NTQUERYDRIVERENTRYORDER = 0xe1,
	NTQUERYEAFILE = 0xe2,
	NTQUERYEVENT = 0xe3,
	NTQUERYFULLATTRIBUTESFILE = 0xe4,
	NTQUERYINFORMATIONATOM = 0xe5,
	NTQUERYINFORMATIONENLISTMENT = 0xe6,
	NTQUERYINFORMATIONFILE = 0xe7,
	NTQUERYINFORMATIONJOBOBJECT = 0xe8,
	NTQUERYINFORMATIONPORT = 0xe9,
	NTQUERYINFORMATIONPROCESS = 0xea,
	NTQUERYINFORMATIONRESOURCEMANAGER = 0xeb,
	NTQUERYINFORMATIONTHREAD = 0xec,
	NTQUERYINFORMATIONTOKEN = 0xed,
	NTQUERYINFORMATIONTRANSACTION = 0xee,
	NTQUERYINFORMATIONTRANSACTIONMANAGER = 0xef,
	NTQUERYINFORMATIONWORKERFACTORY = 0xf0,
	NTQUERYINSTALLUILANGUAGE = 0xf1,
	NTQUERYINTERVALPROFILE = 0xf2,
	NTQUERYIOCOMPLETION = 0xf3,
	NTQUERYKEY = 0xf4,
	NTQUERYLICENSEVALUE = 0xf5,
	NTQUERYMULTIPLEVALUEKEY = 0xf6,
	NTQUERYMUTANT = 0xf7,
	NTQUERYOBJECT = 0xf8,
	NTQUERYOPENSUBKEYS = 0xf9,
	NTQUERYOPENSUBKEYSEX = 0xfa,
	NTQUERYPERFORMANCECOUNTER = 0xfb,
	NTQUERYPORTINFORMATIONPROCESS = 0xfc,
	NTQUERYQUOTAINFORMATIONFILE = 0xfd,
	NTQUERYSECTION = 0xfe,
	NTQUERYSECURITYATTRIBUTESTOKEN = 0xff,
	NTQUERYSECURITYOBJECT = 0x100,
	NTQUERYSEMAPHORE = 0x101,
	NTQUERYSYMBOLICLINKOBJECT = 0x102,
	NTQUERYSYSTEMENVIRONMENTVALUE = 0x103,
	NTQUERYSYSTEMENVIRONMENTVALUEEX = 0x104,
	NTQUERYSYSTEMINFORMATION = 0x105,
	NTQUERYSYSTEMINFORMATIONEX = 0x106,
	NTQUERYSYSTEMTIME = 0x107,
	NTQUERYTIMER = 0x108,
	NTQUERYTIMERRESOLUTION = 0x109,
	NTQUERYVALUEKEY = 0x10a,
	NTQUERYVIRTUALMEMORY = 0x10b,
	NTQUERYVOLUMEINFORMATIONFILE = 0x10c,
	NTQUEUEAPCTHREAD = 0x10d,
	NTQUEUEAPCTHREADEX = 0x10e,
	NTRAISEEXCEPTION = 0x10f,
	NTRAISEHARDERROR = 0x110,
	NTREADFILE = 0x111,
	NTREADFILESCATTER = 0x112,
	NTREADONLYENLISTMENT = 0x113,
	NTREADREQUESTDATA = 0x114,
	NTREADVIRTUALMEMORY = 0x115,
	NTRECOVERENLISTMENT = 0x116,
	NTRECOVERRESOURCEMANAGER = 0x117,
	NTRECOVERTRANSACTIONMANAGER = 0x118,
	NTREGISTERPROTOCOLADDRESSINFORMATION = 0x119,
	NTREGISTERTHREADTERMINATEPORT = 0x11a,
	NTRELEASEKEYEDEVENT = 0x11b,
	NTRELEASEMUTANT = 0x11c,
	NTRELEASESEMAPHORE = 0x11d,
	NTRELEASEWORKERFACTORYWORKER = 0x11e,
	NTREMOVEIOCOMPLETION = 0x11f,
	NTREMOVEIOCOMPLETIONEX = 0x120,
	NTREMOVEPROCESSDEBUG = 0x121,
	NTRENAMEKEY = 0x122,
	NTRENAMETRANSACTIONMANAGER = 0x123,
	NTREPLACEKEY = 0x124,
	NTREPLACEPARTITIONUNIT = 0x125,
	NTREPLYPORT = 0x126,
	NTREPLYWAITRECEIVEPORT = 0x127,
	NTREPLYWAITRECEIVEPORTEX = 0x128,
	NTREPLYWAITREPLYPORT = 0x129,
	NTREQUESTPORT = 0x12a,
	NTREQUESTWAITREPLYPORT = 0x12b,
	NTRESETEVENT = 0x12c,
	NTRESETWRITEWATCH = 0x12d,
	NTRESTOREKEY = 0x12e,
	NTRESUMEPROCESS = 0x12f,
	NTRESUMETHREAD = 0x130,
	NTROLLBACKCOMPLETE = 0x131,
	NTROLLBACKENLISTMENT = 0x132,
	NTROLLBACKTRANSACTION = 0x133,
	NTROLLFORWARDTRANSACTIONMANAGER = 0x134,
	NTSAVEKEY = 0x135,
	NTSAVEKEYEX = 0x136,
	NTSAVEMERGEDKEYS = 0x137,
	NTSECURECONNECTPORT = 0x138,
	NTSERIALIZEBOOT = 0x139,
	NTSETBOOTENTRYORDER = 0x13a,
	NTSETBOOTOPTIONS = 0x13b,
	NTSETCONTEXTTHREAD = 0x13c,
	NTSETDEBUGFILTERSTATE = 0x13d,
	NTSETDEFAULTHARDERRORPORT = 0x13e,
	NTSETDEFAULTLOCALE = 0x13f,
	NTSETDEFAULTUILANGUAGE = 0x140,
	NTSETDRIVERENTRYORDER = 0x141,
	NTSETEAFILE = 0x142,
	NTSETEVENT = 0x143,
	NTSETEVENTBOOSTPRIORITY = 0x144,
	NTSETHIGHEVENTPAIR = 0x145,
	NTSETHIGHWAITLOWEVENTPAIR = 0x146,
	NTSETINFORMATIONDEBUGOBJECT = 0x147,
	NTSETINFORMATIONENLISTMENT = 0x148,
	NTSETINFORMATIONFILE = 0x149,
	NTSETINFORMATIONJOBOBJECT = 0x14a,
	NTSETINFORMATIONKEY = 0x14b,
	NTSETINFORMATIONOBJECT = 0x14c,
	NTSETINFORMATIONPROCESS = 0x14d,
	NTSETINFORMATIONRESOURCEMANAGER = 0x14e,
	NTSETINFORMATIONTHREAD = 0x14f,
	NTSETINFORMATIONTOKEN = 0x150,
	NTSETINFORMATIONTRANSACTION = 0x151,
	NTSETINFORMATIONTRANSACTIONMANAGER = 0x152,
	NTSETINFORMATIONWORKERFACTORY = 0x153,
	NTSETINTERVALPROFILE = 0x154,
	NTSETIOCOMPLETION = 0x155,
	NTSETIOCOMPLETIONEX = 0x156,
	NTSETLDTENTRIES = 0x157,
	NTSETLOWEVENTPAIR = 0x158,
	NTSETLOWWAITHIGHEVENTPAIR = 0x159,
	NTSETQUOTAINFORMATIONFILE = 0x15a,
	NTSETSECURITYOBJECT = 0x15b,
	NTSETSYSTEMENVIRONMENTVALUE = 0x15c,
	NTSETSYSTEMENVIRONMENTVALUEEX = 0x15d,
	NTSETSYSTEMINFORMATION = 0x15e,
	NTSETSYSTEMPOWERSTATE = 0x15f,
	NTSETSYSTEMTIME = 0x160,
	NTSETTHREADEXECUTIONSTATE = 0x161,
	NTSETTIMER = 0x162,
	NTSETTIMEREX = 0x163,
	NTSETTIMERRESOLUTION = 0x164,
	NTSETUUIDSEED = 0x165,
	NTSETVALUEKEY = 0x166,
	NTSETVOLUMEINFORMATIONFILE = 0x167,
	NTSHUTDOWNSYSTEM = 0x168,
	NTSHUTDOWNWORKERFACTORY = 0x169,
	NTSIGNALANDWAITFORSINGLEOBJECT = 0x16a,
	NTSINGLEPHASEREJECT = 0x16b,
	NTSTARTPROFILE = 0x16c,
	NTSTOPPROFILE = 0x16d,
	NTSUSPENDPROCESS = 0x16e,
	NTSUSPENDTHREAD = 0x16f,
	NTSYSTEMDEBUGCONTROL = 0x170,
	NTTERMINATEJOBOBJECT = 0x171,
	NTTERMINATEPROCESS = 0x172,
	NTTERMINATETHREAD = 0x173,
	NTTESTALERT = 0x174,
	NTTHAWREGISTRY = 0x175,
	NTTHAWTRANSACTIONS = 0x176,
	NTTRACECONTROL = 0x177,
	NTTRACEEVENT = 0x178,
	NTTRANSLATEFILEPATH = 0x179,
	NTUMSTHREADYIELD = 0x17a,
	NTUNLOADDRIVER = 0x17b,
	NTUNLOADKEY = 0x17c,
	NTUNLOADKEY2 = 0x17d,
	NTUNLOADKEYEX = 0x17e,
	NTUNLOCKFILE = 0x17f,
	NTUNLOCKVIRTUALMEMORY = 0x180,
	NTUNMAPVIEWOFSECTION = 0x181,
	NTVDMCONTROL = 0x182,
	NTWAITFORDEBUGEVENT = 0x183,
	NTWAITFORKEYEDEVENT = 0x184,
	NTWAITFORMULTIPLEOBJECTS = 0x185,
	NTWAITFORMULTIPLEOBJECTS32 = 0x186,
	NTWAITFORSINGLEOBJECT = 0x187,
	NTWAITFORWORKVIAWORKERFACTORY = 0x188,
	NTWAITHIGHEVENTPAIR = 0x189,
	NTWAITLOWEVENTPAIR = 0x18a,
	NTWORKERFACTORYWORKERREADY = 0x18b,
	NTWRITEFILE = 0x18c,
	NTWRITEFILEGATHER = 0x18d,
	NTWRITEREQUESTDATA = 0x18e,
	NTWRITEVIRTUALMEMORY = 0x18f,
	NTYIELDEXECUTION = 0x190
};

#define NUM_SYSCALLS 0x191

const char * NUM_TO_SYSCALL[NUM_SYSCALLS] = {
	"NtAcceptConnectPort",
	"NtAccessCheck",
	"NtAccessCheckAndAuditAlarm",
	"NtAccessCheckByType",
	"NtAccessCheckByTypeAndAuditAlarm",
	"NtAccessCheckByTypeResultList",
	"NtAccessCheckByTypeResultListAndAuditAlarm",
	"NtAccessCheckByTypeResultListAndAuditAlarmByHandle",
	"NtAddAtom",
	"NtAddBootEntry",
	"NtAddDriverEntry",
	"NtAdjustGroupsToken",
	"NtAdjustPrivilegesToken",
	"NtAlertResumeThread",
	"NtAlertThread",
	"NtAllocateLocallyUniqueId",
	"NtAllocateReserveObject",
	"NtAllocateUserPhysicalPages",
	"NtAllocateUuids",
	"NtAllocateVirtualMemory",
	"NtAlpcAcceptConnectPort",
	"NtAlpcCancelMessage",
	"NtAlpcConnectPort",
	"NtAlpcCreatePort",
	"NtAlpcCreatePortSection",
	"NtAlpcCreateResourceReserve",
	"NtAlpcCreateSectionView",
	"NtAlpcCreateSecurityContext",
	"NtAlpcDeletePortSection",
	"NtAlpcDeleteResourceReserve",
	"NtAlpcDeleteSectionView",
	"NtAlpcDeleteSecurityContext",
	"NtAlpcDisconnectPort",
	"NtAlpcImpersonateClientOfPort",
	"NtAlpcOpenSenderProcess",
	"NtAlpcOpenSenderThread",
	"NtAlpcQueryInformation",
	"NtAlpcQueryInformationMessage",
	"NtAlpcRevokeSecurityContext",
	"NtAlpcSendWaitReceivePort",
	"NtAlpcSetInformation",
	"NtApphelpCacheControl",
	"NtAreMappedFilesTheSame",
	"NtAssignProcessToJobObject",
	"NtCallbackReturn",
	"NtCancelIoFile",
	"NtCancelIoFileEx",
	"NtCancelSynchronousIoFile",
	"NtCancelTimer",
	"NtClearEvent",
	"NtClose",
	"NtCloseObjectAuditAlarm",
	"NtCommitComplete",
	"NtCommitEnlistment",
	"NtCommitTransaction",
	"NtCompactKeys",
	"NtCompareTokens",
	"NtCompleteConnectPort",
	"NtCompressKey",
	"NtConnectPort",
	"NtContinue",
	"NtCreateDebugObject",
	"NtCreateDirectoryObject",
	"NtCreateEnlistment",
	"NtCreateEvent",
	"NtCreateEventPair",
	"NtCreateFile",
	"NtCreateIoCompletion",
	"NtCreateJobObject",
	"NtCreateJobSet",
	"NtCreateKey",
	"NtCreateKeyedEvent",
	"NtCreateKeyTransacted",
	"NtCreateMailslotFile",
	"NtCreateMutant",
	"NtCreateNamedPipeFile",
	"NtCreatePagingFile",
	"NtCreatePort",
	"NtCreatePrivateNamespace",
	"NtCreateProcess",
	"NtCreateProcessEx",
	"NtCreateProfile",
	"NtCreateProfileEx",
	"NtCreateResourceManager",
	"NtCreateSection",
	"NtCreateSemaphore",
	"NtCreateSymbolicLinkObject",
	"NtCreateThread",
	"NtCreateThreadEx",
	"NtCreateTimer",
	"NtCreateToken",
	"NtCreateTransaction",
	"NtCreateTransactionManager",
	"NtCreateUserProcess",
	"NtCreateWaitablePort",
	"NtCreateWorkerFactory",
	"NtDebugActiveProcess",
	"NtDebugContinue",
	"NtDelayExecution",
	"NtDeleteAtom",
	"NtDeleteBootEntry",
	"NtDeleteDriverEntry",
	"NtDeleteFile",
	"NtDeleteKey",
	"NtDeleteObjectAuditAlarm",
	"NtDeletePrivateNamespace",
	"NtDeleteValueKey",
	"NtDeviceIoControlFile",
	"NtDisableLastKnownGood",
	"NtDisplayString",
	"NtDrawText",
	"NtDuplicateObject",
	"NtDuplicateToken",
	"NtEnableLastKnownGood",
	"NtEnumerateBootEntries",
	"NtEnumerateDriverEntries",
	"NtEnumerateKey",
	"NtEnumerateSystemEnvironmentValuesEx",
	"NtEnumerateTransactionObject",
	"NtEnumerateValueKey",
	"NtExtendSection",
	"NtFilterToken",
	"NtFindAtom",
	"NtFlushBuffersFile",
	"NtFlushInstallUILanguage",
	"NtFlushInstructionCache",
	"NtFlushKey",
	"NtFlushProcessWriteBuffers",
	"NtFlushVirtualMemory",
	"NtFlushWriteBuffer",
	"NtFreeUserPhysicalPages",
	"NtFreeVirtualMemory",
	"NtFreezeRegistry",
	"NtFreezeTransactions",
	"NtFsControlFile",
	"NtGetContextThread",
	"NtGetCurrentProcessorNumber",
	"NtGetDevicePowerState",
	"NtGetMUIRegistryInfo",
	"NtGetNextProcess",
	"NtGetNextThread",
	"NtGetNlsSectionPtr",
	"NtGetNotificationResourceManager",
	"NtGetPlugPlayEvent",
	"NtGetWriteWatch",
	"NtImpersonateAnonymousToken",
	"NtImpersonateClientOfPort",
	"NtImpersonateThread",
	"NtInitializeNlsFiles",
	"NtInitializeRegistry",
	"NtInitiatePowerAction",
	"NtIsProcessInJob",
	"NtIsSystemResumeAutomatic",
	"NtIsUILanguageComitted",
	"NtListenPort",
	"NtLoadDriver",
	"NtLoadKey",
	"NtLoadKey2",
	"NtLoadKeyEx",
	"NtLockFile",
	"NtLockProductActivationKeys",
	"NtLockRegistryKey",
	"NtLockVirtualMemory",
	"NtMakePermanentObject",
	"NtMakeTemporaryObject",
	"NtMapCMFModule",
	"NtMapUserPhysicalPages",
	"NtMapUserPhysicalPagesScatter",
	"NtMapViewOfSection",
	"NtModifyBootEntry",
	"NtModifyDriverEntry",
	"NtNotifyChangeDirectoryFile",
	"NtNotifyChangeKey",
	"NtNotifyChangeMultipleKeys",
	"NtNotifyChangeSession",
	"NtOpenDirectoryObject",
	"NtOpenEnlistment",
	"NtOpenEvent",
	"NtOpenEventPair",
	"NtOpenFile",
	"NtOpenIoCompletion",
	"NtOpenJobObject",
	"NtOpenKey",
	"NtOpenKeyEx",
	"NtOpenKeyedEvent",
	"NtOpenKeyTransacted",
	"NtOpenKeyTransactedEx",
	"NtOpenMutant",
	"NtOpenObjectAuditAlarm",
	"NtOpenPrivateNamespace",
	"NtOpenProcess",
	"NtOpenProcessToken",
	"NtOpenProcessTokenEx",
	"NtOpenResourceManager",
	"NtOpenSection",
	"NtOpenSemaphore",
	"NtOpenSession",
	"NtOpenSymbolicLinkObject",
	"NtOpenThread",
	"NtOpenThreadToken",
	"NtOpenThreadTokenEx",
	"NtOpenTimer",
	"NtOpenTransaction",
	"NtOpenTransactionManager",
	"NtPlugPlayControl",
	"NtPowerInformation",
	"NtPrepareComplete",
	"NtPrepareEnlistment",
	"NtPrePrepareComplete",
	"NtPrePrepareEnlistment",
	"NtPrivilegeCheck",
	"NtPrivilegedServiceAuditAlarm",
	"NtPrivilegeObjectAuditAlarm",
	"NtPropagationComplete",
	"NtPropagationFailed",
	"NtProtectVirtualMemory",
	"NtPulseEvent",
	"NtQueryAttributesFile",
	"NtQueryBootEntryOrder",
	"NtQueryBootOptions",
	"NtQueryDebugFilterState",
	"NtQueryDefaultLocale",
	"NtQueryDefaultUILanguage",
	"NtQueryDirectoryFile",
	"NtQueryDirectoryObject",
	"NtQueryDriverEntryOrder",
	"NtQueryEaFile",
	"NtQueryEvent",
	"NtQueryFullAttributesFile",
	"NtQueryInformationAtom",
	"NtQueryInformationEnlistment",
	"NtQueryInformationFile",
	"NtQueryInformationJobObject",
	"NtQueryInformationPort",
	"NtQueryInformationProcess",
	"NtQueryInformationResourceManager",
	"NtQueryInformationThread",
	"NtQueryInformationToken",
	"NtQueryInformationTransaction",
	"NtQueryInformationTransactionManager",
	"NtQueryInformationWorkerFactory",
	"NtQueryInstallUILanguage",
	"NtQueryIntervalProfile",
	"NtQueryIoCompletion",
	"NtQueryKey",
	"NtQueryLicenseValue",
	"NtQueryMultipleValueKey",
	"NtQueryMutant",
	"NtQueryObject",
	"NtQueryOpenSubKeys",
	"NtQueryOpenSubKeysEx",
	"NtQueryPerformanceCounter",
	"NtQueryPortInformationProcess",
	"NtQueryQuotaInformationFile",
	"NtQuerySection",
	"NtQuerySecurityAttributesToken",
	"NtQuerySecurityObject",
	"NtQuerySemaphore",
	"NtQuerySymbolicLinkObject",
	"NtQuerySystemEnvironmentValue",
	"NtQuerySystemEnvironmentValueEx",
	"NtQuerySystemInformation",
	"NtQuerySystemInformationEx",
	"NtQuerySystemTime",
	"NtQueryTimer",
	"NtQueryTimerResolution",
	"NtQueryValueKey",
	"NtQueryVirtualMemory",
	"NtQueryVolumeInformationFile",
	"NtQueueApcThread",
	"NtQueueApcThreadEx",
	"NtRaiseException",
	"NtRaiseHardError",
	"NtReadFile",
	"NtReadFileScatter",
	"NtReadOnlyEnlistment",
	"NtReadRequestData",
	"NtReadVirtualMemory",
	"NtRecoverEnlistment",
	"NtRecoverResourceManager",
	"NtRecoverTransactionManager",
	"NtRegisterProtocolAddressInformation",
	"NtRegisterThreadTerminatePort",
	"NtReleaseKeyedEvent",
	"NtReleaseMutant",
	"NtReleaseSemaphore",
	"NtReleaseWorkerFactoryWorker",
	"NtRemoveIoCompletion",
	"NtRemoveIoCompletionEx",
	"NtRemoveProcessDebug",
	"NtRenameKey",
	"NtRenameTransactionManager",
	"NtReplaceKey",
	"NtReplacePartitionUnit",
	"NtReplyPort",
	"NtReplyWaitReceivePort",
	"NtReplyWaitReceivePortEx",
	"NtReplyWaitReplyPort",
	"NtRequestPort",
	"NtRequestWaitReplyPort",
	"NtResetEvent",
	"NtResetWriteWatch",
	"NtRestoreKey",
	"NtResumeProcess",
	"NtResumeThread",
	"NtRollbackComplete",
	"NtRollbackEnlistment",
	"NtRollbackTransaction",
	"NtRollforwardTransactionManager",
	"NtSaveKey",
	"NtSaveKeyEx",
	"NtSaveMergedKeys",
	"NtSecureConnectPort",
	"NtSerializeBoot",
	"NtSetBootEntryOrder",
	"NtSetBootOptions",
	"NtSetContextThread",
	"NtSetDebugFilterState",
	"NtSetDefaultHardErrorPort",
	"NtSetDefaultLocale",
	"NtSetDefaultUILanguage",
	"NtSetDriverEntryOrder",
	"NtSetEaFile",
	"NtSetEvent",
	"NtSetEventBoostPriority",
	"NtSetHighEventPair",
	"NtSetHighWaitLowEventPair",
	"NtSetInformationDebugObject",
	"NtSetInformationEnlistment",
	"NtSetInformationFile",
	"NtSetInformationJobObject",
	"NtSetInformationKey",
	"NtSetInformationObject",
	"NtSetInformationProcess",
	"NtSetInformationResourceManager",
	"NtSetInformationThread",
	"NtSetInformationToken",
	"NtSetInformationTransaction",
	"NtSetInformationTransactionManager",
	"NtSetInformationWorkerFactory",
	"NtSetIntervalProfile",
	"NtSetIoCompletion",
	"NtSetIoCompletionEx",
	"NtSetLdtEntries",
	"NtSetLowEventPair",
	"NtSetLowWaitHighEventPair",
	"NtSetQuotaInformationFile",
	"NtSetSecurityObject",
	"NtSetSystemEnvironmentValue",
	"NtSetSystemEnvironmentValueEx",
	"NtSetSystemInformation",
	"NtSetSystemPowerState",
	"NtSetSystemTime",
	"NtSetThreadExecutionState",
	"NtSetTimer",
	"NtSetTimerEx",
	"NtSetTimerResolution",
	"NtSetUuidSeed",
	"NtSetValueKey",
	"NtSetVolumeInformationFile",
	"NtShutdownSystem",
	"NtShutdownWorkerFactory",
	"NtSignalAndWaitForSingleObject",
	"NtSinglePhaseReject",
	"NtStartProfile",
	"NtStopProfile",
	"NtSuspendProcess",
	"NtSuspendThread",
	"NtSystemDebugControl",
	"NtTerminateJobObject",
	"NtTerminateProcess",
	"NtTerminateThread",
	"NtTestAlert",
	"NtThawRegistry",
	"NtThawTransactions",
	"NtTraceControl",
	"NtTraceEvent",
	"NtTranslateFilePath",
	"NtUmsThreadYield",
	"NtUnloadDriver",
	"NtUnloadKey",
	"NtUnloadKey2",
	"NtUnloadKeyEx",
	"NtUnlockFile",
	"NtUnlockVirtualMemory",
	"NtUnmapViewOfSection",
	"NtVdmControl",
	"NtWaitForDebugEvent",
	"NtWaitForKeyedEvent",
	"NtWaitForMultipleObjects",
	"NtWaitForMultipleObjects32",
	"NtWaitForSingleObject",
	"NtWaitForWorkViaWorkerFactory",
	"NtWaitHighEventPair",
	"NtWaitLowEventPair",
	"NtWorkerFactoryWorkerReady",
	"NtWriteFile",
	"NtWriteFileGather",
	"NtWriteRequestData",
	"NtWriteVirtualMemory",
	"NtYieldExecution"
};


#endif