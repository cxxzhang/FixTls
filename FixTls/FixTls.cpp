#include"FixTls.h"

typedef unsigned long       DWORD;
typedef struct _PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY {
	union {
		DWORD Flags;
		struct {
			DWORD EnableUserShadowStack : 1;
			DWORD AuditUserShadowStack : 1;
			DWORD SetContextIpValidation : 1;
			DWORD AuditSetContextIpValidation : 1;
			DWORD EnableUserShadowStackStrictMode : 1;
			DWORD BlockNonCetBinaries : 1;
			DWORD BlockNonCetBinariesNonEhcont : 1;
			DWORD AuditBlockNonCetBinaries : 1;
			DWORD CetDynamicApisOutOfProcOnly : 1;
			DWORD SetContextIpValidationRelaxedMode : 1;
			DWORD ReservedFlags : 22;

		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;
} PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY, *PPROCESS_MITIGATION_USER_SHADOW_STACK_POLICY;//由于用的17763的SDK，手动定义一下结构体

#include <MINT.h>





///----假设exe或者它的依赖dll一定包含了tls的初始化部分，代码里没处理ThreadLocalStoragePointer为空的场景----///

typedef struct _LDRP_TLS_ENTRY {
	LIST_ENTRY Links;
	IMAGE_TLS_DIRECTORY Tls;
} LDRP_TLS_ENTRY, *PLDRP_TLS_ENTRY;

typedef struct _TLS_OLD_DATA
{
	DWORD  dwThreadId;
	PVOID  ThreadLocalStoragePointerOrg;
	PVOID  ThreadLocalStoragePointerNew;
}TLS_OLD_DATA, *PTLS_OLD_DATA;


#define TLS_TAG 3
#define MAKE_TAG( t ) (RTL_HEAP_MAKE_TAG( NtdllBaseTag, (t) ))
#define MAX_TLS_SLOT_COUNT  0x1000

static ULONG NtdllBaseTag = 0;
static LIST_ENTRY LdrpTlsList = {};
static ULONG LdrpNumberOfTlsEntries = 0;
static BOOLEAN LdrpImageHasTls = FALSE;

static TLS_OLD_DATA LdrpTlsThreadOldData[MAX_TLS_SLOT_COUNT] = {};//0x1000个线程，XP应该够用了


PVOID SetTlsOldData(DWORD dwCurrentThreadId, PVOID ThreadLocalStoragePointerOrg, PVOID ThreadLocalStoragePointerNew)
{
	for (int i = 0; i < MAX_TLS_SLOT_COUNT; ++i)
	{
		auto dwOrgThreadId = InterlockedCompareExchange(&LdrpTlsThreadOldData[i].dwThreadId, dwCurrentThreadId, 0);
		if (dwOrgThreadId == 0)
		{
			LdrpTlsThreadOldData[i].ThreadLocalStoragePointerOrg = ThreadLocalStoragePointerOrg;
			LdrpTlsThreadOldData[i].ThreadLocalStoragePointerNew = ThreadLocalStoragePointerNew;
			return 	LdrpTlsThreadOldData[i].ThreadLocalStoragePointerOrg;
		}
	}

	return nullptr;
}


PVOID  ResetTlsOldData(DWORD dwCurrentThreadId, PVOID ThreadLocalStoragePointerNew)
{
	PVOID ThreadLocalStoragePointerOrg = ThreadLocalStoragePointerNew;
	for (int i = 0; i < MAX_TLS_SLOT_COUNT; ++i)
	{
		auto dwOrgThreadId = InterlockedCompareExchange(&LdrpTlsThreadOldData[i].dwThreadId, 0, dwCurrentThreadId);
		if (dwOrgThreadId == dwCurrentThreadId)
		{
			if (ThreadLocalStoragePointerNew == LdrpTlsThreadOldData[i].ThreadLocalStoragePointerNew)
			{
				ThreadLocalStoragePointerOrg = LdrpTlsThreadOldData[i].ThreadLocalStoragePointerOrg;
			}

			LdrpTlsThreadOldData[i].ThreadLocalStoragePointerOrg = nullptr;
			LdrpTlsThreadOldData[i].ThreadLocalStoragePointerNew = nullptr;

			break;
		}
	}
	return ThreadLocalStoragePointerOrg;
}


VOID* GetOffsetInFile(PVOID lpBase, ULONG rva)
{

	IMAGE_DOS_HEADER * dos_hdr = (IMAGE_DOS_HEADER *)lpBase;
	if (dos_hdr->e_magic == 'MZ' || dos_hdr->e_magic == 'ZM') {
	}
	else
	{
		return nullptr;
	}

	IMAGE_NT_HEADERS *nt_hdrs = (IMAGE_NT_HEADERS *)((UCHAR *)dos_hdr + dos_hdr->e_lfanew);
	if (nt_hdrs->Signature != IMAGE_NT_SIGNATURE)
	{
		return nullptr;
	}

	IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(nt_hdrs);
	for (ULONG i = 0; i < nt_hdrs->FileHeader.NumberOfSections; ++i)
	{
		if (rva >= section->VirtualAddress &&
			rva < section->VirtualAddress + section->SizeOfRawData)
		{

			VOID *addr = (UCHAR *)lpBase + rva - section->VirtualAddress + section->PointerToRawData;
			return addr;
		}

		++section;
	}


	return nullptr;
}


NTSTATUS
LdrpInitializeTls(
	VOID
)
{
	PLDR_DATA_TABLE_ENTRY Entry;
	PLIST_ENTRY Head, Next;
	PIMAGE_TLS_DIRECTORY TlsImage;
	PLDRP_TLS_ENTRY TlsEntry;
	ULONG TlsSize;
	LOGICAL FirstTimeThru;
	HANDLE ProcessHeap;
	PPEB_LDR_DATA pPebLdr = NtCurrentPeb()->Ldr;

	ProcessHeap = RtlProcessHeap();
	FirstTimeThru = TRUE;

	InitializeListHead(&LdrpTlsList);

	//
	// Walk through the loaded modules and look for TLS. If we find TLS,
	// lock in the module and add to the TLS chain.
	//

	Head = &(pPebLdr->InLoadOrderModuleList);
	Next = Head->Flink;

	while (Next != Head) {

		Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
		Next = Next->Flink;

		TlsImage = (PIMAGE_TLS_DIRECTORY)RtlImageDirectoryEntryToData(
			Entry->DllBase,
			TRUE,
			IMAGE_DIRECTORY_ENTRY_TLS,
			&TlsSize);

		//
		// Mark whether or not the image file has TLS.
		//

		if (FirstTimeThru) {
			FirstTimeThru = FALSE;
			if (TlsImage && !LdrpImageHasTls) {
				//RtlpSerializeHeap(ProcessHeap);
				LdrpImageHasTls = TRUE;
			}
		}

		if (TlsImage) {

			//if (ShowSnaps) {
			//	DbgPrint("LDR: Tls Found in %wZ at %p\n",
			//		&Entry->BaseDllName,
			//		TlsImage);
			//}

			TlsEntry = (PLDRP_TLS_ENTRY)RtlAllocateHeap(ProcessHeap, MAKE_TAG(TLS_TAG), sizeof(*TlsEntry));
			if (!TlsEntry) {
				return STATUS_NO_MEMORY;
			}

			//
			// Since this DLL has TLS, lock it in
			//

			Entry->ObsoleteLoadCount = (USHORT)0xffff;

			//
			// Mark this as having thread local storage
			//

			Entry->TlsIndex = (USHORT)0xffff;

			TlsEntry->Tls = *TlsImage;
			InsertTailList(&LdrpTlsList, &TlsEntry->Links);

			//
			// Update the index for this dll's thread local storage
			//
			ULONG OldIndex = *(PLONG)TlsEntry->Tls.AddressOfIndex;
			if (OldIndex != 0)
			{
				if (OldIndex != LdrpNumberOfTlsEntries)//这里做一下校验，已经初始化了的TLS模块，如果跟想要赋值的index不一致，直接返回失败
				{
					LdrpNumberOfTlsEntries = 0;
					return STATUS_INVALID_INFO_CLASS;
				}

			}

			*(PLONG)TlsEntry->Tls.AddressOfIndex = LdrpNumberOfTlsEntries;
			TlsEntry->Tls.Characteristics = LdrpNumberOfTlsEntries++;

		}
	}

	//
	// We now have walked through all static DLLs and know
	// all DLLs that reference thread local storage. Now we
	// just have to allocate the thread local storage for the current
	// thread and for all subsequent threads.
	//
	return STATUS_SUCCESS;
	//return LdrpAllocateTls();
}


NTSTATUS
LdrpAllocateTls(
	PTEB _Teb
)
{
	PTEB Teb = _Teb;
	PLIST_ENTRY Head, Next;
	PLDRP_TLS_ENTRY TlsEntry;
	PVOID *TlsVector;
	HANDLE ProcessHeap;

	//
	// Allocate the array of thread local storage pointers
	//

	if (LdrpNumberOfTlsEntries) {

		if (Teb == nullptr)
			Teb = NtCurrentTeb();
		ProcessHeap = Teb->ProcessEnvironmentBlock->ProcessHeap;

		TlsVector = (PVOID *)RtlAllocateHeap(ProcessHeap, MAKE_TAG(TLS_TAG), sizeof(PVOID)*LdrpNumberOfTlsEntries);

		if (!TlsVector) {
			return STATUS_NO_MEMORY;
		}
		//
		// NOTICE-2002/03/14-ELi
		// Zero out the new array of pointers, LdrpFreeTls frees the pointers
		// if the pointers are non-NULL
		//
		RtlZeroMemory(TlsVector, sizeof(PVOID)*LdrpNumberOfTlsEntries);


		Head = &LdrpTlsList;
		Next = Head->Flink;

		while (Next != Head) {
			TlsEntry = CONTAINING_RECORD(Next, LDRP_TLS_ENTRY, Links);
			Next = Next->Flink;
			TlsVector[TlsEntry->Tls.Characteristics] = RtlAllocateHeap(
				ProcessHeap,
				MAKE_TAG(TLS_TAG),
				TlsEntry->Tls.EndAddressOfRawData - TlsEntry->Tls.StartAddressOfRawData
			);
			if (!TlsVector[TlsEntry->Tls.Characteristics]) {
				return STATUS_NO_MEMORY;
			}

			//if (ShowSnaps) {
			//	DbgPrint("LDR: TlsVector %x Index %d = %x copied from %x to %x\n",
			//		TlsVector,
			//		TlsEntry->Tls.Characteristics,
			//		&TlsVector[TlsEntry->Tls.Characteristics],
			//		TlsEntry->Tls.StartAddressOfRawData,
			//		TlsVector[TlsEntry->Tls.Characteristics]);
			//}

			//
			// Do the TLS Callouts
			//

			RtlCopyMemory(
				TlsVector[TlsEntry->Tls.Characteristics],
				(PVOID)TlsEntry->Tls.StartAddressOfRawData,
				TlsEntry->Tls.EndAddressOfRawData - TlsEntry->Tls.StartAddressOfRawData
			);
		}

		SetTlsOldData((DWORD)Teb->ClientId.UniqueThread, Teb->ThreadLocalStoragePointer, TlsVector);
		Teb->ThreadLocalStoragePointer = TlsVector;
	}
	return STATUS_SUCCESS;
}


VOID
LdrpFreeTls(
	PTEB _Teb
)
{
	PTEB Teb = _Teb;
	PLIST_ENTRY Head, Next;
	PLDRP_TLS_ENTRY TlsEntry;
	PVOID *TlsVector;
	HANDLE ProcessHeap;

	if (LdrpNumberOfTlsEntries == 0)
	{
		return;
	}

	if (Teb == nullptr)
		Teb = NtCurrentTeb();

	TlsVector = (PVOID *)(Teb->ThreadLocalStoragePointer);
	Teb->ThreadLocalStoragePointer = ResetTlsOldData((DWORD)Teb->ClientId.UniqueThread, Teb->ThreadLocalStoragePointer);

	if (TlsVector)
	{
		ProcessHeap = Teb->ProcessEnvironmentBlock->ProcessHeap;

		Head = &LdrpTlsList;
		Next = Head->Flink;

		while (Next != Head) {

			TlsEntry = CONTAINING_RECORD(Next, LDRP_TLS_ENTRY, Links);
			Next = Next->Flink;

			//
			// Do the TLS callouts
			//

			if (TlsVector[TlsEntry->Tls.Characteristics]) {

				RtlFreeHeap(ProcessHeap,
					0,
					TlsVector[TlsEntry->Tls.Characteristics]);
			}
		}

		RtlFreeHeap(ProcessHeap, 0, TlsVector);
	}

}


PVOID NTAPI TlsQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_opt_ LPDWORD ReturnLength) {

	if (ReturnLength)*ReturnLength = 0;

	NTSTATUS status;
	PVOID buffer = nullptr;
	ULONG len = 0;


	do {

		RtlFreeHeap(
			RtlProcessHeap(),
			0,
			buffer
		);
		buffer = nullptr;

		if (len) {
			len *= 2;
			buffer = RtlAllocateHeap(
				RtlProcessHeap(),
				0,
				len
			);
			if (!buffer)return nullptr;
		}

		status = NtQuerySystemInformation(
			SystemInformationClass,
			buffer,
			len,
			&len
		);
		if (NT_SUCCESS(status))break;
	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (ReturnLength)*ReturnLength = len;
	return buffer;
}



VOID TlsFixInAllThread()
{

	auto pid = NtCurrentProcessId();
	auto p_system_process_info = PSYSTEM_PROCESS_INFORMATION(TlsQuerySystemInformation(SystemProcessInformation, nullptr));
	if (!p_system_process_info)
	{
		return;
	}

	auto p_process_info = p_system_process_info;
	while (true)
	{
		if (p_process_info->UniqueProcessId == pid)
		{
			OBJECT_ATTRIBUTES oa{};
			InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
			THREAD_BASIC_INFORMATION tbi{};
			NTSTATUS status = 0;
			for (ULONG i = 0; i < p_process_info->NumberOfThreads; ++i)
			{
				HANDLE hThread = nullptr;
				status = NtOpenThread(&hThread, THREAD_QUERY_INFORMATION, &oa, &p_process_info->Threads[i].ClientId);

				if (NT_SUCCESS(status))
				{
					status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
					if (NT_SUCCESS(status) && !!tbi.TebBaseAddress->ThreadLocalStoragePointer)
					{
						LdrpAllocateTls(tbi.TebBaseAddress);
					}

					NtClose(hThread);
				}
			}

			break;
		}

		if (!p_process_info->NextEntryOffset)break;
		p_process_info = PSYSTEM_PROCESS_INFORMATION(LPSTR(p_process_info) + p_process_info->NextEntryOffset);
	}

	RtlFreeHeap(RtlProcessHeap(), 0, p_system_process_info);

}



VOID TlsFreeInAllThread()
{

	auto pid = NtCurrentProcessId();
	auto p_system_process_info = PSYSTEM_PROCESS_INFORMATION(TlsQuerySystemInformation(SystemProcessInformation, nullptr));
	if (!p_system_process_info)
	{
		return;
	}

	auto p_process_info = p_system_process_info;
	while (true)
	{
		if (p_process_info->UniqueProcessId == pid)
		{
			OBJECT_ATTRIBUTES oa{};
			InitializeObjectAttributes(&oa, nullptr, 0, nullptr, nullptr);
			THREAD_BASIC_INFORMATION tbi{};
			NTSTATUS status = 0;
			for (ULONG i = 0; i < p_process_info->NumberOfThreads; ++i)
			{
				HANDLE hThread = nullptr;
				status = NtOpenThread(&hThread, THREAD_QUERY_INFORMATION, &oa, &p_process_info->Threads[i].ClientId);

				if (NT_SUCCESS(status))
				{
					status = NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), nullptr);
					if (NT_SUCCESS(status) && !!tbi.TebBaseAddress->ThreadLocalStoragePointer)
					{
						LdrpFreeTls(tbi.TebBaseAddress);
					}

					NtClose(hThread);
				}
			}

			break;
		}

		if (!p_process_info->NextEntryOffset)break;
		p_process_info = PSYSTEM_PROCESS_INFORMATION(LPSTR(p_process_info) + p_process_info->NextEntryOffset);
	}

	RtlFreeHeap(RtlProcessHeap(), 0, p_system_process_info);

}

static VOID NTAPI tlsload_tls_callback(
	PVOID DllHandle,
	DWORD Reason,
	PVOID Reserved
)
{
	switch (Reason)
	{
	case DLL_THREAD_ATTACH:
		LdrpAllocateTls(nullptr);
		break;
	case DLL_THREAD_DETACH:
		LdrpFreeTls(nullptr);
		break;
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		TlsFreeInAllThread();
		break;;
	}
}

#pragma section(".CRT$XLB",    long, read)
__declspec(allocate(".CRT$XLB")) static PIMAGE_TLS_CALLBACK _TLS_CALLBACKs = tlsload_tls_callback;
#if defined(_X86_)
#pragma comment(linker, "/INCLUDE:__tls_used")
#else
#pragma comment(linker, "/INCLUDE:_tls_used")
#endif





void FixTls()
{
	PPEB  lpPeb = NtCurrentPeb();
	if (lpPeb->OSMajorVersion >= 6)
	{
		return;//只需要支持XP就可以了。也只能支持XP，后续的操作系统会动态操作TLS数组。
	}

	if (LdrpInitializeTls() != STATUS_SUCCESS)
	{
		return;
	}

	TlsFixInAllThread();
}

