#include <ntifs.h>
#include <windef.h>
#include <strsafe.h>
#include <ntifs.h>
#include <intrin.h>
#include <ntddk.h>
#include <cstdint>
#include <ntdef.h>
#include "low.h"

//allah is fake

#define dtbfix_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x12A, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define rw_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x13A, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define base_code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x14A, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
struct comms_t {
	std::uint32_t key;

	struct {
		void* handle;
	}window;
};

UNICODE_STRING name, link;
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

EXTERN_C int _fltused = 0;
uintptr_t eac_cr32 = 0;
PEPROCESS saved_process = 0;
typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBigPoolInformation = 0x42,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);
ULONGLONG m_stored_dtb;
PEPROCESS save_process;
uint64_t eac_module;
uint64_t eac_cr3;
#define PAGE_OFFSET_SIZE 12
static const UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull;
typedef struct _dtb {
	INT32 process_id;
	bool* operation;
} dtb, * dtbl;
typedef struct _ba {
	INT32 process_id;
	ULONGLONG* address;
} ba, * pba;
typedef struct _rw {
	INT32 process_id;
	ULONGLONG address;
	ULONGLONG buffer;
	ULONGLONG size;
	BOOLEAN write;
} rw, * prw;
bool is_cr3_invalid(uintptr_t cr3)
{
	return (cr3 >> 0x38) == 0x40;
}
uintptr_t getproccr3(PEPROCESS pprocess)
{
	if (!pprocess) return 0;
	uintptr_t process_dirbase = *(uintptr_t*)((PUCHAR)pprocess + 0x28);
	if (process_dirbase == 0)
	{
		ULONG user_diroffset = 0x0388;
		process_dirbase = *(uintptr_t*)((PUCHAR)pprocess + user_diroffset);
	}
	return process_dirbase;
}


ULONG64 find_min(INT32 g,
	SIZE_T f) 
{
	INT32 h = (INT32)f;
	ULONG64 result = 0;

	result = (((g) < (h)) ? (g) : (h));

	return result;
}
auto read_physical(PVOID target_address,
	PVOID buffer,
	SIZE_T size,
	SIZE_T* bytes_read) -> NTSTATUS
{
	MM_COPY_ADDRESS to_read = { 0 };
	to_read.PhysicalAddress.QuadPart = (LONGLONG)target_address;
	return MmCopyMemory(buffer, to_read, size, MM_COPY_MEMORY_PHYSICAL, bytes_read);
}
NTSTATUS write_phyiscal(PVOID target_address,
	PVOID buffer,
	SIZE_T size,
	SIZE_T* bytes_read)
{
	if (!target_address) {
		return STATUS_UNSUCCESSFUL;
	}
	PHYSICAL_ADDRESS to_write = { 0 };
	to_write.QuadPart = LONGLONG(target_address);
	PVOID sp_mapped_memory = MmMapIoSpaceEx(to_write, size, PAGE_READWRITE);
	if (!sp_mapped_memory) {
		return STATUS_UNSUCCESSFUL;
	}
	memcpy(sp_mapped_memory, buffer, size);
	*bytes_read = size;
	MmUnmapIoSpace(sp_mapped_memory, size);
	return STATUS_SUCCESS;
}
namespace pml
{
	PVOID split_memory(PVOID SearchBase, SIZE_T SearchSize, const void* Pattern, SIZE_T PatternSize)
	{
		const UCHAR* searchBase = static_cast<const UCHAR*>(SearchBase);
		const UCHAR* pattern = static_cast<const UCHAR*>(Pattern);

		for (SIZE_T i = 0; i <= SearchSize - PatternSize; ++i) {
			SIZE_T j = 0;
			for (; j < PatternSize; ++j) {
				if (searchBase[i + j] != pattern[j])
					break;
			}
			if (j == PatternSize)
				return const_cast<UCHAR*>(&searchBase[i]);
		}

		return nullptr;
	}

	void* g_mmonp_MmPfnDatabase;

	static NTSTATUS InitializeMmPfnDatabase()
	{
		struct MmPfnDatabaseSearchPattern
		{
			const UCHAR* bytes;
			SIZE_T bytes_size;
			bool hard_coded;
		};

		MmPfnDatabaseSearchPattern patterns;

		// Windows 10 x64 Build 14332+
		static const UCHAR kPatternWin10x64[] = {
			0x48, 0x8B, 0xC1,        // mov     rax, rcx
			0x48, 0xC1, 0xE8, 0x0C,  // shr     rax, 0Ch
			0x48, 0x8D, 0x14, 0x40,  // lea     rdx, [rax + rax * 2]
			0x48, 0x03, 0xD2,        // add     rdx, rdx
			0x48, 0xB8,              // mov     rax, 0FFFFFA8000000008h
		};

		patterns.bytes = kPatternWin10x64;
		patterns.bytes_size = sizeof(kPatternWin10x64);
		patterns.hard_coded = true;
		const auto p_MmGetVirtualForPhysical = reinterpret_cast<UCHAR*>(((MmGetVirtualForPhysical)));
		if (!p_MmGetVirtualForPhysical) {

			return STATUS_PROCEDURE_NOT_FOUND;
		}

		auto found = reinterpret_cast<UCHAR*>(split_memory(p_MmGetVirtualForPhysical, 0x20, patterns.bytes, patterns.bytes_size));
		if (!found) {
			return STATUS_UNSUCCESSFUL;
		}


		found += patterns.bytes_size;
		if (patterns.hard_coded) {
			g_mmonp_MmPfnDatabase = *reinterpret_cast<void**>(found);
		}
		else {
			const auto mmpfn_address = *reinterpret_cast<ULONG_PTR*>(found);
			g_mmonp_MmPfnDatabase = *reinterpret_cast<void**>(mmpfn_address);
		}

		g_mmonp_MmPfnDatabase = PAGE_ALIGN(g_mmonp_MmPfnDatabase);

		return STATUS_SUCCESS;
	}

	uintptr_t dirbase_from_base_address(void* base)
	{
		if (!NT_SUCCESS(InitializeMmPfnDatabase()))
			return 0;

		virt_addr_t virt_base{}; virt_base.value = base;

		size_t read{};

		auto ranges = MmGetPhysicalMemoryRanges();

		for (int i = 0;; i++) {

			auto elem = &ranges[i];

			if (!elem->BaseAddress.QuadPart || !elem->NumberOfBytes.QuadPart)
				break;
			
			/*uintptr_t*/UINT64 current_phys_address = elem->BaseAddress.QuadPart;

			for (int j = 0; j < (elem->NumberOfBytes.QuadPart / 0x1000); j++, current_phys_address += 0x1000) {

				_MMPFN* pnfinfo = (_MMPFN*)((uintptr_t)g_mmonp_MmPfnDatabase + (current_phys_address >> 12) * sizeof(_MMPFN));

				if (pnfinfo->u4.PteFrame == (current_phys_address >> 12)) {
					MMPTE pml4e{};
					if (!NT_SUCCESS(read_physical(PVOID(current_phys_address + 8 * virt_base.pml4_index), &pml4e, 8, &read)))
						continue;
					
					if (!pml4e.u.Hard.Valid)
						continue;
					
					MMPTE pdpte{};
					if (!NT_SUCCESS(read_physical(PVOID((pml4e.u.Hard.PageFrameNumber << 12) + 8 * virt_base.pdpt_index), &pdpte, 8, &read)))
						continue;
					
					if (!pdpte.u.Hard.Valid)
						continue;
					
					MMPTE pde{};
					if (!NT_SUCCESS(read_physical(PVOID((pdpte.u.Hard.PageFrameNumber << 12) + 8 * virt_base.pd_index), &pde, 8, &read)))
						continue;

					if (!pde.u.Hard.Valid)
						continue;

					MMPTE pte{};
					if (!NT_SUCCESS(read_physical(PVOID((pde.u.Hard.PageFrameNumber << 12) + 8 * virt_base.pt_index), &pte, 8, &read)))
						continue;

					if (!pte.u.Hard.Valid)
						continue;

					return current_phys_address;
				}
			}
		}

		return 0;
	}

}
struct cache {
	uintptr_t Address;
	MMPTE Value;
};
static cache cached_pml4e[512];
static cache cached_pdpte[512];
static cache cached_pde[512];
static cache cached_pte[512];
auto translate_linear(
	UINT64 directory_base,
	UINT64 address) -> UINT64 {
	_virt_addr_t virtual_address{};
	virtual_address.value = PVOID(address);
	SIZE_T Size = 0;

	if (cached_pml4e[virtual_address.pml4_index].Address != directory_base + 8 * virtual_address.pml4_index || !cached_pml4e[virtual_address.pml4_index].Value.u.Hard.Valid) {
		cached_pml4e[virtual_address.pml4_index].Address = directory_base + 8 * virtual_address.pml4_index;
		Physical::ReadPhysical(PVOID(cached_pml4e[virtual_address.pml4_index].Address), reinterpret_cast<PVOID>(&cached_pml4e[virtual_address.pml4_index].Value), 8, &Size);
	}
	if (!cached_pml4e[virtual_address.pml4_index].Value.u.Hard.Valid)
		return 0;

	if (cached_pdpte[virtual_address.pdpt_index].Address != (cached_pml4e[virtual_address.pml4_index].Value.u.Hard.PageFrameNumber << 12) + 8 * virtual_address.pdpt_index || !cached_pdpte[virtual_address.pdpt_index].Value.u.Hard.Valid) {
		cached_pdpte[virtual_address.pdpt_index].Address = (cached_pml4e[virtual_address.pml4_index].Value.u.Hard.PageFrameNumber << 12) + 8 * virtual_address.pdpt_index;
		Physical::ReadPhysical(PVOID(cached_pdpte[virtual_address.pdpt_index].Address), reinterpret_cast<PVOID>(&cached_pdpte[virtual_address.pdpt_index].Value), 8, &Size);
	}

	if (!cached_pdpte[virtual_address.pdpt_index].Value.u.Hard.Valid)
		return 0;

	if (cached_pde[virtual_address.pd_index].Address != (cached_pdpte[virtual_address.pdpt_index].Value.u.Hard.PageFrameNumber << 12) + 8 * virtual_address.pd_index || !cached_pde[virtual_address.pd_index].Value.u.Hard.Valid) {
		cached_pde[virtual_address.pd_index].Address = (cached_pdpte[virtual_address.pdpt_index].Value.u.Hard.PageFrameNumber << 12) + 8 * virtual_address.pd_index;
		Physical::ReadPhysical(PVOID(cached_pde[virtual_address.pd_index].Address), reinterpret_cast<PVOID>(&cached_pde[virtual_address.pd_index].Value), 8, &Size);
	}
	if (!cached_pde[virtual_address.pd_index].Value.u.Hard.Valid)
		return 0;

	if (cached_pte[virtual_address.pt_index].Address != (cached_pde[virtual_address.pd_index].Value.u.Hard.PageFrameNumber << 12) + 8 * virtual_address.pt_index || !cached_pte[virtual_address.pt_index].Value.u.Hard.Valid) {
		cached_pte[virtual_address.pt_index].Address = (cached_pde[virtual_address.pd_index].Value.u.Hard.PageFrameNumber << 12) + 8 * virtual_address.pt_index;
		Physical::ReadPhysical(PVOID(cached_pte[virtual_address.pt_index].Address), reinterpret_cast<PVOID>(&cached_pte[virtual_address.pt_index].Value), 8, &Size);
	}

	if (!cached_pte[virtual_address.pt_index].Value.u.Hard.Valid)
		return 0;

	return (cached_pte[virtual_address.pt_index].Value.u.Hard.PageFrameNumber << 12) + virtual_address.offset;
}
NTSTATUS FKX99(prw x)
{
	if (!x->process_id) {
		return STATUS_UNSUCCESSFUL;
	}
	PEPROCESS PROCCSS = NULL;
	PsLookupProcessByProcessId((HANDLE)(x->process_id), &PROCCSS);
	if (!PROCCSS) {
		return STATUS_UNSUCCESSFUL;
	}
	INT64 physicaladdress;
	physicaladdress = translate_linear(m_stored_dtb, (ULONG64)(x->address));
	if (!physicaladdress) {
		return STATUS_UNSUCCESSFUL;
	}
	ULONG64 finalsize = find_min(PAGE_SIZE - (physicaladdress & 0xFFF), x->size);
	SIZE_T bytestrough = NULL;
	if (x->write) {
		write_phyiscal(PVOID(physicaladdress), (PVOID)((ULONG64)(x->buffer)), finalsize, &bytestrough);
	}else 
	{
		read_physical(PVOID(physicaladdress), (PVOID)((ULONG64)(x->buffer)), finalsize, &bytestrough);
	}
	return STATUS_SUCCESS;
}
NTSTATUS KEK889(pba f) {
	if (!f->process_id) {
		return STATUS_UNSUCCESSFUL;
	}
	PEPROCESS processs = NULL;
	PsLookupProcessByProcessId((HANDLE)f->process_id, &processs);
	if (!processs) {
		return STATUS_UNSUCCESSFUL;
	}
	ULONGLONG baseimg = (ULONGLONG)PsGetProcessSectionBaseAddress(processs);
	if (!baseimg) {
		return STATUS_UNSUCCESSFUL;
	}
	RtlCopyMemory(f->address, &baseimg, sizeof(baseimg));
	ObDereferenceObject(processs);
	return STATUS_SUCCESS;
}
NTSTATUS DTBBFIX(dtbl gja)
{
	dtb dtbdata = { 0 };
	if (!gja->process_id) {
		return STATUS_UNSUCCESSFUL;
	}
	PEPROCESS procc = 0;
	PsLookupProcessByProcessId((HANDLE)gja->process_id, &procc);
	if (!procc) {
		return STATUS_UNSUCCESSFUL;
	}
	m_stored_dtb = pml::dirbase_from_base_address((void*)PsGetProcessSectionBaseAddress(procc));
	ObDereferenceObject(procc);
	ULONGLONG raaa = 1;
	RtlCopyMemory(gja->operation, &raaa, sizeof(raaa));
	return STATUS_SUCCESS;
}
extern "C" {
	NTSYSCALLAPI
		NTSTATUS
		ObReferenceObjectByName(
			__in PUNICODE_STRING ObjectName,
			__in ULONG Attributes,
			__in_opt PACCESS_STATE AccessState,
			__in_opt ACCESS_MASK DesiredAccess,
			__in POBJECT_TYPE ObjectType,
			__in KPROCESSOR_MODE AccessMode,
			__inout_opt PVOID ParseContext,
			__out PVOID* Object
		);
}
extern "C" POBJECT_TYPE* IoDriverObjectType;

NTSTATUS io_controller(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);
	NTSTATUS status = { };
	ULONG bytes = { };
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	ULONG code = stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG size = stack->Parameters.DeviceIoControl.InputBufferLength;
	if (code == rw_code) {
		if (size == sizeof(_rw)) {
			prw req = (prw)(irp->AssociatedIrp.SystemBuffer);

			status = FKX99(req);
			bytes = sizeof(_rw);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}
	else if (code == dtbfix_code)
	{
		if (size == sizeof(_dtb)) {
			dtbl req = (dtbl)(irp->AssociatedIrp.SystemBuffer);

			status = DTBBFIX(req);
			bytes = sizeof(_dtb);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}
	else if (code == base_code) {
		if (size == sizeof(_ba)) {
			pba req = (pba)(irp->AssociatedIrp.SystemBuffer);
			status = KEK889(req);
			bytes = sizeof(_ba);
		}
		else
		{
			status = STATUS_INFO_LENGTH_MISMATCH;
			bytes = 0;
		}
	}
	irp->IoStatus.Status = status;
	irp->IoStatus.Information = bytes;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}
NTSTATUS unsupported_dispatch(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);

	irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS dispatch_handler(PDEVICE_OBJECT device_obj, PIRP irp) {
	UNREFERENCED_PARAMETER(device_obj);
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	switch (stack->MajorFunction) {
	case IRP_MJ_CREATE:
		break;
	case IRP_MJ_CLOSE:
		break;
	default:
		break;
	}
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}
NTSTATUS driverinit(PDRIVER_OBJECT drv_obj, PUNICODE_STRING path) {
	UNREFERENCED_PARAMETER(path);
	NTSTATUS status = { };
	PDEVICE_OBJECT device_obj = { };
	RtlInitUnicodeString(&name, L"\\Device\\staydetected");
	RtlInitUnicodeString(&link, L"\\DosDevices\\staydetected");

	status = IoCreateDevice(drv_obj, 0, &name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_obj);
	if (!NT_SUCCESS(status))
		return status;
	status = IoCreateSymbolicLink(&link, &name);
	if (!NT_SUCCESS(status))
		return status;
	for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		drv_obj->MajorFunction[i] = &unsupported_dispatch;
	device_obj->Flags |= DO_BUFFERED_IO;
	drv_obj->MajorFunction[IRP_MJ_CREATE] = &dispatch_handler;
	drv_obj->MajorFunction[IRP_MJ_CLOSE] = &dispatch_handler;
	drv_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &io_controller;
	device_obj->Flags &= ~DO_DEVICE_INITIALIZING;
	return status;
}
