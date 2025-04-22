#ifndef NTAPIS_H
#define NTAPIS_H
#include  <windows.h>

#define NT_SUCCESS(Status)  (((NTSTATUS)(Status)) >= 0)

#define InitializeObjectAttributes(p, n, a, r, s) { \
(p)->Length = sizeof(NT::OBJECT_ATTRIBUTES); \
(p)->RootDirectory = r; \
(p)->Attributes = a; \
(p)->ObjectName = n; \
(p)->SecurityDescriptor = s; \
(p)->SecurityQualityOfService = NULL; \
}

namespace  NT {
    using NTSTATUS = _Return_type_success_(return >= 0) long;

    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING, *PUNICODE_STRING;

    typedef const UNICODE_STRING *PCUNICODE_STRING;
    
    //0x30 bytes (sizeof)
    typedef struct _OBJECT_ATTRIBUTES
    {
        ULONG Length;                                                           //0x0
        VOID* RootDirectory;                                                    //0x8
        struct _UNICODE_STRING* ObjectName;                                     //0x10
        ULONG Attributes;                                                       //0x18
        VOID* SecurityDescriptor;                                               //0x20
        VOID* SecurityQualityOfService;                                         //0x28
    } OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
    typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

    typedef struct _CLIENT_ID
    {
        HANDLE UniqueProcess;
        HANDLE UniqueThread;
    } CLIENT_ID, *PCLIENT_ID;

    using NtOpenProcess = NTSTATUS(NTAPI*)(
    _Out_ PHANDLE ProcessHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PCLIENT_ID ClientId
    );

    using NtAllocateVirtualMemory = NTSTATUS(NTAPI*)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
    );

    using NtWriteVirtualMemory = NTSTATUS(NTAPI*)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_reads_bytes_(NumberOfBytesToWrite) PVOID Buffer,
    _In_ SIZE_T NumberOfBytesToWrite,
    _Out_opt_ PSIZE_T NumberOfBytesWritten
    );

    typedef struct _INITIAL_TEB
    {
        struct
        {
            PVOID OldStackBase;
            PVOID OldStackLimit;
        } OldInitialTeb;
        PVOID StackBase;
        PVOID StackLimit;
        PVOID StackAllocationBase;
    } INITIAL_TEB, *PINITIAL_TEB;

    typedef NTSTATUS (NTAPI *PUSER_THREAD_START_ROUTINE)(
    _In_ PVOID ThreadParameter
    );

    typedef struct _PS_ATTRIBUTE
    {
        ULONG_PTR Attribute;
        SIZE_T Size;
        union
        {
            ULONG_PTR Value;
            PVOID ValuePtr;
        };
        PSIZE_T ReturnLength;
    } PS_ATTRIBUTE, *PPS_ATTRIBUTE;

    typedef struct _PS_ATTRIBUTE_LIST
    {
        SIZE_T TotalLength;
        PS_ATTRIBUTE Attributes[1];
    } PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

    using NtCreateThreadEx = NTSTATUS(NTAPI*)(
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_ HANDLE ProcessHandle,
    _In_ PUSER_THREAD_START_ROUTINE StartRoutine,
    _In_opt_ PVOID Argument,
    _In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
    _In_ SIZE_T ZeroBits,
    _In_ SIZE_T StackSize,
    _In_ SIZE_T MaximumStackSize,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
    );

    using NtWaitForSingleObject = NTSTATUS(NTAPI*)(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout
    );

    using NtFreeVirtualMemory = NTSTATUS(NTAPI*)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG FreeType
    );

    using NtClose = NTSTATUS(NTAPI*)(
    _In_ HANDLE Handle
    );

    typedef enum _SECTION_INHERIT
    {
        ViewShare = 1,
        ViewUnmap = 2
    } SECTION_INHERIT;

    using NtCreatSection = NTSTATUS(NTAPI*)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
    );

    using NtMapViewOfSection = NTSTATUS(NTAPI*)(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
    );


}

#endif //NTAPIS_H
