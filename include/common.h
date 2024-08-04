#ifndef KAINE_COMMON_H
#define KAINE_COMMON_H

#include <stdint.h>

typedef void*              PVOID;
typedef void*              C_PTR;
typedef uintptr_t          U_PTR;
typedef char*              C_STR;
typedef wchar_t*           W_PTR;
typedef unsigned short     USHORT;
typedef unsigned char      UCHAR;
typedef uint8_t            BYTE;
typedef uint16_t           SHORT;
typedef uint32_t           ULONG;
typedef uintptr_t          QWORD;
typedef size_t             SIZE_T;
typedef unsigned long long ULONGLONG;
typedef long               LONG;
typedef void               VOID;
typedef void*              HANDLE;
typedef unsigned long      NTSTATUS;

#if defined(_WIN64)
typedef __int64 LONG_PTR;
#else
typedef long LONG_PTR;
#endif

#define NtCurrentThread()  ( (HANDLE)(LONG_PTR) -2 )
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define ZwCurrentProcess() NtCurrentProcess()
#define ZwCurrentThread()  NtCurrentThread()

#define THREAD_QUERY_INFORMATION (0x0040)
#define PROCESS_QUERY_INFORMATION (0x0400)

#define GENERIC_READ (__MSABI_LONG(0x80000000))
#define GENERIC_WRITE (__MSABI_LONG(0x40000000))
#define OPEN_EXISTING 3

enum {
    KernelMode = 0,
    UserMode   = 1
};


#define INVALID_HANDLE_VALUE ((HANDLE) (LONG_PTR)-1)
#define STATUS_SUCCESS   ((NTSTATUS)0x00000000L) // ntsubauth
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) == STATUS_SUCCESS)

typedef struct _UNICODE_STRING {
    short    Length;
    short    MaximumLength;
    wchar_t* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

//0x30 bytes (sizeof)
typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;                                                           //0x0
    VOID* RootDirectory;                                                    //0x8
    struct _UNICODE_STRING* ObjectName;                                     //0x10
    ULONG Attributes;                                                       //0x18
    VOID* SecurityDescriptor;                                               //0x20
    VOID* SecurityQualityOfService;                                         //0x28
} OBJECT_ATTRIBUTES;

//0x10 bytes (sizeof)
typedef struct _IO_STATUS_BLOCK
{
    union
    {
        LONG Status;                                                        //0x0
        VOID* Pointer;                                                      //0x0
    };
    ULONGLONG Information;                                                  //0x8
} IO_STATUS_BLOCK;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

#define InitializeObjectAttributes( p, n, a, r, s ) {   \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
	(p)->RootDirectory = r;                             \
	(p)->Attributes = a;                                \
	(p)->ObjectName = n;                                \
	(p)->SecurityDescriptor = s;                        \
	(p)->SecurityQualityOfService = 0;                  \
}

#ifndef __MSABI_LONG
#  ifndef __LP64__
#    define __MSABI_LONG(x) x ## l
#  else
#    define __MSABI_LONG(x) x
#  endif
#endif

#define DELETE (__MSABI_LONG(0x00010000))
#define READ_CONTROL (__MSABI_LONG(0x00020000))
#define WRITE_DAC (__MSABI_LONG(0x00040000))
#define WRITE_OWNER (__MSABI_LONG(0x00080000))
#define SYNCHRONIZE (__MSABI_LONG(0x00100000))

#define FILE_ATTRIBUTE_NORMAL 0x00000080
#define FILE_OPEN_IF 0x00000003
#define FILE_CREATE_TREE_CONNECTION 0x00000080

#define EPROCESS_TOKEN_OFFSET			0x4B8
#define KTHREAD_PREVIOUS_MODE_OFFSET	0x232
#define CSC_DEV_FCB_XXX_CONTROL_FILE    0x001401a3 // vuln ioctl

// rev
// private
typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
    SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
    SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
    SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
    SystemPathInformation, // not implemented
    SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
    SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
    SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
    SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION (EX in: USHORT ProcessorGroup)
    SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
    SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
    SystemModuleInformation, // q: RTL_PROCESS_MODULES
    SystemLocksInformation, // q: RTL_PROCESS_LOCKS
    SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
    SystemPagedPoolInformation, // not implemented
    SystemNonPagedPoolInformation, // not implemented
    SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
} SYSTEM_INFORMATION_CLASS;


#endif //KAINE_COMMON_H
