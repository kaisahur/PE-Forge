OPTION CASEMAP:NONE

.DATA

PUBLIC g_ssn_nt_read_virtual_memory
PUBLIC g_ssn_nt_write_virtual_memory
PUBLIC g_ssn_nt_query_virtual_memory
PUBLIC g_ssn_nt_open_process
PUBLIC g_ssn_nt_close
PUBLIC g_ssn_nt_query_information_process
PUBLIC g_ssn_nt_allocate_virtual_memory
PUBLIC g_ssn_nt_free_virtual_memory
PUBLIC g_ssn_nt_protect_virtual_memory
PUBLIC g_ssn_nt_query_system_information
PUBLIC g_ssn_nt_suspend_process
PUBLIC g_ssn_nt_resume_process
PUBLIC g_ssn_nt_create_file
PUBLIC g_ssn_nt_write_file
PUBLIC g_ssn_nt_flush_buffers_file

g_ssn_nt_read_virtual_memory DWORD 0
g_ssn_nt_write_virtual_memory DWORD 0
g_ssn_nt_query_virtual_memory DWORD 0
g_ssn_nt_open_process DWORD 0
g_ssn_nt_close DWORD 0
g_ssn_nt_query_information_process DWORD 0
g_ssn_nt_allocate_virtual_memory DWORD 0
g_ssn_nt_free_virtual_memory DWORD 0
g_ssn_nt_protect_virtual_memory DWORD 0
g_ssn_nt_query_system_information DWORD 0
g_ssn_nt_suspend_process DWORD 0
g_ssn_nt_resume_process DWORD 0
g_ssn_nt_create_file DWORD 0
g_ssn_nt_write_file DWORD 0
g_ssn_nt_flush_buffers_file DWORD 0

.CODE

; NTSTATUS NtReadVirtualMemory(
;   HANDLE ProcessHandle,
;   PVOID BaseAddress,
;   PVOID Buffer,
;   ULONG NumberOfBytesToRead,
;   PULONG NumberOfBytesRead)
PUBLIC nt_read_virtual_memory_stub
nt_read_virtual_memory_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_read_virtual_memory]
    syscall
    ret
nt_read_virtual_memory_stub ENDP

; NTSTATUS NtWriteVirtualMemory(
;   HANDLE ProcessHandle,
;   PVOID BaseAddress,
;   PVOID Buffer,
;   ULONG NumberOfBytesToWrite,
;   PULONG NumberOfBytesWritten)
PUBLIC nt_write_virtual_memory_stub
nt_write_virtual_memory_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_write_virtual_memory]
    syscall
    ret
nt_write_virtual_memory_stub ENDP

; NTSTATUS NtQueryVirtualMemory(
;   HANDLE ProcessHandle,
;   PVOID BaseAddress,
;   ULONG MemoryInformationClass,
;   PVOID MemoryInformation,
;   SIZE_T MemoryInformationLength,
;   PSIZE_T ReturnLength)
PUBLIC nt_query_virtual_memory_stub
nt_query_virtual_memory_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_query_virtual_memory]
    syscall
    ret
nt_query_virtual_memory_stub ENDP

; NTSTATUS NtOpenProcess(
;   PHANDLE ProcessHandle,
;   ACCESS_MASK DesiredAccess,
;   POBJECT_ATTRIBUTES ObjectAttributes,
;   PCLIENT_ID ClientId)
PUBLIC nt_open_process_stub
nt_open_process_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_open_process]
    syscall
    ret
nt_open_process_stub ENDP

; NTSTATUS NtClose(HANDLE Handle)
PUBLIC nt_close_stub
nt_close_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_close]
    syscall
    ret
nt_close_stub ENDP

; NTSTATUS NtQueryInformationProcess(
;   HANDLE ProcessHandle,
;   ULONG ProcessInformationClass,
;   PVOID ProcessInformation,
;   ULONG ProcessInformationLength,
;   PULONG ReturnLength)
PUBLIC nt_query_information_process_stub
nt_query_information_process_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_query_information_process]
    syscall
    ret
nt_query_information_process_stub ENDP

; NTSTATUS NtAllocateVirtualMemory(
;   HANDLE ProcessHandle,
;   PVOID* BaseAddress,
;   ULONG_PTR ZeroBits,
;   PSIZE_T RegionSize,
;   ULONG AllocationType,
;   ULONG Protect)
PUBLIC nt_allocate_virtual_memory_stub
nt_allocate_virtual_memory_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_allocate_virtual_memory]
    syscall
    ret
nt_allocate_virtual_memory_stub ENDP

; NTSTATUS NtFreeVirtualMemory(
;   HANDLE  ProcessHandle,
;   PVOID*  BaseAddress,
;   PSIZE_T RegionSize,
;   ULONG   FreeType)
PUBLIC nt_free_virtual_memory_stub
nt_free_virtual_memory_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_free_virtual_memory]
    syscall
    ret
nt_free_virtual_memory_stub ENDP

; NTSTATUS NtProtectVirtualMemory(
;   HANDLE  ProcessHandle,
;   PVOID*  BaseAddress,
;   PSIZE_T RegionSize,
;   ULONG   NewAccessProtection,
;   PULONG  OldAccessProtection)
PUBLIC nt_protect_virtual_memory_stub
nt_protect_virtual_memory_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_protect_virtual_memory]
    syscall
    ret
nt_protect_virtual_memory_stub ENDP

; NTSTATUS NtQuerySystemInformation(
;   ULONG   SystemInformationClass,
;   PVOID   SystemInformation,
;   ULONG   SystemInformationLength,
;   PULONG  ReturnLength)
PUBLIC nt_query_system_information_stub
nt_query_system_information_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_query_system_information]
    syscall
    ret
nt_query_system_information_stub ENDP

; NTSTATUS NtSuspendProcess(HANDLE ProcessHandle)
PUBLIC nt_suspend_process_stub
nt_suspend_process_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_suspend_process]
    syscall
    ret
nt_suspend_process_stub ENDP

; NTSTATUS NtResumeProcess(HANDLE ProcessHandle)
PUBLIC nt_resume_process_stub
nt_resume_process_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_resume_process]
    syscall
    ret
nt_resume_process_stub ENDP

; NTSTATUS NtCreateFile(
;   PHANDLE FileHandle,
;   ACCESS_MASK DesiredAccess,
;   POBJECT_ATTRIBUTES ObjectAttributes,
;   PIO_STATUS_BLOCK IoStatusBlock,
;   PLARGE_INTEGER AllocationSize,
;   ULONG FileAttributes,
;   ULONG ShareAccess,
;   ULONG CreateDisposition,
;   ULONG CreateOptions,
;   PVOID EaBuffer,
;   ULONG EaLength)
PUBLIC nt_create_file_stub
nt_create_file_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_create_file]
    syscall
    ret
nt_create_file_stub ENDP

; NTSTATUS NtWriteFile(
;   HANDLE FileHandle,
;   HANDLE Event,
;   PVOID ApcRoutine,
;   PVOID ApcContext,
;   PIO_STATUS_BLOCK IoStatusBlock,
;   PVOID Buffer,
;   ULONG Length,
;   PLARGE_INTEGER ByteOffset,
;   PULONG Key)
PUBLIC nt_write_file_stub
nt_write_file_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_write_file]
    syscall
    ret
nt_write_file_stub ENDP

; NTSTATUS NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock)
PUBLIC nt_flush_buffers_file_stub
nt_flush_buffers_file_stub PROC
    mov r10, rcx
    mov eax, DWORD PTR [g_ssn_nt_flush_buffers_file]
    syscall
    ret
nt_flush_buffers_file_stub ENDP

END
