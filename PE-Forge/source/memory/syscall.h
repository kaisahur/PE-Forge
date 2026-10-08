#pragma once

#ifndef _WIN64
#error "PE Forge requires x64"
#endif

#include <Windows.h>

#include <cstdint>

#ifndef NT_SUCCESS
#define NT_SUCCESS( s ) ( ( ( NTSTATUS )( s ) ) >= 0 )
#endif

#define STATUS_SUCCESS              0x00000000L
#define STATUS_BUFFER_TOO_SMALL     0xC0000023L
#define STATUS_BUFFER_OVERFLOW      0x80000005L
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L

typedef struct _unicode_string_t
{
    USHORT length;
    USHORT maximum_length;
    PWSTR buffer;
} unicode_string_t;

typedef struct _object_attributes_t
{
    ULONG length;
    HANDLE root_directory;
    unicode_string_t* object_name;
    ULONG attributes;
    PVOID security_descriptor;
    PVOID security_quality_of_service;
} object_attributes_t;

typedef struct _client_id_t
{
    HANDLE unique_process;
    HANDLE unique_thread;
} client_id_t;

typedef struct _io_status_block_t
{
    union
    {
        NTSTATUS status;
        PVOID pointer;
    };
    ULONG_PTR information;
} io_status_block_t;

typedef struct _process_basic_information_t
{
    NTSTATUS exit_status;
    PVOID peb_base_address;
    ULONG_PTR affinity_mask;
    LONG base_priority;
    ULONG_PTR unique_process_id;
    ULONG_PTR inherited_from_unique_process_id;
} process_basic_information_t;

typedef struct _system_process_information_t
{
    ULONG next_entry_offset;
    ULONG number_of_threads;
    LARGE_INTEGER spare[ 3 ];
    LARGE_INTEGER create_time;
    LARGE_INTEGER user_time;
    LARGE_INTEGER kernel_time;
    unicode_string_t image_name;
    LONG base_priority;
    HANDLE unique_process_id;
    HANDLE inherited_from_unique_process_id;
    ULONG handle_count;
    ULONG session_id;
    ULONG_PTR unique_process_key;
    SIZE_T peak_virtual_size;
    SIZE_T virtual_size;
    ULONG page_fault_count;
    SIZE_T peak_working_set_size;
    SIZE_T working_set_size;
    SIZE_T quota_peak_paged_pool_usage;
    SIZE_T quota_paged_pool_usage;
    SIZE_T quota_peak_non_paged_pool_usage;
    SIZE_T quota_non_paged_pool_usage;
    SIZE_T pagefile_usage;
    SIZE_T peak_pagefile_usage;
    SIZE_T private_page_count;
    LARGE_INTEGER read_operation_count;
    LARGE_INTEGER write_operation_count;
    LARGE_INTEGER other_operation_count;
    LARGE_INTEGER read_transfer_count;
    LARGE_INTEGER write_transfer_count;
    LARGE_INTEGER other_transfer_count;
} system_process_information_t;

enum processinfoclass_t : ULONG
{
    proc_basic_information = 0,
    proc_debug_port = 7,
    proc_wow64_information = 26,
    proc_image_file_name = 27,
    proc_image_information = 50,
    proc_protection_information = 61,
};

enum system_information_class_t : ULONG
{
    sys_basic_information = 0,
    sys_process_information = 5,
};

enum memory_information_class_t : ULONG
{
    mem_basic_information = 0,
    mem_mapped_file_name = 2,
    mem_region_information = 3,
};

extern "C"
{
    extern DWORD g_ssn_nt_read_virtual_memory;
    extern DWORD g_ssn_nt_write_virtual_memory;
    extern DWORD g_ssn_nt_query_virtual_memory;
    extern DWORD g_ssn_nt_open_process;
    extern DWORD g_ssn_nt_close;
    extern DWORD g_ssn_nt_query_information_process;
    extern DWORD g_ssn_nt_allocate_virtual_memory;
    extern DWORD g_ssn_nt_free_virtual_memory;
    extern DWORD g_ssn_nt_protect_virtual_memory;
    extern DWORD g_ssn_nt_query_system_information;
    extern DWORD g_ssn_nt_suspend_process;
    extern DWORD g_ssn_nt_resume_process;
    extern DWORD g_ssn_nt_create_file;
    extern DWORD g_ssn_nt_write_file;
    extern DWORD g_ssn_nt_flush_buffers_file;
}

extern "C"
{
    NTSTATUS nt_read_virtual_memory_stub( HANDLE process_handle, PVOID base_address, PVOID buffer, ULONG num_bytes_to_read, PULONG num_bytes_read );

    NTSTATUS
    nt_write_virtual_memory_stub( HANDLE process_handle, PVOID base_address, PVOID buffer, ULONG num_bytes_to_write, PULONG num_bytes_written );

    NTSTATUS nt_query_virtual_memory_stub(
        HANDLE process_handle,
        PVOID base_address,
        ULONG memory_info_class,
        PVOID memory_info,
        SIZE_T memory_info_len,
        PSIZE_T return_length );

    NTSTATUS nt_open_process_stub( PHANDLE process_handle, ACCESS_MASK desired_access, object_attributes_t* object_attrs, client_id_t* client_id );

    NTSTATUS nt_close_stub( HANDLE handle );

    NTSTATUS
    nt_query_information_process_stub( HANDLE process_handle, ULONG info_class, PVOID process_info, ULONG process_info_len, PULONG return_length );

    NTSTATUS nt_allocate_virtual_memory_stub(
        HANDLE process_handle,
        PVOID* base_address,
        ULONG_PTR zero_bits,
        PSIZE_T region_size,
        ULONG allocation_type,
        ULONG protect );

    NTSTATUS nt_free_virtual_memory_stub( HANDLE process_handle, PVOID* base_address, PSIZE_T region_size, ULONG free_type );

    NTSTATUS
    nt_protect_virtual_memory_stub( HANDLE process_handle, PVOID* base_address, PSIZE_T region_size, ULONG new_protection, PULONG old_protection );

    NTSTATUS nt_query_system_information_stub( ULONG info_class, PVOID system_info, ULONG system_info_len, PULONG return_length );

    NTSTATUS nt_suspend_process_stub( HANDLE process_handle );
    NTSTATUS nt_resume_process_stub( HANDLE process_handle );

    NTSTATUS nt_create_file_stub(
        PHANDLE file_handle,
        ACCESS_MASK desired_access,
        object_attributes_t* object_attrs,
        io_status_block_t* io_status_block,
        PLARGE_INTEGER allocation_size,
        ULONG file_attributes,
        ULONG share_access,
        ULONG create_disposition,
        ULONG create_options,
        PVOID ea_buffer,
        ULONG ea_length );

    NTSTATUS nt_write_file_stub(
        HANDLE file_handle,
        HANDLE event,
        PVOID apc_routine,
        PVOID apc_context,
        io_status_block_t* io_status_block,
        PVOID buffer,
        ULONG length,
        PLARGE_INTEGER byte_offset,
        PULONG key );

    NTSTATUS nt_flush_buffers_file_stub( HANDLE file_handle, io_status_block_t* io_status_block );
}

bool syscall_initialize( );
