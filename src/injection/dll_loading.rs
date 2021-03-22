use winapi::um::winnt::PIMAGE_IMPORT_BY_NAME;
use winapi::um::winnt::PIMAGE_THUNK_DATA64;
use std::ffi::CStr;
use std::os::raw::c_char;
use winapi::um::winnt::PIMAGE_IMPORT_DESCRIPTOR;
use winapi::um::winnt::IMAGE_DIRECTORY_ENTRY_IMPORT;
use crate::injection::get_exe_headers;
use winapi::um::libloaderapi::FreeLibrary;
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::libloaderapi::LoadLibraryA;
use winapi::um::libloaderapi::GetModuleHandleA;
use std::ffi::CString;
use winapi::shared::ntdef::LPCSTR;
use std::time::Duration;
use crate::injection::NtGetContextThread;
use winapi::um::winnt::CONTEXT_FULL;
use crate::injection::CONTEXT;
use winapi::um::processthreadsapi::SetThreadContext;
use winapi::um::processthreadsapi::ResumeThread;
use std::thread::sleep;
use winapi::um::processthreadsapi::SuspendThread;
use winapi::um::winnt::MEM_RELEASE;
use winapi::um::winnt::MEM_DECOMMIT;
use winapi::um::memoryapi::VirtualFreeEx;
use winapi::um::errhandlingapi::GetLastError;
use std::ptr::null_mut;
use winapi::um::memoryapi::WriteProcessMemory;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use winapi::um::winnt::MEM_RESERVE;
use winapi::um::winnt::MEM_COMMIT;
use winapi::shared::ntdef::PVOID;
use winapi::um::processthreadsapi::PROCESS_INFORMATION;
use winapi::um::memoryapi::VirtualAllocEx;
use std::mem;

const DLL_LOADER: &[u8] = include_bytes!(r"..\..\inject_code\to_inject.bin");


fn encode_str_as_u64(s: &str) -> u64{
    let mut code: u64 = 0;
    for i in 0..8{
        match s.chars().nth(i){
            Some(v) => {
                code |= (v as u8 as u64) << 8*i;
            }
            None => {
                break;
            }
        }
    }
    code
}


pub struct DllLoader<'a>{
    asm_addr: u64,
    proc: &'a PROCESS_INFORMATION
}

impl<'a> Drop for DllLoader<'a>{
    fn drop(&mut self) {
        unsafe{
            VirtualFreeEx(self.proc.hProcess, self.asm_addr as PVOID, DLL_LOADER.len(), MEM_DECOMMIT | MEM_RELEASE);
        }
    }
}

impl<'a> DllLoader<'a>{
    pub unsafe fn new(proc: &'a PROCESS_INFORMATION, ld_address: u64) -> Self{
        let base_addr = ld_address - DLL_LOADER.len() as u64;

        VirtualAllocEx(proc.hProcess, base_addr as PVOID, DLL_LOADER.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
        if WriteProcessMemory(proc.hProcess, base_addr as PVOID, DLL_LOADER.as_ptr().cast(), DLL_LOADER.len(), null_mut()) == 0{
            panic!("Could not write process memory: {:X}", GetLastError());
        }

        Self{
            asm_addr: base_addr,
            proc: proc
        }
    }


    pub unsafe fn load_dll(&self, dll: &str) -> u64{
        let mut context: CONTEXT = mem::zeroed();
        context.ContextFlags = CONTEXT_FULL;
        let err = NtGetContextThread(self.proc.hThread, (&mut context as *mut CONTEXT).cast());
        if err != 0{
            panic!("Failed getting thread context - err: 0x{:X}", err);
        }

        let encoded_name = encode_str_as_u64(dll);
        context.R14 = encoded_name;
        context.Rip = self.asm_addr;

        if SetThreadContext(self.proc.hThread, (&mut context as *mut CONTEXT).cast()) == 0{
            panic!("Failed setting thread context - err: 0x{:X}", GetLastError());
        }

        ResumeThread(self.proc.hThread);

        sleep(Duration::from_millis(100));

        SuspendThread(self.proc.hThread);

        context.ContextFlags = CONTEXT_FULL;
        let err = NtGetContextThread(self.proc.hThread, (&mut context as *mut CONTEXT).cast());
        if err != 0{
            panic!("Failed getting thread context - err: 0x{:X}", err);
        }

        let load_addr = context.R15;
        load_addr
    }

    pub unsafe fn get_fn_offset(dll: &str, funcs: &[LPCSTR]) -> Vec<u64>{
        let dll_c = CString::new(dll).unwrap();
        let mut address_deltas:Vec<u64> = Vec::new();

        let mut needs_unloading = false;
        let dll_ptr = {
            // First see if it is already loaded in this process
            let n = GetModuleHandleA(dll_c.as_ptr());
            if n != null_mut(){
                n
            }
            else{
                // If not load it
                needs_unloading = true;
                LoadLibraryA(dll_c.as_ptr())
            }
        };
        if dll_ptr == null_mut(){
            panic!("Failed to load required DLL: {}", dll);
        }

        for func in funcs{
            let addr = GetProcAddress(dll_ptr, *func);
            if addr == null_mut(){
                panic!("Failed to locate symbol {:?} in DLL {}", func, dll);
            }

            println!("{}", dll_ptr as u64);
            println!("{}", addr as u64);
            address_deltas.push(
                addr as u64 - dll_ptr as u64
            );
        }

        if needs_unloading{
            FreeLibrary(dll_ptr);
        }
        address_deltas
    }

    pub unsafe fn process_pe(&self, binary: &mut [u8]){
        let (_, nt_h) = get_exe_headers(binary);
        let mut pimport_table: PIMAGE_IMPORT_DESCRIPTOR = binary.as_ptr().add(nt_h.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT as usize].VirtualAddress as usize) as PIMAGE_IMPORT_DESCRIPTOR;

        loop{
            if (*pimport_table).Name == 0{
                break;
            }

            let name: *const c_char = binary.as_ptr().add((*pimport_table).Name as usize).cast();
            let name = CStr::from_ptr(name);
            println!("Requires DLL: {:?}", name);

            let dll_load_location = self.load_dll(name.to_str().unwrap());

            let mut required_functions:Vec<LPCSTR> = Vec::new();
            let mut function_name_list:PIMAGE_THUNK_DATA64 = binary.as_ptr().add(*(*pimport_table).u.OriginalFirstThunk() as usize) as PIMAGE_THUNK_DATA64;
            
            loop{
                if *(*function_name_list).u1.AddressOfData() == 0{
                    break;
                }

                required_functions.push(
                    if 0x80000000 & (*function_name_list).u1.Ordinal() != 0{
                        let ordinal = ((*function_name_list).u1.Ordinal() & 0x0000FFFF) as LPCSTR;

                        ordinal
                    }
                    else{
                        let name: PIMAGE_IMPORT_BY_NAME = binary.as_ptr().add(*(*function_name_list).u1.AddressOfData() as usize) as _;
                        let name = (*name).Name.as_ptr() as LPCSTR;
                        
                        name
                    }
                );

                function_name_list = function_name_list.add(1);
            }

            let offsets = Self::get_fn_offset(name.to_str().unwrap(), &required_functions);

            let mut function_pointer_list:PIMAGE_THUNK_DATA64 = binary.as_ptr().add((*pimport_table).FirstThunk as usize) as PIMAGE_THUNK_DATA64;
            
            for offset in offsets{
                *(function_pointer_list as *mut u64) = dll_load_location+offset;
                function_pointer_list = function_pointer_list.add(1);
            }

            pimport_table = pimport_table.offset(1);
        }
    }
}
