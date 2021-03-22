use winapi::shared::basetsd::ULONG_PTR;
use crate::injection::PVOID;
use winapi::um::winnt::M128A;
use winapi::um::winnt::CONTEXT_u;
use winapi::shared::minwindef::WORD;
use winapi::shared::minwindef::DWORD;
use winapi::shared::basetsd::DWORD64;

#[repr(C)]
#[repr(align(16))]
#[allow(non_snake_case)]
pub struct CONTEXT { // FIXME align 16
    P1Home: DWORD64,
    P2Home: DWORD64,
    P3Home: DWORD64,
    P4Home: DWORD64,
    P5Home: DWORD64,
    P6Home: DWORD64,
    pub ContextFlags: DWORD,
    MxCsr: DWORD,
    SegCs: WORD,
    SegDs: WORD,
    SegEs: WORD,
    SegFs: WORD,
    SegGs: WORD,
    SegSs: WORD,
    EFlags: DWORD,
    Dr0: DWORD64,
    Dr1: DWORD64,
    Dr2: DWORD64,
    Dr3: DWORD64,
    Dr6: DWORD64,
    Dr7: DWORD64,
    Rax: DWORD64,
    pub Rcx: DWORD64,
    pub Rdx: DWORD64,
    Rbx: DWORD64,
    Rsp: DWORD64,
    Rbp: DWORD64,
    Rsi: DWORD64,
    Rdi: DWORD64,
    R8: DWORD64,
    R9: DWORD64,
    R10: DWORD64,
    R11: DWORD64,
    R12: DWORD64,
    R13: DWORD64,
    pub R14: DWORD64,
    pub R15: DWORD64,
    pub Rip: DWORD64,
    u: CONTEXT_u,
    VectorRegister: [M128A; 26],
    VectorControl: DWORD64,
    DebugControl: DWORD64,
    LastBranchToRip: DWORD64,
    LastBranchFromRip: DWORD64,
    LastExceptionToRip: DWORD64,
    LastExceptionFromRip: DWORD64,
}


#[repr(C)]
#[allow(non_snake_case)]
pub struct PROCESS_BASIC_INFO{
    Reserved1: PVOID,
    PebBaseAddress: PVOID,
    Reserved2: [PVOID; 2],
    UniqueProcessId: ULONG_PTR,
    Reserved3: PVOID
}
