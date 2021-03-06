#![windows_subsystem = "windows"]

mod bindings {
    ::windows::include_bindings!();
}

use bindings::windows::{
    win32::{
        shell::ShellExecuteExW,
        system_services::{WaitForSingleObject, HANDLE, HINSTANCE},
        windows_and_messaging::{MessageBoxW, HWND},
        windows_programming::HKEY,
    },
    Error, ErrorCode, Result,
};

const E_INVALIDARG: u32 = 0x80070057;
const INFINITE: u32 = 0xFFFFFFFF;
const MB_ICONINFORMATION: u32 = 0x00000040;
const MB_OK: u32 = 0x0000000;
const SEE_MASK_FLAG_NO_UI: u32 = 0x00000400;
const SEE_MASK_NOCLOSEPROCESS: u32 = 0x00000040;
const SW_SHOWDEFAULT: i32 = 10;
const WAIT_FAILED: u32 = 0xFFFFFFFF;

struct Command {
    program: String,
    args: Vec<String>,
    wait: bool,
}

#[repr(C)]
struct SHELLEXECUTEINFOW {
    cb_size: u32,
    f_mask: u32,
    hwnd: HWND,
    lp_verb: *const u16,
    lp_file: *const u16,
    lp_parameters: *const u16,
    lp_directory: *const u16,
    n_show: i32,
    h_inst_app: HINSTANCE,
    lp_id_list: *const std::ffi::c_void,
    lp_class: *const u16,
    hkey_class: HKEY,
    dw_hot_key: u32,
    h_icon_or_h_monitor: HANDLE,
    h_process: HANDLE,
}

fn to_u16vec(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsString::from(s)
        .encode_wide()
        .chain(Some(0))
        .collect()
}

fn show_message_box(message: &str) {
    unsafe {
        MessageBoxW(
            HWND(0),
            to_u16vec(message).as_ptr(),
            to_u16vec(std::env!("CARGO_PKG_NAME")).as_ptr(),
            MB_OK | MB_ICONINFORMATION,
        );
    }
}

fn parse_command_line() -> Result<Option<Command>> {
    let mut opts = getopts::Options::new();
    opts.parsing_style(getopts::ParsingStyle::StopAtFirstFree);
    opts.optflag("h", "help", "print this help and exit");
    opts.optflag("v", "version", "print the version and exit");
    opts.optflag("w", "wait", "wait the program to exit");

    let matches = opts
        .parse(std::env::args().skip(1))
        .map_err(|fail| Error::new(ErrorCode(E_INVALIDARG), &fail.to_string()))?;

    if matches.opt_present("h") {
        show_message_box(&opts.usage(&format!(
            "Usage: {} [OPTION] PROGRAM [ARGS...]",
            std::env!("CARGO_BIN_NAME")
        )));
        return Ok(None);
    }

    if matches.opt_present("v") {
        show_message_box(&format!(
            "{} {}",
            std::env!("CARGO_PKG_NAME"),
            std::env!("CARGO_PKG_VERSION")
        ));
        return Ok(None);
    }

    if matches.free.is_empty() {
        return Err(Error::new(ErrorCode(E_INVALIDARG), "Program missing"));
    }
    Ok(Some(Command {
        program: matches.free[0].clone(),
        args: matches.free[1..].to_vec(),
        wait: matches.opt_present("w"),
    }))
}

fn join_args<T: AsRef<str>>(args: &[T]) -> String {
    let r = regex::Regex::new(r#"\\|""#).unwrap();
    args.iter()
        .map(|arg| format!(r#""{}""#, r.replace_all(arg.as_ref(), r"\$0")))
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn test_join_args() {
    assert_eq!(join_args(&["a", "b c"]), r#""a" "b c""#);
    assert_eq!(join_args(&[r#""a""#, r#"\"b\""#]), r#""\"a\"" "\\\"b\\\"""#);
}

fn run_as_administrator(command: Command) -> Result<()> {
    let verb = to_u16vec("runas");
    let file = to_u16vec(&command.program);
    let parameters = to_u16vec(&join_args(&command.args));
    let mut exec_info = SHELLEXECUTEINFOW {
        cb_size: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        f_mask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI,
        hwnd: HWND(0),
        lp_verb: verb.as_ptr(),
        lp_file: file.as_ptr(),
        lp_parameters: parameters.as_ptr(),
        lp_directory: std::ptr::null(),
        n_show: SW_SHOWDEFAULT,
        h_inst_app: HINSTANCE(0),
        lp_id_list: std::ptr::null(),
        lp_class: std::ptr::null(),
        hkey_class: HKEY(0),
        dw_hot_key: 0,
        h_icon_or_h_monitor: HANDLE(0),
        h_process: HANDLE(0),
    };
    unsafe {
        ShellExecuteExW(std::mem::transmute(&mut exec_info)).ok()?;
    }
    if command.wait {
        let result = unsafe { WaitForSingleObject(exec_info.h_process, INFINITE) };
        if result == WAIT_FAILED {
            return Err(Error::from(ErrorCode::from_thread()));
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    if let Some(command) = parse_command_line()? {
        run_as_administrator(command)?
    }
    Ok(())
}
