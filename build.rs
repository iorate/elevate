fn main() {
    windows::build!(
        windows::win32::shell::ShellExecuteExW,
        windows::win32::system_services::WaitForSingleObject,
        windows::win32::windows_and_messaging::MessageBoxW,
    );
}
