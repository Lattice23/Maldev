#ifndef HEADER_H
#define HEADER_H
#include <iostream>
#include <Windows.h>
#include <string>
#include <winhttp.h>
#include <vector>

struct URL {
    std::string url {};
    std::string host{};
    std::string file{};
    std::string port{};
};

std::vector<BYTE> makeRequest(const URL& format);
void injectProcess(std::vector<BYTE>& buffer);
URL formatURL(URL& format);
#endif //HEADER_H
