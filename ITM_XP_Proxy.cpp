// ITM_XP_Proxy_v2.0.cpp : Target IP 마스킹(보안) 기능이 추가된 최종 배포본
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma warning(disable: 4996)

#include <windows.h>
#include <winsock2.h>
#include <process.h>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>

#pragma comment(lib, "ws2_32.lib")

const char* TARGET_IP = "10.172.111.93";
const int MAX_CONNECTIONS = 50;
volatile LONG activeConnections = 0;

const std::streampos MAX_LOG_SIZE = 2 * 1024 * 1024;

CRITICAL_SECTION logMutex;

struct ConnectionParam {
    SOCKET clientSocket;
    int targetPort;
};

// ⭐️ 보안: IP 주소 마스킹 함수 (예: 10.172.111.93 -> *.*.*.93)
std::string MaskIP(const std::string& ip) {
    size_t lastDot = ip.find_last_of('.');
    if (lastDot != std::string::npos) {
        return "*.*.*" + ip.substr(lastDot);
    }
    return ip;
}

// rename 및 open 실패를 감지하고 안전하게 넘기는 로깅 함수
void WriteLog(const std::string& msg) {
    EnterCriticalSection(&logMutex);

    std::ofstream logFile("Proxy_Log.txt", std::ios_base::app | std::ios_base::ate);

    char dt[64];
    time_t now = time(0);
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);
    strftime(dt, sizeof(dt), "%Y-%m-%d %H:%M:%S", &timeinfo);

    if (logFile.is_open()) {
        if (logFile.tellp() > MAX_LOG_SIZE) {
            logFile.close();

            remove("Proxy_Log.bak");
            // 파일 락(Lock) 등으로 인해 백업 파일 이름 변경이 실패했는지 확인
            if (rename("Proxy_Log.txt", "Proxy_Log.bak") != 0) {
                std::cout << "[" << dt << "] [Warning] Failed to rename log file for backup." << std::endl;
            }

            // 새 로그 파일 열기
            logFile.open("Proxy_Log.txt", std::ios_base::out | std::ios_base::trunc);
            // 디스크 풀, 권한 오류 등으로 새 파일을 만들지 못했는지 확인
            if (logFile.is_open()) {
                logFile << "[" << dt << "] === Log file rotated (Previous log saved as Proxy_Log.bak) ===" << std::endl;
            }
            else {
                std::cout << "[" << dt << "] [Error] Failed to create new log file." << std::endl;
            }
        }

        // 파일이 정상적으로 열려 있을 때만 기록
        if (logFile.is_open()) {
            logFile << "[" << dt << "] " << msg << std::endl;
        }
        std::cout << "[" << dt << "] " << msg << std::endl;
    }
    else {
        // 처음부터 파일을 열지 못한 경우 (권한 부족 등) 콘솔에만 출력
        std::cout << "[" << dt << "] [Error] Cannot open Proxy_Log.txt for writing." << std::endl;
        std::cout << "[" << dt << "] " << msg << std::endl;
    }

    LeaveCriticalSection(&logMutex);
}

bool SendAll(SOCKET sock, const char* buffer, int length, int& outErrorCode) {
    int totalSent = 0;
    while (totalSent < length) {
        int sent = send(sock, buffer + totalSent, length - totalSent, 0);
        if (sent == SOCKET_ERROR) {
            outErrorCode = WSAGetLastError();
            return false;
        }
        else if (sent == 0) {
            outErrorCode = WSAECONNABORTED;
            return false;
        }
        totalSent += sent;
    }
    outErrorCode = 0;
    return true;
}

bool ConnectWithTimeout(SOCKET sock, sockaddr_in& targetAddr, int timeoutSeconds, int& outErrorCode) {
    unsigned long iMode = 1;
    ioctlsocket(sock, FIONBIO, &iMode);

    int res = connect(sock, (SOCKADDR*)&targetAddr, sizeof(targetAddr));

    if (res == 0) {
        outErrorCode = 0;
        iMode = 0; ioctlsocket(sock, FIONBIO, &iMode);
        return true;
    }
    else if (res == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err != WSAEWOULDBLOCK) {
            outErrorCode = err;
            iMode = 0; ioctlsocket(sock, FIONBIO, &iMode);
            return false;
        }
    }

    fd_set Write, Err;
    FD_ZERO(&Write); FD_ZERO(&Err);
    FD_SET(sock, &Write); FD_SET(sock, &Err);

    timeval tv;
    tv.tv_sec = timeoutSeconds; tv.tv_usec = 0;

    res = select(0, NULL, &Write, &Err, &tv);

    iMode = 0;
    ioctlsocket(sock, FIONBIO, &iMode);

    if (res > 0) {
        if (FD_ISSET(sock, &Err)) {
            int so_error = 0; int len = sizeof(so_error);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len) == 0) {
                outErrorCode = so_error;
            }
            else {
                outErrorCode = WSAGetLastError();
            }
            return false;
        }

        if (FD_ISSET(sock, &Write)) {
            int so_error = 0; int len = sizeof(so_error);
            if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len) == 0) {
                if (so_error == 0) {
                    outErrorCode = 0;
                    return true;
                }
                outErrorCode = so_error;
            }
            else {
                outErrorCode = WSAGetLastError();
            }
        }
    }
    else if (res == 0) {
        outErrorCode = WSAETIMEDOUT;
    }
    else {
        outErrorCode = WSAGetLastError();
    }
    return false;
}

unsigned __stdcall ProxyWorker(void* lpParam) {
    ConnectionParam* param = (ConnectionParam*)lpParam;
    SOCKET clientSocket = param->clientSocket;
    int targetPort = param->targetPort;
    delete param;

    SOCKET targetSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (targetSocket == INVALID_SOCKET) {
        WriteLog("[Error] Worker target socket() failed: " + std::to_string(WSAGetLastError()));
        closesocket(clientSocket);
        InterlockedDecrement(&activeConnections);
        return 0;
    }

    sockaddr_in targetAddr;
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(targetPort);
    targetAddr.sin_addr.s_addr = inet_addr(TARGET_IP);

    int connectErr = 0;
    if (!ConnectWithTimeout(targetSocket, targetAddr, 3, connectErr)) {
        WriteLog("Target Server connection failed/timeout (Port: " + std::to_string(targetPort) + "), Err: " + std::to_string(connectErr));
        closesocket(clientSocket);
        closesocket(targetSocket);
        InterlockedDecrement(&activeConnections);
        return 0;
    }

    int optval = 1;
    if (setsockopt(clientSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&optval, sizeof(optval)) == SOCKET_ERROR)
        WriteLog("[Warning] setsockopt SO_KEEPALIVE (client) failed: " + std::to_string(WSAGetLastError()));
    if (setsockopt(targetSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&optval, sizeof(optval)) == SOCKET_ERROR)
        WriteLog("[Warning] setsockopt SO_KEEPALIVE (target) failed: " + std::to_string(WSAGetLastError()));

    if (setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&optval, sizeof(optval)) == SOCKET_ERROR)
        WriteLog("[Warning] setsockopt TCP_NODELAY (client) failed: " + std::to_string(WSAGetLastError()));
    if (setsockopt(targetSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&optval, sizeof(optval)) == SOCKET_ERROR)
        WriteLog("[Warning] setsockopt TCP_NODELAY (target) failed: " + std::to_string(WSAGetLastError()));

    int timeoutMs = 5000;
    if (setsockopt(clientSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeoutMs, sizeof(timeoutMs)) == SOCKET_ERROR)
        WriteLog("[Warning] setsockopt SO_SNDTIMEO (client) failed: " + std::to_string(WSAGetLastError()));
    if (setsockopt(targetSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeoutMs, sizeof(timeoutMs)) == SOCKET_ERROR)
        WriteLog("[Warning] setsockopt SO_SNDTIMEO (target) failed: " + std::to_string(WSAGetLastError()));

    if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeoutMs, sizeof(timeoutMs)) == SOCKET_ERROR)
        WriteLog("[Warning] setsockopt SO_RCVTIMEO (client) failed: " + std::to_string(WSAGetLastError()));
    if (setsockopt(targetSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeoutMs, sizeof(timeoutMs)) == SOCKET_ERROR)
        WriteLog("[Warning] setsockopt SO_RCVTIMEO (target) failed: " + std::to_string(WSAGetLastError()));

    char buffer[8192];
    fd_set readSet;
    timeval tv;

    while (true) {
        FD_ZERO(&readSet);
        FD_SET(clientSocket, &readSet);
        FD_SET(targetSocket, &readSet);

        tv.tv_sec = 60;
        tv.tv_usec = 0;

        int ret = select(0, &readSet, NULL, NULL, &tv);

        if (ret == 0) {
            WriteLog("Connection closed due to 60s inactivity timeout.");
            break;
        }
        else if (ret < 0) {
            WriteLog("Select error occurred: " + std::to_string(WSAGetLastError()));
            break;
        }

        if (FD_ISSET(clientSocket, &readSet)) {
            int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (bytesRead <= 0) {
                int err = WSAGetLastError();
                if (bytesRead == 0) {
                    // 정상 종료 로그 출력 방지 (No news is good news)
                    // WriteLog("Client closed the connection gracefully.");
                }
                else if (err == WSAETIMEDOUT) {
                    WriteLog("Client recv() timeout (SO_RCVTIMEO triggered).");
                }
                else {
                    WriteLog("Client connection dropped. Err: " + std::to_string(err));
                }
                break;
            }
            int sendErr = 0;
            if (!SendAll(targetSocket, buffer, bytesRead, sendErr)) {
                WriteLog("Failed to send data to Target. (Send Err): " + std::to_string(sendErr));
                break;
            }
        }

        if (FD_ISSET(targetSocket, &readSet)) {
            int bytesRead = recv(targetSocket, buffer, sizeof(buffer), 0);
            if (bytesRead <= 0) {
                int err = WSAGetLastError();
                if (bytesRead == 0) {
                    // 정상 종료 로그 출력 방지 (No news is good news)
                    // WriteLog("Target server closed the connection gracefully.");
                }
                else if (err == WSAETIMEDOUT) {
                    WriteLog("Target recv() timeout (SO_RCVTIMEO triggered).");
                }
                else {
                    WriteLog("Target connection dropped. Err: " + std::to_string(err));
                }
                break;
            }
            int sendErr = 0;
            if (!SendAll(clientSocket, buffer, bytesRead, sendErr)) {
                WriteLog("Failed to send data to Client. (Send Err): " + std::to_string(sendErr));
                break;
            }
        }
    }

    shutdown(clientSocket, SD_BOTH);
    shutdown(targetSocket, SD_BOTH);
    closesocket(clientSocket);
    closesocket(targetSocket);

    InterlockedDecrement(&activeConnections);
    return 0;
}

unsigned __stdcall StartListener(void* lpParam) {
    int* ports = (int*)lpParam;
    int localPort = ports[0];
    int targetPort = ports[1];
    delete[] ports;

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) {
        WriteLog("[Error] socket() creation failed for port " + std::to_string(localPort) + ", Err: " + std::to_string(WSAGetLastError()));
        return 0;
    }

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(localPort);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        WriteLog("[Error] bind() failed on port " + std::to_string(localPort) + ", Err: " + std::to_string(WSAGetLastError()));
        closesocket(listenSocket);
        return 0;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        WriteLog("[Error] listen() failed on port " + std::to_string(localPort) + ", Err: " + std::to_string(WSAGetLastError()));
        closesocket(listenSocket);
        return 0;
    }

    WriteLog("Listening on port " + std::to_string(localPort) + " -> Forwarding to " + std::to_string(targetPort));

    while (true) {
        SOCKET clientSocket = accept(listenSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            int err = WSAGetLastError();
            if (err != WSAEWOULDBLOCK && err != WSAECONNRESET) {
                WriteLog("[Error] accept() failed. Err: " + std::to_string(err));
            }
            Sleep(50);
            continue;
        }

        if (InterlockedIncrement(&activeConnections) > MAX_CONNECTIONS) {
            WriteLog("Max connections (" + std::to_string(MAX_CONNECTIONS) + ") reached. Dropped new client.");
            closesocket(clientSocket);
            InterlockedDecrement(&activeConnections);
            continue;
        }

        ConnectionParam* param = new ConnectionParam();
        param->clientSocket = clientSocket;
        param->targetPort = targetPort;

        HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, ProxyWorker, param, 0, NULL);
        if (hThread != NULL) {
            CloseHandle(hThread);
        }
        else {
            WriteLog("Failed to create worker thread. Err: " + std::to_string(GetLastError()));
            closesocket(clientSocket);
            InterlockedDecrement(&activeConnections);
            delete param;
        }
    }
    return 0;
}

int main() {
    SetConsoleTitleA("ITM Agent Proxy Server v2.0");

    HANDLE hMutex = CreateMutexA(NULL, FALSE, "ITM_XP_PROXY_MUTEX_V2_0_UNIQUE");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "[Error] ITM Proxy Server is already running!" << std::endl;
        std::cout << "Closing this instance in 3 seconds..." << std::endl;
        Sleep(3000);
        if (hMutex) CloseHandle(hMutex);
        return 1;
    }

    InitializeCriticalSection(&logMutex);

    WSADATA wsaData;
    int wsaRes = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaRes != 0) {
        std::cout << "WSAStartup failed. Err: " << wsaRes << std::endl;
        if (hMutex) CloseHandle(hMutex);
        return 1;
    }

    WriteLog("=================================================");
    WriteLog("  [ITM Proxy Server v2.0] Started for Windows XP");
    WriteLog("  Target IP : " + MaskIP(TARGET_IP));
    WriteLog("=================================================");

    int* dbPorts = new int[2] { 15432, 5432 };
    HANDLE hDbListener = (HANDLE)_beginthreadex(NULL, 0, StartListener, dbPorts, 0, NULL);
    if (hDbListener) CloseHandle(hDbListener);

    int* apiPorts = new int[2] { 18082, 8082 };
    HANDLE hApiListener = (HANDLE)_beginthreadex(NULL, 0, StartListener, apiPorts, 0, NULL);
    if (hApiListener) CloseHandle(hApiListener);

    Sleep(INFINITE);

    WSACleanup();
    DeleteCriticalSection(&logMutex);

    if (hMutex) CloseHandle(hMutex);

    return 0;
}
