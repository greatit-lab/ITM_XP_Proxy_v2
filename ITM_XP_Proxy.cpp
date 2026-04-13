// ITM_XP_Proxy_v2.2.cpp : 동적 IP 변경 사항을 ini 파일에 영구 저장(Persistence)하는 기능 추가본
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

// ─────────────────────────────────────────────────────────────
// 전역 설정 및 동적 IP 관리
// ─────────────────────────────────────────────────────────────
std::string g_TargetIP; // 설정 파일에서 읽어올 타겟 IP
const std::string DEFAULT_IP = "10.172.111.93"; // 설정 파일이 없을 때의 기본값
const std::string INI_FILE_NAME = ".\\Proxy_Settings.ini";

CRITICAL_SECTION g_TargetIpMutex;
const int CONTROL_PORT = 19000;

const int MAX_CONNECTIONS = 50;
volatile LONG activeConnections = 0;

const std::streampos MAX_LOG_SIZE = 2 * 1024 * 1024;
CRITICAL_SECTION logMutex;

struct ConnectionParam {
    SOCKET clientSocket;
    int targetPort;
};

// IP 주소 마스킹 함수
std::string MaskIP(const std::string& ip) {
    size_t lastDot = ip.find_last_of('.');
    if (lastDot != std::string::npos) {
        return "*.*.*" + ip.substr(lastDot);
    }
    return ip;
}

// ─────────────────────────────────────────────────────────────
// [신규] INI 파일 읽기/쓰기 유틸리티 함수
// ─────────────────────────────────────────────────────────────
void LoadTargetIpFromIni() {
    char ipBuffer[128] = { 0 };
    GetPrivateProfileStringA("Network", "TargetIP", DEFAULT_IP.c_str(), ipBuffer, sizeof(ipBuffer), INI_FILE_NAME.c_str());
    g_TargetIP = std::string(ipBuffer);

    // 만약 파일이 없어서 기본값을 읽어왔다면, 즉시 파일을 생성하여 기본값을 기록함
    WritePrivateProfileStringA("Network", "TargetIP", g_TargetIP.c_str(), INI_FILE_NAME.c_str());
}

void SaveTargetIpToIni(const std::string& newIp) {
    WritePrivateProfileStringA("Network", "TargetIP", newIp.c_str(), INI_FILE_NAME.c_str());
}

// 로깅 함수 (기존 상세 로깅 100% 유지)
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
            if (rename("Proxy_Log.txt", "Proxy_Log.bak") != 0) {
                std::cout << "[" << dt << "] [Warning] Failed to rename log file for backup." << std::endl;
            }

            logFile.open("Proxy_Log.txt", std::ios_base::out | std::ios_base::trunc);
            if (logFile.is_open()) {
                logFile << "[" << dt << "] === Log file rotated (Previous log saved as Proxy_Log.bak) ===" << std::endl;
            }
            else {
                std::cout << "[" << dt << "] [Error] Failed to create new log file." << std::endl;
            }
        }

        if (logFile.is_open()) {
            logFile << "[" << dt << "] " << msg << std::endl;
        }
        std::cout << "[" << dt << "] " << msg << std::endl;
    }
    else {
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

    std::string currentTargetIP;
    EnterCriticalSection(&g_TargetIpMutex);
    currentTargetIP = g_TargetIP;
    LeaveCriticalSection(&g_TargetIpMutex);

    sockaddr_in targetAddr;
    targetAddr.sin_family = AF_INET;
    targetAddr.sin_port = htons(targetPort);
    targetAddr.sin_addr.s_addr = inet_addr(currentTargetIP.c_str());

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

// 제어 포트(19000) 리스너 
unsigned __stdcall ControlListener(void* lpParam) {
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET) return 0;

    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(CONTROL_PORT);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    if (bind(listenSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        closesocket(listenSocket);
        return 0;
    }

    if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(listenSocket);
        return 0;
    }

    WriteLog("Control Listener active on port " + std::to_string(CONTROL_PORT) + " (Ready for Hot-Reload)");

    while (true) {
        SOCKET clientSocket = accept(listenSocket, NULL, NULL);
        if (clientSocket == INVALID_SOCKET) {
            Sleep(50);
            continue;
        }

        char buf[256];
        int bytes = recv(clientSocket, buf, sizeof(buf) - 1, 0);
        if (bytes > 0) {
            buf[bytes] = '\0';
            std::string msg(buf);

            // 프로토콜 검사: "CHANGE_IP:10.x.x.x"
            if (msg.find("CHANGE_IP:") == 0) {
                std::string newIp = msg.substr(10);

                size_t endpos = newIp.find_last_not_of(" \n\r\t");
                if (std::string::npos != endpos) {
                    newIp = newIp.substr(0, endpos + 1);
                }

                // 1. 메모리 업데이트
                EnterCriticalSection(&g_TargetIpMutex);
                g_TargetIP = newIp;
                LeaveCriticalSection(&g_TargetIpMutex);

                // 2. INI 파일 영구 저장 (v2.2 핵심 로직)
                SaveTargetIpToIni(newIp);

                WriteLog("[HOT-RELOAD] Proxy Target IP dynamically updated and saved to INI: " + MaskIP(newIp));

                const char* okMsg = "OK";
                send(clientSocket, okMsg, strlen(okMsg), 0);
            }
        }
        closesocket(clientSocket);
    }
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
    SetConsoleTitleA("ITM Agent Proxy Server v2.2");

    HANDLE hMutex = CreateMutexA(NULL, FALSE, "ITM_XP_PROXY_MUTEX_V2_2_UNIQUE");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "[Error] ITM Proxy Server is already running!" << std::endl;
        std::cout << "Closing this instance in 3 seconds..." << std::endl;
        Sleep(3000);
        if (hMutex) CloseHandle(hMutex);
        return 1;
    }

    InitializeCriticalSection(&logMutex);
    InitializeCriticalSection(&g_TargetIpMutex);

    WSADATA wsaData;
    int wsaRes = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaRes != 0) {
        std::cout << "WSAStartup failed. Err: " << wsaRes << std::endl;
        if (hMutex) CloseHandle(hMutex);
        return 1;
    }

    // ─────────────────────────────────────────────────────────────
    // [신규] 최초 기동 시 INI 파일에서 IP를 읽어오도록 처리
    // ─────────────────────────────────────────────────────────────
    LoadTargetIpFromIni();

    WriteLog("=================================================");
    WriteLog("  [ITM Proxy Server v2.2] Started for Windows XP");
    WriteLog("  Target IP Loaded  : " + MaskIP(g_TargetIP));
    WriteLog("=================================================");

    int* dbPorts = new int[2] { 15432, 5432 };
    HANDLE hDbListener = (HANDLE)_beginthreadex(NULL, 0, StartListener, dbPorts, 0, NULL);
    if (hDbListener) CloseHandle(hDbListener);

    int* apiPorts = new int[2] { 18082, 8082 };
    HANDLE hApiListener = (HANDLE)_beginthreadex(NULL, 0, StartListener, apiPorts, 0, NULL);
    if (hApiListener) CloseHandle(hApiListener);

    HANDLE hControlListener = (HANDLE)_beginthreadex(NULL, 0, ControlListener, NULL, 0, NULL);
    if (hControlListener) CloseHandle(hControlListener);

    Sleep(INFINITE);

    WSACleanup();
    DeleteCriticalSection(&logMutex);
    DeleteCriticalSection(&g_TargetIpMutex);

    if (hMutex) CloseHandle(hMutex);

    return 0;
}
