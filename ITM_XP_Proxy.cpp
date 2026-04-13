// ITM_XP_Proxy_v2.1.cpp : Target IP 마스킹 및 Agent 제어형 동적 IP 변경(Hot-Reload) 기능 포함
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
// 전역 설정 및 동적 IP 관리 (v2.1 신규)
// ─────────────────────────────────────────────────────────────
std::string g_TargetIP = "10.172.111.93"; // 기본 타겟 IP
CRITICAL_SECTION g_TargetIpMutex;
const int CONTROL_PORT = 19000;           // Agent 제어용 포트

const int MAX_CONNECTIONS = 50;
volatile LONG activeConnections = 0;
const std::streampos MAX_LOG_SIZE = 2 * 1024 * 1024;
CRITICAL_SECTION logMutex;

struct ConnectionParam {
    SOCKET clientSocket;
    int targetPort;
};

// IP 주소 마스킹 (보안)
std::string MaskIP(const std::string& ip) {
    size_t lastDot = ip.find_last_of('.');
    if (lastDot != std::string::npos) {
        return "*.*.*" + ip.substr(lastDot);
    }
    return ip;
}

// 스레드 안전 로깅 함수
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
            rename("Proxy_Log.txt", "Proxy_Log.bak");
            logFile.open("Proxy_Log.txt", std::ios_base::out | std::ios_base::trunc);
        }
        if (logFile.is_open()) logFile << "[" << dt << "] " << msg << std::endl;
        std::cout << "[" << dt << "] " << msg << std::endl;
    }
    LeaveCriticalSection(&logMutex);
}

bool SendAll(SOCKET sock, const char* buffer, int length, int& outErrorCode) {
    int totalSent = 0;
    while (totalSent < length) {
        int sent = send(sock, buffer + totalSent, length - totalSent, 0);
        if (sent <= 0) {
            outErrorCode = (sent == 0) ? WSAECONNABORTED : WSAGetLastError();
            return false;
        }
        totalSent += sent;
    }
    return true;
}

bool ConnectWithTimeout(SOCKET sock, sockaddr_in& targetAddr, int timeoutSeconds, int& outErrorCode) {
    unsigned long iMode = 1;
    ioctlsocket(sock, FIONBIO, &iMode);
    int res = connect(sock, (SOCKADDR*)&targetAddr, sizeof(targetAddr));

    if (res == 0) {
        iMode = 0; ioctlsocket(sock, FIONBIO, &iMode);
        return true;
    }
    
    fd_set Write, Err;
    FD_ZERO(&Write); FD_ZERO(&Err);
    FD_SET(sock, &Write); FD_SET(sock, &Err);
    timeval tv = { timeoutSeconds, 0 };

    res = select(0, NULL, &Write, &Err, &tv);
    iMode = 0; ioctlsocket(sock, FIONBIO, &iMode);

    if (res > 0 && FD_ISSET(sock, &Write) && !FD_ISSET(sock, &Err)) return true;
    outErrorCode = (res == 0) ? WSAETIMEDOUT : WSAGetLastError();
    return false;
}

// ─────────────────────────────────────────────────────────────
// 프록시 워커 (실제 데이터 중계)
// ─────────────────────────────────────────────────────────────
unsigned __stdcall ProxyWorker(void* lpParam) {
    ConnectionParam* param = (ConnectionParam*)lpParam;
    SOCKET clientSocket = param->clientSocket;
    int targetPort = param->targetPort;
    delete param;

    SOCKET targetSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    
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
        WriteLog("Target Server connection failed (Port: " + std::to_string(targetPort) + "), Err: " + std::to_string(connectErr));
        closesocket(clientSocket);
        closesocket(targetSocket);
        InterlockedDecrement(&activeConnections);
        return 0;
    }

    // 소켓 옵션 설정 (KeepAlive, NoDelay, Timeouts)
    int opt = 1; int timeoutMs = 5000;
    setsockopt(clientSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(opt));
    setsockopt(targetSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&opt, sizeof(opt));
    setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
    setsockopt(targetSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeoutMs, sizeof(timeoutMs));
    setsockopt(targetSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeoutMs, sizeof(timeoutMs));

    char buffer[8192];
    fd_set readSet;
    timeval tv = { 60, 0 };

    while (true) {
        FD_ZERO(&readSet);
        FD_SET(clientSocket, &readSet);
        FD_SET(targetSocket, &readSet);

        int ret = select(0, &readSet, NULL, NULL, &tv);
        if (ret <= 0) break;

        if (FD_ISSET(clientSocket, &readSet)) {
            int bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (bytesRead <= 0) break;
            int err = 0;
            if (!SendAll(targetSocket, buffer, bytesRead, err)) break;
        }

        if (FD_ISSET(targetSocket, &readSet)) {
            int bytesRead = recv(targetSocket, buffer, sizeof(buffer), 0);
            if (bytesRead <= 0) break;
            int err = 0;
            if (!SendAll(clientSocket, buffer, bytesRead, err)) break;
        }
    }

    shutdown(clientSocket, SD_BOTH); shutdown(targetSocket, SD_BOTH);
    closesocket(clientSocket); closesocket(targetSocket);
    InterlockedDecrement(&activeConnections);
    return 0;
}

// ─────────────────────────────────────────────────────────────
// 제어 포트 리스너 (Hot-Reload 명령 수신용 v2.1)
// ─────────────────────────────────────────────────────────────
unsigned __stdcall ControlListener(void* lpParam) {
    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr = { AF_INET, htons(CONTROL_PORT), INADDR_ANY };
    bind(listenSocket, (SOCKADDR*)&addr, sizeof(addr));
    listen(listenSocket, SOMAXCONN);

    WriteLog("Control Listener active on port " + std::to_string(CONTROL_PORT) + " (Ready for v2.1 commands)");

    while (true) {
        SOCKET client = accept(listenSocket, NULL, NULL);
        if (client == INVALID_SOCKET) continue;

        char buf[256] = { 0 };
        int bytes = recv(client, buf, sizeof(buf) - 1, 0);
        if (bytes > 0) {
            std::string msg(buf);
            if (msg.find("CHANGE_IP:") == 0) {
                std::string newIp = msg.substr(10);
                newIp.erase(newIp.find_last_not_of(" \n\r\t") + 1);

                EnterCriticalSection(&g_TargetIpMutex);
                g_TargetIP = newIp;
                LeaveCriticalSection(&g_TargetIpMutex);

                WriteLog("[v2.1 HOT-RELOAD] Target IP updated to: " + MaskIP(newIp));
                send(client, "OK", 2, 0);
            }
        }
        closesocket(client);
    }
    return 0;
}

unsigned __stdcall StartListener(void* lpParam) {
    int* p = (int*)lpParam;
    int lPort = p[0], tPort = p[1]; delete[] p;

    SOCKET listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in addr = { AF_INET, htons(lPort), INADDR_ANY };
    bind(listenSock, (SOCKADDR*)&addr, sizeof(addr));
    listen(listenSock, SOMAXCONN);

    WriteLog("Proxy Port Open: " + std::to_string(lPort) + " -> Target Port: " + std::to_string(tPort));

    while (true) {
        SOCKET client = accept(listenSock, NULL, NULL);
        if (client == INVALID_SOCKET) continue;

        if (InterlockedIncrement(&activeConnections) > MAX_CONNECTIONS) {
            closesocket(client); InterlockedDecrement(&activeConnections);
            continue;
        }

        ConnectionParam* param = new ConnectionParam { client, tPort };
        HANDLE h = (HANDLE)_beginthreadex(NULL, 0, ProxyWorker, param, 0, NULL);
        if (h) CloseHandle(h); else { closesocket(client); InterlockedDecrement(&activeConnections); delete param; }
    }
    return 0;
}

int main() {
    SetConsoleTitleA("ITM Agent Proxy Server v2.1");

    HANDLE hMutex = CreateMutexA(NULL, FALSE, "ITM_XP_PROXY_V2_1_MUTEX");
    if (GetLastError() == ERROR_ALREADY_EXISTS) return 1;

    InitializeCriticalSection(&logMutex);
    InitializeCriticalSection(&g_TargetIpMutex);

    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);

    WriteLog("=================================================");
    WriteLog("  [ITM Proxy Server v2.1] Started for Windows XP");
    WriteLog("  Initial Target IP : " + MaskIP(g_TargetIP));
    WriteLog("=================================================");

    // 서비스별 포트 중계 시작
    _beginthreadex(NULL, 0, StartListener, new int[2]{ 15432, 5432 }, 0, NULL);
    _beginthreadex(NULL, 0, StartListener, new int[2]{ 18082, 8082 }, 0, NULL);
    _beginthreadex(NULL, 0, ControlListener, NULL, 0, NULL);

    Sleep(INFINITE);

    WSACleanup();
    DeleteCriticalSection(&logMutex); DeleteCriticalSection(&g_TargetIpMutex);
    return 0;
}
