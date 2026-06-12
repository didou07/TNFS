#ifndef PLATFORM_H
#define PLATFORM_H

#ifdef _WIN32
  #ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0600
  #endif
  #include <winsock2.h>
  #include <windows.h>
  #include <ws2tcpip.h>
  #include <wincrypt.h>
  #pragma comment(lib, "ws2_32.lib")
  #pragma comment(lib, "advapi32.lib")
  typedef SOCKET sock_t;
  #define SOCK_INVALID  INVALID_SOCKET
  #define sock_close    closesocket
  #define THREAD_RET    DWORD WINAPI
  #define THREAD_ARG    LPVOID
#else
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <pthread.h>
  #include <sys/time.h>
  typedef int sock_t;
  #define SOCK_INVALID  (-1)
  #define sock_close    close
  #define THREAD_RET    void *
  #define THREAD_ARG    void *
  #define Sleep(ms)     usleep((ms)*1000)
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <stdarg.h>

#endif
