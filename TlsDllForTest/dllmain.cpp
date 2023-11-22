// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <string>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}



thread_local int aaa = 100;//测试tls变量

extern "C"  __declspec(dllexport)
int  __cdecl  test_tls_add(int i1, int i2)
{
	static std::wstring str_safe_static = L"100";//测试static变量，并且开启了 /Zc:threadSafeInit 
	aaa += 2;
	str_safe_static += L"0";	

	int aa = aaa + _wtoi(str_safe_static.c_str()) + i1 + i2;

	return aa;
}
