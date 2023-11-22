// FixTls.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <Windows.h>
#include <thread>
#include "FixTls.h"

typedef int(__cdecl*  pnf_test_tls_add)(int i1, int i2);
pnf_test_tls_add test_tls_add = nullptr;

int main()
{
	std::cout << "FixTls Start!" << std::endl;

	HMODULE hd = LoadLibraryW(L"TlsDllForTest.dll");
	FixTls();


	if (hd)
	{
		test_tls_add = (pnf_test_tls_add)GetProcAddress(hd, "test_tls_add");
	}

	if (test_tls_add)
	{
		for (size_t i = 0; i < 5; i++)
		{
			std::thread([&] {
				int aaa = 1;

				std::cout << "FixTls 01-->" << aaa << std::endl;

				aaa = test_tls_add(aaa, aaa);

				std::cout << "FixTls 02-->" << aaa << std::endl;
			}).join();
		}		
	}

	std::cout << "FixTls End!" << std::endl;

	getchar();

	return 0;
}