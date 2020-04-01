// TestExe.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <sstream>
#include <Windows.h>

extern DWORD Print(int i);

int main(int argc, char** argv)
{
    std::stringstream ss;
    ss << (ULONG_PTR)OutputDebugStringA;
    ss << "  TestExe: execute main\n";
    OutputDebugStringA(ss.str().c_str());
    HANDLE nt = GetModuleHandleA("ntdll.dll");

    return (int)nt + Print(1);
}