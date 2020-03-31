// TestExe.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <Windows.h>

extern DWORD Print(int i);

int main(int argc, char** argv)
{
    OutputDebugStringA("TestExe: execute main\n");
    HANDLE nt = GetModuleHandleA("ntdll.dll");

    return (int)nt + Print(1);
}