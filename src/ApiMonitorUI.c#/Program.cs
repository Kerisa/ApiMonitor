using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ApiMonitorUI
{
    class Monitor
    {

        typedef struct reloc_line
        {
            WORD m_addr : 12;
            WORD m_type : 4;
        }
        reloc_line;

void LoadVReloc(ULONG_PTR hBase, bool bForce, ULONG_PTR delta)
        {
            PIMAGE_NT_HEADERS imNH = (PIMAGE_NT_HEADERS)(hBase + ((PIMAGE_DOS_HEADER)hBase)->e_lfanew);
            if (imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0)
                return; // 没有重定位数据
            if (hBase == imNH->OptionalHeader.ImageBase && bForce == FALSE)
                return; // 装入了默认地址
            if (delta == 0)
                delta = hBase - imNH->OptionalHeader.ImageBase;
            ULONG_PTR lpreloc = hBase + imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
            PIMAGE_BASE_RELOCATION pimBR = (PIMAGE_BASE_RELOCATION)lpreloc;
            while (pimBR->VirtualAddress != 0)
            {
                reloc_line* reline = (reloc_line*)((char*)pimBR + sizeof(IMAGE_BASE_RELOCATION));
                int preNum = (pimBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(reloc_line);
                for (int i = 0; i < preNum; ++i)
                {
                    switch (reline->m_type)
                    {
                        case IMAGE_REL_BASED_HIGHLOW:
                            *(PDWORD)(hBase + pimBR->VirtualAddress + reline->m_addr) += delta;
                            break;
                        case IMAGE_REL_BASED_DIR64:
                            *(ULONG_PTR*)(hBase + pimBR->VirtualAddress + reline->m_addr) += delta;
                            break;
                    }
                    ++reline;
                }
                pimBR = (PIMAGE_BASE_RELOCATION)reline;
            }
        }


        PVOID BuildRemoteData(HANDLE hProcess, const TCHAR* dllPath)
        {
            HMODULE hDll2 = LoadLibraryEx(dllPath, NULL, 0);
            ULONG_PTR entry = (ULONG_PTR)GetProcAddress(hDll2, "Entry");
            HANDLE hDll = CreateFile(dllPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
            if (hDll == INVALID_HANDLE_VALUE)
                return NULL;
            std::vector<char> file(GetFileSize(hDll, 0));
            SIZE_T R;
            ReadFile(hDll, file.data(), file.size(), &R, 0);
            CloseHandle(hDll);

            char* imageData = (char*)file.data();
            PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(imageData + ((PIMAGE_DOS_HEADER)imageData)->e_lfanew);
            DWORD imageSize = ntHeader->OptionalHeader.SizeOfImage;
            std::vector<char> memData(imageSize);
            PIMAGE_SECTION_HEADER secHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)ntHeader + sizeof(IMAGE_NT_HEADERS));
            DWORD secHeaderBegin = secHeader->VirtualAddress;
            for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
            {
                if (secHeader->PointerToRawData != 0)
                    secHeaderBegin = min(secHeader->PointerToRawData, secHeaderBegin);
                memcpy(&memData[secHeader->VirtualAddress], imageData + secHeader->PointerToRawData, secHeader->SizeOfRawData);
                ++secHeader;
            }
            memcpy(memData.data(), imageData, secHeaderBegin); // 复制 pe 头
            PVOID newBase = VirtualAllocEx(hProcess, 0, imageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            ULONG_PTR delta = (ULONG_PTR)newBase - (ULONG_PTR)ntHeader->OptionalHeader.ImageBase;
            if (delta != 0) // 需要重定位
                LoadVReloc((ULONG_PTR)memData.data(), TRUE, delta);
            SIZE_T W = 0;
            WriteProcessMemory(hProcess, newBase, memData.data(), imageSize, &W);
            PVOID oep = (PVOID)(entry - (ULONG_PTR)hDll2 + (ULONG_PTR)newBase);


            HMODULE ntDllBase = GetModuleHandleA("ntdll.dll");
            auto pLdrLoadDll = (FN_LdrLoadDll)GetProcAddress(ntDllBase, "LdrLoadDll");
            vector < unsigned char> remoteMemory(0x200);
            ReadProcessMemory(hProcess, (LPVOID)((ULONG_PTR)pLdrLoadDll - 0x100), remoteMemory.data(), remoteMemory.size(), &R);
            bool found = false;
            size_t position = 0;
            for (size_t i = 0x100; i > 0 && !found; --i)
            {
                if (remoteMemory[i] == 0xcc)
                {
                    int k = 0;
                    for (; k < 7; ++k)
                        if (remoteMemory[i - k] != 0xcc)
                            break;
                    if (k == 7)
                    {
                        found = true;
                        position = i - 6;
                    }
                }
            }
            assert(found);
            if (found)
            {
                char jmp[2];
                jmp[0] = '\xeb';
                jmp[1] = position - (0x100 + 0x2);
                WriteProcessMemory(hProcess, (LPVOID)pLdrLoadDll, jmp, sizeof(jmp), &R);

                auto hook = GetProcAddress(hDll2, "HookLdrLoadDllPad");
                char jmp2[6];
                jmp2[0] = '\x68';
                *(PDWORD) & jmp2[1] = (DWORD)((ULONG_PTR)hook - (ULONG_PTR)hDll2 + (ULONG_PTR)newBase);
                jmp2[5] = '\xc3';
                WriteProcessMemory(hProcess, (LPVOID)((ULONG_PTR)pLdrLoadDll - 0x100 + position), jmp2, sizeof(jmp2), &R);
            }

            FreeLibrary(hDll2);
            return oep;
        }


    }


    static class Program
    {
        /// <summary>
        /// 应用程序的主入口点。
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new ApiMonitor());
        }

        public static bool LoadFile(string exeFilePath)
        {
            return false;
        }
    }
}
