
#include <afxwin.h>         // MFC 核心组件和标准组件
#include "uihelper.h"
#include <vector>
#include <Windows.h>

std::wstring ToWString(const std::string & str)
{
    int sz = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, 0, 0);
    std::vector<wchar_t> vec(sz + 1);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, vec.data(), sz);
    return std::wstring(vec.data());
}

CString ToCString(const std::string & str)
{
#ifdef UNICODE
    CString cs;
    cs.GetBuffer(str.size() * 2);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, cs.GetBuffer(), str.size() * 2);
    return cs;
#else
    return str.c_str();
#endif
}

CString ToCString(long long i, bool hex)
{
    CString cs;
    cs.Format((hex ? _T("0x%llx") : _T("%lld")), i);
    return cs;
}