#pragma once

#include <string>
#include <afxstr.h>

std::wstring ToWString(const std::string & str);
CString      ToCString(const std::string & str);
std::string  ToStdString(const CString & str);
CString      ToCString(long long i, bool hex = false);