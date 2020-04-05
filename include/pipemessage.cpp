#pragma once

#include "allocator.h"
#include <vector>
#include "pipemessage.h"

namespace PipeDefine
{

namespace detail
{
    bool SerialInit(std::vector<char, Allocator::allocator<char>>& str)
    {
        str.resize(SerialHeaderSizeSpace);
        return true;
    }

    bool CalFinalLength(std::vector<char, Allocator::allocator<char>>& str)
    {
        if (str.size() < SerialHeaderSizeSpace)
            return false;
        *(SerialHeaderSize*)&str[0] = str.size();
        return true;
    }

    size_t GetFirstItemIndex(std::vector<char, Allocator::allocator<char>>& str)
    {
        if (str.size() > SerialHeaderSizeSpace)
            return SerialHeaderSizeSpace;
        else
            return 0;
    }

    template<>
    void SerialItem(std::vector<char, Allocator::allocator<char>>& str, Allocator::string& n)
    {
        union {
            SerialItemSize size;
            char c1[SerialItemSizeSpace];
        } u;
        static_assert(sizeof(u.size) == sizeof(u.c1), "");
        if (n.size() > USHRT_MAX)
            throw "item size too large";
        u.size = static_cast<SerialItemSize>(n.size());
        str.insert(str.end(), u.c1, u.c1 + sizeof(u.c1));
        str.insert(str.end(), n.begin(), n.end());
    }

    template<>
    size_t ExtractItem(std::vector<char, Allocator::allocator<char>>& str, size_t from_byte_index, Allocator::string& s)
    {
        if (str.size() <= from_byte_index + SerialItemSizeSpace)
            throw "msg too short";

        SerialItemSize size = *(SerialItemSize*)&str[from_byte_index];
        if (str.size() < size + SerialItemSizeSpace + from_byte_index)
            throw "content too long";

        s.assign((char*)&str[from_byte_index + SerialItemSizeSpace], (char*)&str[from_byte_index + SerialItemSizeSpace + size]);
        return from_byte_index + SerialItemSizeSpace + size;
    }

} // namespace detail

} // namespace PipeDefine
