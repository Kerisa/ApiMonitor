#pragma once

#include "allocator.h"
#include <vector>

namespace PipeDefine
{
    const char* PIPE_NAME = "\\\\.\\Pipe\\{8813F049-6B99-4962-8271-3C82FCB566D5}";

    enum MsgReq
    {
        Pipe_Req_Inited,
        Pipe_Req_FilterModule,
        Pipe_Req_FilterApi,
        Pipe_Req_ModuleApiList,
        Pipe_Req_ApiInvoked,
    };

    enum MsgAck
    {
        Pipe_Ack_Inited,
        Pipe_Ack_FilterModule,
        Pipe_Ack_FilterApi,
        Pipe_Ack_ApiInvoked,
    };

    struct Message
    {
        static constexpr const size_t HeaderLength = sizeof(MsgReq) + sizeof(size_t);
        union {
            MsgReq Req;
            MsgAck Ack;
        };
        static_assert(sizeof(MsgReq) == sizeof(MsgAck), "sizeof(MsgReq) == sizeof(MsgAck)");

        size_t ContentSize;
        char Content[1];
    };

    // 0            4            8    8+<size>        ?       ?     ?
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // + total size + item1 size + item1 + item2 size + item2 + ... +
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    //

    typedef long SerialHeaderSize;
    typedef short int SerialItemSize;
    constexpr size_t SerialHeaderSizeSpace = sizeof(SerialHeaderSize);
    constexpr size_t SerialItemSizeSpace = sizeof(SerialItemSize);

    bool SerialInit(std::vector<char, Allocator::allocator<char>>& str)
    {
        str.resize(SerialHeaderSizeSpace);
        return true;
    }

    template<class T>
    void SerialItem(std::vector<char, Allocator::allocator<char>>& str, T& n)
    {
        union {
            SerialItemSize size = sizeof(T);
            char c1[SerialItemSizeSpace];
        };
        static_assert(sizeof(size) == sizeof(c1), "");
        union {
            T detail;
            char c2[sizeof(T)];
        } u;
        static_assert(sizeof(u.detail) == sizeof(u.c2), "");
        u.detail = n;
        str.insert(str.end(), c1, c1 + sizeof(c1));
        str.insert(str.end(), u.c2, u.c2 + sizeof(u.c2));
    }
    template<>
    void SerialItem(std::vector<char, Allocator::allocator<char>>& str, Allocator::string& n)
    {
        union {
            SerialItemSize size;
            char c1[SerialItemSizeSpace];
        } u;
        static_assert(sizeof(u.size) == sizeof(u.c1), "");
        u.size = n.size();
        str.insert(str.end(), u.c1, u.c1 + sizeof(u.c1));
        str.insert(str.end(), n.begin(), n.end());
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

    template<class T>
    size_t ExtractItem(std::vector<char, Allocator::allocator<char>>& str, size_t from_byte_index, T& t)
    {
        if (str.size() <= from_byte_index + SerialItemSizeSpace)
            throw "msg too short";
        
        SerialItemSize size = *(SerialItemSize*)&str[from_byte_index];
        if (sizeof(T) != size)
            throw "content type not match";
        if (str.size() < size + SerialItemSizeSpace + from_byte_index)
            throw "content too long";

        t = *(T*)&str[from_byte_index + SerialItemSizeSpace];
        return from_byte_index + SerialItemSizeSpace + size;
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

    struct Msg_Init
    {
        unsigned long dummy;

        std::vector<char, Allocator::allocator<char>> Serial()
        {
            std::vector<char, Allocator::allocator<char>> vec;
            SerialInit(vec);
            SerialItem(vec, dummy);
            CalFinalLength(vec);
            return vec;
        }
        void Unserial(std::vector<char, Allocator::allocator<char>>& str)
        {
            size_t idx = GetFirstItemIndex(str);
            ExtractItem(str, idx, dummy);
        }
    };

    struct Msg_ModuleFilter
    {
        Allocator::string name;
        bool              filter;

        std::vector<char, Allocator::allocator<char>> Serial()
        {
            std::vector<char, Allocator::allocator<char>> vec;
            SerialInit(vec);
            SerialItem(vec, name);
            SerialItem(vec, filter);
            CalFinalLength(vec);
            return vec;
        }
        void Unserial(std::vector<char, Allocator::allocator<char>>& str)
        {
            size_t idx = GetFirstItemIndex(str);
            idx = ExtractItem(str, idx, name);
            ExtractItem(str, idx, filter);
        }
    };


    struct Msg_ApiFilter
    {
        Allocator::string module_name;
        struct Api
        {
            Allocator::string api_name;
            bool              filter;
        };
        std::vector<Api, Allocator::allocator<Api>> apis;

        std::vector<char, Allocator::allocator<char>> Serial()
        {
            size_t s = apis.size();
            std::vector<char, Allocator::allocator<char>> vec;
            SerialInit(vec);
            SerialItem(vec, module_name);
            SerialItem(vec, s);
            for (size_t i = 0; i < apis.size(); ++i)
            {
                SerialItem(vec, apis[i].api_name);
                SerialItem(vec, apis[i].filter);
            }
            CalFinalLength(vec);
            return vec;
        }
        void Unserial(std::vector<char, Allocator::allocator<char>>& str)
        {
            size_t idx = GetFirstItemIndex(str);
            size_t array_count = 0;
            idx = ExtractItem(str, idx, module_name);
            idx = ExtractItem(str, idx, array_count);
            apis.resize(array_count);
            for (size_t i = 0; i < array_count; ++i)
            {
                Api& a = apis[i];
                idx = ExtractItem(str, idx, a.api_name);
                idx = ExtractItem(str, idx, a.filter);
            }
        }
    };

    struct Msg_ModuleApis
    {
        Allocator::string module_name;
        Allocator::string module_path;
        long long         module_base;

        struct ApiDetail
        {
            Allocator::string name;    // or original number
            long long         va;
            long long         rva;
            bool              forward_api;
            bool              data_api;
        };
        std::vector<ApiDetail, Allocator::allocator<ApiDetail>> apis;

        std::vector<char, Allocator::allocator<char>> Serial()
        {
            std::vector<char, Allocator::allocator<char>> vec;
            SerialInit(vec);
            SerialItem(vec, module_name);
            SerialItem(vec, module_path);
            SerialItem(vec, module_base);
            size_t s = apis.size();
            SerialItem(vec, s);
            for (size_t i = 0; i < apis.size(); ++i)
            {
                SerialItem(vec, apis[i].name);
                SerialItem(vec, apis[i].va);
                SerialItem(vec, apis[i].rva);
                SerialItem(vec, apis[i].forward_api);
                SerialItem(vec, apis[i].data_api);
            }
            CalFinalLength(vec);
            return vec;
        }
        void Unserial(std::vector<char, Allocator::allocator<char>>& str)
        {
            size_t idx = GetFirstItemIndex(str);
            size_t array_count = 0;
            idx = ExtractItem(str, idx, module_name);
            idx = ExtractItem(str, idx, module_path);
            idx = ExtractItem(str, idx, module_base);
            idx = ExtractItem(str, idx, array_count);
            apis.resize(array_count);
            for (size_t i = 0; i < array_count; ++i)
            {
                ApiDetail& ad = apis[i];
                idx = ExtractItem(str, idx, ad.name);
                idx = ExtractItem(str, idx, ad.va);
                idx = ExtractItem(str, idx, ad.rva);
                idx = ExtractItem(str, idx, ad.forward_api);
                idx = ExtractItem(str, idx, ad.data_api);
            }
        }
    };

    struct Msg_ApiInvoked
    {
        Allocator::string module_name;
        Allocator::string api_name;
        long              action;
    };
}
