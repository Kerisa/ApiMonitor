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
    bool SerialInit(std::vector<char, Allocator::allocator<char>>& str)
    {
        str.resize(sizeof(long));
        return true;
    }

    template<class T>
    void SerialContent(std::vector<char, Allocator::allocator<char>>& str, T& n)
    {
        union {
            long size = sizeof(T);
            char c1[sizeof(long)];
        };
        union {
            T detail;
            char c2[sizeof(T)];
        } u;
        u.detail = n;
        str.insert(str.end(), c1, c1 + sizeof(c1));
        str.insert(str.end(), u.c2, u.c2 + sizeof(u.c2));
    }
    template<>
    void SerialContent(std::vector<char, Allocator::allocator<char>>& str, Allocator::string& n)
    {
        union {
            long size;
            char c1[sizeof(long)];
        } u;
        u.size = n.size();
        str.insert(str.end(), u.c1, u.c1 + sizeof(u.c1));
        str.insert(str.end(), n.begin(), n.end());
    }
    bool CalFinalLength(std::vector<char, Allocator::allocator<char>>& str)
    {
        if (str.size() < sizeof(long))
            return false;
        *(long*)&str[0] = str.size();
        return true;
    }

    size_t GetFirstItemIndex(std::vector<char, Allocator::allocator<char>>& str)
    {
        if (str.size() > sizeof(long))
            return sizeof(long);
        else
            return 0;
    }

    template<class T>
    size_t ExtractItem(std::vector<char, Allocator::allocator<char>>& str, size_t from_byte_index, T& t)
    {
        if (str.size() <= from_byte_index + sizeof(long))
            throw "msg too short";
        
        size_t size = *(long*)&str[from_byte_index];
        if (sizeof(T) != size)
            throw "content type not match";
        if (str.size() < size + sizeof(long) + from_byte_index)
            throw "content too long";

        t = *(T*)&str[from_byte_index + sizeof(long)];
        return from_byte_index + sizeof(long) + size;
    }
    template<>
    size_t ExtractItem(std::vector<char, Allocator::allocator<char>>& str, size_t from_byte_index, Allocator::string& s)
    {
        if (str.size() <= from_byte_index + sizeof(long))
            throw "msg too short";

        size_t size = *(long*)&str[from_byte_index];
        if (str.size() < size + sizeof(long) + from_byte_index)
            throw "content too long";

        s.assign((char*)&str[from_byte_index + sizeof(long)], (char*)&str[from_byte_index + sizeof(long) + size]);
        return from_byte_index + sizeof(long) + size;
    }

    struct Msg_Init
    {
        unsigned long dummy;

        std::vector<char, Allocator::allocator<char>> Serial()
        {
            std::vector<char, Allocator::allocator<char>> vec;
            SerialInit(vec);
            SerialContent(vec, dummy);
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
            SerialContent(vec, name);
            SerialContent(vec, filter);
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
        Allocator::string api_name;
        bool              filter;

        std::vector<char, Allocator::allocator<char>> Serial()
        {
            std::vector<char, Allocator::allocator<char>> vec;
            SerialInit(vec);
            SerialContent(vec, module_name);
            SerialContent(vec, api_name);
            SerialContent(vec, filter);
            CalFinalLength(vec);
            return vec;
        }
        void Unserial(std::vector<char, Allocator::allocator<char>>& str)
        {
            size_t idx = GetFirstItemIndex(str);
            idx = ExtractItem(str, idx, module_name);
            idx = ExtractItem(str, idx, api_name);
            idx = ExtractItem(str, idx, filter);
        }
    };

    struct Msg_ModuleApis
    {
        Allocator::string module_name;

        struct ApiDetail
        {
            Allocator::string name;    // or original number
            long long         va;
            long long         rva;
            bool              forward;
        };
        std::vector<ApiDetail, Allocator::allocator<ApiDetail>> apis;
    };

    struct Msg_ApiInvoked
    {
        Allocator::string module_name;
        Allocator::string api_name;
        long              action;
    };
}
