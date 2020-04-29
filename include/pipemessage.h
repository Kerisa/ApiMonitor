#pragma once

#include "allocator.h"
#include <vector>

namespace PipeDefine
{
    const constexpr char* PIPE_NAME_TEMPLATE = "\\\\.\\Pipe\\{8813F049-6B99-4962-8271-3C82FCB566D5}.%d";

    enum PipeMsg
    {
        Pipe_C_Req_Inited,
        Pipe_C_Req_FilterModule,
        Pipe_C_Req_FilterApi,
        Pipe_C_Req_ModuleApiList,
        Pipe_C_Req_ApiInvoked,

        Pipe_S_Ack_Inited,
        Pipe_S_Ack_FilterModule,
        Pipe_S_Ack_FilterApi,
        Pipe_S_Ack_ApiInvoked,

        Pipe_S_Req_SuspendProcess,
        Pipe_S_Req_ResumeProcess,
        Pipe_S_Req_SetBreakCondition,

        Pipe_Msg_Total,
    };

    struct Message
    {
        static constexpr const size_t HeaderLength = sizeof(PipeMsg) + sizeof(size_t) + sizeof(DWORD);
        PipeMsg     type;
        DWORD       tid;            // tid 填入线程 id 则由指定线程接收处理，填入 -1 则由管道接收线程直接处理
        size_t      ContentSize;
        char        Content[1];
    };

namespace detail
{

    // 0            4            8    8+<size>        ?       ?     ?
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    // + total size + item1 size + item1 + item2 size + item2 + ... +
    // ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    //

    typedef long SerialHeaderSize;
    typedef short int SerialItemSize;
    constexpr size_t SerialHeaderSizeSpace = sizeof(SerialHeaderSize);
    constexpr size_t SerialItemSizeSpace = sizeof(SerialItemSize);

    bool SerialInit(std::vector<char, Allocator::allocator<char>>& str);
    bool CalFinalLength(std::vector<char, Allocator::allocator<char>>& str);
    size_t GetFirstItemIndex(std::vector<char, Allocator::allocator<char>>& str);

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
    void SerialItem(std::vector<char, Allocator::allocator<char>>& str, Allocator::string& n);

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
    size_t ExtractItem(std::vector<char, Allocator::allocator<char>>& str, size_t from_byte_index, Allocator::string& s);

} // namespace detail

namespace msg
{
    using namespace detail;

    struct Init
    {
        unsigned long dummy{ 0 };

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

    struct ModuleFilter
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


    struct ApiFilter
    {
        static constexpr long FLAG_FILTER           = 1;
        static constexpr long FLAG_BC_ALWAYS        = 2;
        static constexpr long FLAG_BC_NEXT_TIME     = 4;
        static constexpr long FLAG_BC_CALL_FROM     = 8;
        static constexpr long FLAG_BC_INVOKE_TIME   = 16;

        Allocator::string module_name;
        struct Api
        {
            long long   func_addr           { 0 };       // VA
            long        flags               { 0 };
            long        invoke_time         { 0 };
            long long   call_from           { 0 };

            bool IsFilter() const           { return flags & FLAG_FILTER;         }
            bool IsBreakALways() const      { return flags & FLAG_BC_ALWAYS;      }
            bool IsBreakNextTime() const    { return flags & FLAG_BC_NEXT_TIME;   }
            bool IsBreakCallFrom() const    { return flags & FLAG_BC_CALL_FROM;   }
            bool IsBreakInvokeTime() const  { return flags & FLAG_BC_INVOKE_TIME; }

            void SetFilter()                { flags |= FLAG_FILTER;               }
            void SetBreakALways()           { flags |= FLAG_BC_ALWAYS;            }
            void SetBreakNextTime()         { flags |= FLAG_BC_NEXT_TIME;         }
            void SetBreakCallFrom()         { flags |= FLAG_BC_CALL_FROM;         }
            void SetBreakInvokeTime()       { flags |= FLAG_BC_INVOKE_TIME;       }
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
                SerialItem(vec, apis[i].func_addr);
                SerialItem(vec, apis[i].flags);
                SerialItem(vec, apis[i].invoke_time);
                SerialItem(vec, apis[i].call_from);
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
                idx = ExtractItem(str, idx, a.func_addr);
                idx = ExtractItem(str, idx, a.flags);
                idx = ExtractItem(str, idx, a.invoke_time);
                idx = ExtractItem(str, idx, a.call_from);
            }
        }
    };

    struct ModuleApis
    {
        Allocator::string module_name;
        Allocator::string module_path;
        long long         module_base{ false };
        bool              no_reply{ false };

        struct ApiDetail
        {
            Allocator::string name;    // or original number
            Allocator::string forwardto;
            long long         va{ 0 };
            long long         rva{ 0 };
            bool              forward_api{ false };
            bool              data_export{ false };
        };
        std::vector<ApiDetail, Allocator::allocator<ApiDetail>> apis;

        std::vector<char, Allocator::allocator<char>> Serial()
        {
            std::vector<char, Allocator::allocator<char>> vec;
            SerialInit(vec);
            SerialItem(vec, module_name);
            SerialItem(vec, module_path);
            SerialItem(vec, module_base);
            SerialItem(vec, no_reply);
            size_t s = apis.size();
            SerialItem(vec, s);
            for (size_t i = 0; i < apis.size(); ++i)
            {
                SerialItem(vec, apis[i].name);
                SerialItem(vec, apis[i].forwardto);
                SerialItem(vec, apis[i].va);
                SerialItem(vec, apis[i].rva);
                SerialItem(vec, apis[i].forward_api);
                SerialItem(vec, apis[i].data_export);
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
            idx = ExtractItem(str, idx, no_reply);
            idx = ExtractItem(str, idx, array_count);
            apis.resize(array_count);
            for (size_t i = 0; i < array_count; ++i)
            {
                ApiDetail& ad = apis[i];
                idx = ExtractItem(str, idx, ad.name);
                idx = ExtractItem(str, idx, ad.forwardto);
                idx = ExtractItem(str, idx, ad.va);
                idx = ExtractItem(str, idx, ad.rva);
                idx = ExtractItem(str, idx, ad.forward_api);
                idx = ExtractItem(str, idx, ad.data_export);
            }
        }
    };

    struct ApiInvoked
    {
        Allocator::string   module_name;
        Allocator::string   api_name;
        long long           call_from{ 0 };
        unsigned long long  raw_args[3]{ 0,0,0 };
        long                times{ 0 };
        long                secret{ 0 };
        bool                wait_reply{ false };        // 触发断点

        std::vector<char, Allocator::allocator<char>> Serial()
        {
            std::vector<char, Allocator::allocator<char>> vec;
            SerialInit(vec);
            SerialItem(vec, module_name);
            SerialItem(vec, api_name);
            SerialItem(vec, call_from);
            SerialItem(vec, raw_args[0]);
            SerialItem(vec, raw_args[1]);
            SerialItem(vec, raw_args[2]);
            SerialItem(vec, times);
            SerialItem(vec, wait_reply);
            CalFinalLength(vec);
            return vec;
        }
        void Unserial(std::vector<char, Allocator::allocator<char>>& str)
        {
            size_t idx = GetFirstItemIndex(str);
            idx = ExtractItem(str, idx, module_name);
            idx = ExtractItem(str, idx, api_name);
            idx = ExtractItem(str, idx, call_from);
            idx = ExtractItem(str, idx, raw_args[0]);
            idx = ExtractItem(str, idx, raw_args[1]);
            idx = ExtractItem(str, idx, raw_args[2]);
            idx = ExtractItem(str, idx, times);
            idx = ExtractItem(str, idx, wait_reply);
        }
    };

    struct ApiInvokedReply
    {
        long                secret{ 0 };
        // 可附加断点更新信息

        std::vector<char, Allocator::allocator<char>> Serial()
        {
            std::vector<char, Allocator::allocator<char>> vec;
            SerialInit(vec);
            SerialItem(vec, secret);
            CalFinalLength(vec);
            return vec;
        }
        void Unserial(std::vector<char, Allocator::allocator<char>>& str)
        {
            size_t idx = GetFirstItemIndex(str);
            idx = ExtractItem(str, idx, secret);
        }
    };


    struct SetBreakCondition
    {
        static constexpr long FLAG_BC_ALWAYS        = 2;
        static constexpr long FLAG_BC_NEXT_TIME     = 4;
        static constexpr long FLAG_BC_CALL_FROM     = 8;
        static constexpr long FLAG_BC_INVOKE_TIME   = 16;
        long long func_addr{ 0 };
        long flags{ 0 };
        long invoke_time{ 0 };
        long long call_from{ 0 };

        std::vector<char, Allocator::allocator<char>> Serial()
        {
            std::vector<char, Allocator::allocator<char>> vec;
            SerialInit(vec);
            SerialItem(vec, func_addr);
            SerialItem(vec, flags);
            SerialItem(vec, invoke_time);
            SerialItem(vec, call_from);
            CalFinalLength(vec);
            return vec;
        }
        void Unserial(std::vector<char, Allocator::allocator<char>>& str)
        {
            size_t idx = GetFirstItemIndex(str);
            idx = ExtractItem(str, idx, func_addr);
            idx = ExtractItem(str, idx, flags);
            idx = ExtractItem(str, idx, invoke_time);
            idx = ExtractItem(str, idx, call_from);
        }
    };


} // namespace msg
} // namespace PipeDefine
