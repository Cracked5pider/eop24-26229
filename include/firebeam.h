#ifndef KAINE_FIREBEAM_H
#define KAINE_FIREBEAM_H

#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>

enum class VM_SYSCALL : uintptr_t {
    VM_EXIT        = 10000,
    VM_ABORT       = 10001,

    VM_HOST_CALL   = 20000,
    VM_GET_PEB     = 20001,

    VM_FB_RESPONSE    = 30000,
    VM_FB_SYMBOL_CALL,
    VM_FB_PROCEDURE,

    VM_DEBUG_PRINT = 99999
};

typedef void*     PVOID;
typedef void*     C_PTR;
typedef uintptr_t U_PTR;
typedef char*     C_STR;
typedef wchar_t*  W_PTR;
typedef uint8_t   BYTE;
typedef uint16_t  SHORT;
typedef uint32_t  ULONG;
typedef uintptr_t QWORD;

#define ALWAYS_INLINE [[gnu::always_inline]]

namespace Kaine {

    namespace debug {
        void print(
            C_STR format,
            ...
        );
    }

    namespace util {
        template<typename _Tp>
        struct remove_reference
        { using type = _Tp; };

        template<typename _Tp>
        struct remove_reference<_Tp&>
        { using type = _Tp; };

        template<typename _Tp>
        struct remove_reference<_Tp&&>
        { using type = _Tp; };

        template <class T> T&& forward(typename remove_reference<T>::type& t) noexcept {
            return static_cast<T&&>(t);
        }

        template<typename Arg>
        uintptr_t* map(
            uintptr_t  vargs[],
            uintptr_t& index,
            Arg&&      arg
        ) {
            vargs[ index++ ] = U_PTR( arg );
            return vargs;
        }

        template<typename Arg, typename ...Args>
        uintptr_t* map(
            uintptr_t  vargs[],
            uintptr_t& index,
            Arg&&      arg,
            Args&&...  args
        ) {
            vargs[ index++ ] = U_PTR( arg );
            return map( vargs, index, forward<Args>(args)... );
        }
    }

    //
    // firebeam vm apis
    //

    namespace api {
        void vmstate();

        uintptr_t response(
            U_PTR buffer,
            U_PTR length
        );

        template <typename Ret>
        Ret procedure(
            U_PTR module,
            C_STR symbol
        );

        template <class... Ts>
        uintptr_t syscall(
            VM_SYSCALL code,
            Ts...      args
        );
    }

    //
    // namespace to call win32 apis
    //

    namespace win32 {

        //
        // call win32 apis via the symbol format 'module!Function' (eg. kernel32!GetCurrentProcessId)
        //

        template <typename Ret>
        Ret call(
            C_STR symbol
        );

        template <typename Ret, class... Args>
        Ret call(
            C_STR   symbol,
            Args... args
        );

        //
        // call win32 apis via resolved pointers
        //

        template <typename Ret, class... Args>
        Ret call(
            U_PTR addr
        );

        template <typename Ret, class... Args>
        Ret call(
            U_PTR   addr,
            Args... args
        );

    }

    //
    // memory allocation
    //

    namespace mem {
        __attribute__((noinline))
        C_PTR alloc(
            U_PTR length
        );

        __attribute__((noinline))
        C_PTR realloc(
            C_PTR buffer,
            U_PTR length
        );

        __attribute__((noinline))
        void zero(
            C_PTR buffer,
            U_PTR length
        );

        __attribute__((noinline))
        void free(
            C_PTR buffer
        );
    }

    //
    // I/O functions
    //

    namespace io {
        struct {
            C_PTR buffer;
            U_PTR length;
        } _stdout = { 0, 0 };

        __attribute__((noinline))
        void print(
            C_STR format,
            ...
        ) {
            auto args   = va_list();
            auto length = U_PTR();
            auto offset = C_PTR();

            va_start( args, format );
            length = Kaine::win32::call<int>( C_STR( "_vsnprintf" ), 0, 0, format, args );
            va_end( args );

            if ( ! _stdout.buffer ) {
                //
                // if we haven't allocated any stdout buffer yet then allocate
                //
                _stdout.buffer = Kaine::mem::alloc( length );
            } else {
                _stdout.buffer = Kaine::mem::realloc( _stdout.buffer, _stdout.length + length );
            };

            offset = C_STR( U_PTR( _stdout.buffer ) + _stdout.length );

            //
            // write the formated string to the stdout buffer
            //
            va_start( args, format );
            length = Kaine::win32::call<int>( C_STR( "_vsnprintf" ), offset, length, format, args );
            va_end( args );

            _stdout.length += length;
        }

        __attribute__((noinline))
        void flush() {
            //
            // add the current stdout buffer to the response
            //
            api::response( U_PTR( _stdout.buffer ), _stdout.length );

            //
            // free the stdout memory now
            //
            Kaine::mem::zero( C_PTR( _stdout.buffer ), _stdout.length );
            Kaine::mem::free( C_PTR( _stdout.buffer ) );
            _stdout = { 0, 0 };
        }
    }

    namespace stubs {
        ALWAYS_INLINE uintptr_t syscall(
            U_PTR code
        ) {
            register uintptr_t syscall_id asm("a7") = code;
            register uintptr_t _a0        asm("a0") = 0;
            asm volatile("scall" : "+r"(_a0) : "r"(syscall_id));
            return _a0;
        }

        template <class T0>
        ALWAYS_INLINE uintptr_t syscall(
            U_PTR code,
            T0    _0
        ) {
            register uintptr_t syscall_id asm("a7") = code;
            register uintptr_t _a0        asm("a0") = _0;
            asm volatile("scall" : "+r"(_a0) : "r"(syscall_id));
            return _a0;
        }

        template <class T0, class T1>
        ALWAYS_INLINE uintptr_t syscall(
            U_PTR code,
            T0    _0,
            T1    _1
        ) {
            register uintptr_t syscall_id asm("a7") = code;
            register uintptr_t _a0        asm("a0") = _0;
            register uintptr_t _a1        asm("a1") = _1;
            asm volatile("scall" : "+r"(_a0) : "r"(_a1), "r"(syscall_id));
            return _a0;
        }

        template <class T0, class T1, class T2>
        ALWAYS_INLINE uintptr_t syscall(
            U_PTR code,
            T0    _0,
            T1    _1,
            T2    _2
        ) {
            register uintptr_t syscall_id asm("a7") = code;
            register uintptr_t _a0        asm("a0") = _0;
            register uintptr_t _a1        asm("a1") = _1;
            register uintptr_t _a2        asm("a2") = _2;
            asm volatile("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(syscall_id));
            return _a0;
        }

        template <class T0, class T1, class T2, class T3>
        ALWAYS_INLINE uintptr_t syscall(
            U_PTR code,
            T0    _0,
            T1    _1,
            T2    _2,
            T3    _3
        ) {
            register uintptr_t syscall_id asm("a7") = code;
            register uintptr_t _a0        asm("a0") = _0;
            register uintptr_t _a1        asm("a1") = _1;
            register uintptr_t _a2        asm("a2") = _2;
            register uintptr_t _a3        asm("a3") = _3;
            asm volatile("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(syscall_id));
            return _a0;
        }

        template <class T0, class T1, class T2, class T3, class T4>
        ALWAYS_INLINE uintptr_t syscall(
            U_PTR code,
            T0    _0,
            T1    _1,
            T2    _2,
            T3    _3,
            T4    _4
        ) {
            register uintptr_t syscall_id asm("a7") = code;
            register uintptr_t _a0        asm("a0") = _0;
            register uintptr_t _a1        asm("a1") = _1;
            register uintptr_t _a2        asm("a2") = _2;
            register uintptr_t _a3        asm("a3") = _3;
            register uintptr_t _a4        asm("a4") = _4;
            asm volatile("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(syscall_id));
            return _a0;
        }

        template <class T0, class T1, class T2, class T3, class T4, class T5>
        ALWAYS_INLINE uintptr_t syscall(
            U_PTR code,
            T0    _0,
            T1    _1,
            T2    _2,
            T3    _3,
            T4    _4,
            T5    _5
        ) {
            register uintptr_t syscall_id asm("a7") = code;
            register uintptr_t _a0        asm("a0") = _0;
            register uintptr_t _a1        asm("a1") = _1;
            register uintptr_t _a2        asm("a2") = _2;
            register uintptr_t _a3        asm("a3") = _3;
            register uintptr_t _a4        asm("a4") = _4;
            register uintptr_t _a5        asm("a5") = _5;
            asm volatile("scall" : "+r"(_a0) : "r"(_a1), "r"(_a2), "r"(_a3), "r"(_a4), "r"(_a5), "r"(syscall_id));
            return _a0;
        }
    }

    namespace api {
        void vmstate() {
            asm volatile( ".byte 0x13, 0x00, 0x00, 0x00" );
        }

        template <typename Ret>
        Ret procedure(
            U_PTR module,
            C_STR symbol
        ) {
            return Ret( api::syscall( VM_SYSCALL::VM_FB_PROCEDURE, module, U_PTR( symbol ) ) );
        }

        uintptr_t response(
            U_PTR buffer,
            U_PTR length
        ) {
            return api::syscall( VM_SYSCALL::VM_FB_RESPONSE, buffer, length );
        }

        template <class... Args>
        ALWAYS_INLINE uintptr_t syscall(
            VM_SYSCALL code,
            Args...    args
        ) {
            return stubs::syscall( (uintptr_t)code, (args)... );
        }
    }

    //
    // implementations
    //

    namespace win32 {

        //
        // call win32 apis via the symbol format 'module!Function' (eg. kernel32!GetCurrentProcessId)
        //

        template <typename Ret>
        Ret call(
            C_STR symbol
        ) {
            uintptr_t args[ 13 ] = { 0 };

            return Ret( api::syscall( VM_SYSCALL::VM_FB_SYMBOL_CALL, U_PTR( symbol ), U_PTR( args ) ) );
        }

        template <typename Ret, class... Args>
        Ret call(
            C_STR   symbol,
            Args... args
        ) {
            uintptr_t vargs[ sizeof...(args) ] = { 0 };
            uintptr_t index                    = { 0 };

            util::map( vargs, index, args... );

            return Ret( api::syscall( VM_SYSCALL::VM_FB_SYMBOL_CALL, U_PTR( symbol ), U_PTR( vargs ) ) );
        }

        //
        // call win32 apis via resolved pointers
        //

        template <typename Ret, class... Args>
        Ret call(
            U_PTR addr
        ) {
            uintptr_t args[ 13 ] = { 0 };

            return Ret( api::syscall( VM_SYSCALL::VM_HOST_CALL, addr, U_PTR( args ) ) );
        }

        template <typename Ret, class... Args>
        Ret call(
            U_PTR   addr,
            Args... args
        ) {
            uintptr_t vargs[ sizeof...(args) ] = { 0 };
            uintptr_t index                    = { 0 };

            util::map( vargs, index, args... );

            return Ret( api::syscall( VM_SYSCALL::VM_HOST_CALL, addr, U_PTR( vargs ) ) );
        }
    }

    namespace mem {
        __attribute__((noinline))
        C_PTR alloc(
            U_PTR length
        ) {
            auto Handle = Kaine::win32::call<C_PTR>( C_STR( "GetProcessHeap" ) );

            return Kaine::win32::call<C_PTR>( C_STR( "RtlAllocateHeap" ), Handle, 0x00000008, length );
        }

        template <typename T> __attribute__((noinline))
        T alloc(
            U_PTR length
        ) {
            auto Handle = Kaine::win32::call<C_PTR>( C_STR( "GetProcessHeap" ) );

            return Kaine::win32::call<T>( C_STR( "RtlAllocateHeap" ), Handle, 0x00000008, length );
        }

        __attribute__((noinline))
        C_PTR realloc(
            C_PTR buffer,
            U_PTR length
        ) {
            auto Handle = Kaine::win32::call<C_PTR>( C_STR( "GetProcessHeap" ) );

            return Kaine::win32::call<C_PTR>( C_STR( "RtlReAllocateHeap" ), Handle, 0x00000008, buffer, length );
        }

        template <typename T> __attribute__((noinline))
        T realloc(
            C_PTR buffer,
            U_PTR length
        ) {
            auto Handle = Kaine::win32::call<C_PTR>( C_STR( "GetProcessHeap" ) );

            return Kaine::win32::call<T>( C_STR( "RtlReAllocateHeap" ), Handle, 0x00000008, buffer, length );
        }

        __attribute__((noinline))
        void zero(
            C_PTR buffer,
            U_PTR length
        ) {
            Kaine::win32::call<C_PTR>( C_STR( "RtlZeroMemory" ), buffer, length );
        }

        __attribute__((noinline))
        void free(
            C_PTR buffer
        ) {
            auto Handle = Kaine::win32::call<C_PTR>( C_STR( "GetProcessHeap" ) );
            Kaine::win32::call<C_PTR>( C_STR( "RtlFreeHeap" ), Handle, 0x00000008, buffer );
        }
    }

    namespace debug {
        void print(
            C_STR format,
            ...
        ) {
            auto args   = va_list();
            auto length = U_PTR();
            auto buffer = C_PTR();

            //
            // get the size to allocate
            //
            va_start( args, format );
            length = Kaine::win32::call<int>( C_STR( "_vsnprintf" ), 0, 0, format, args );
            va_end( args );

            if ( ! ( buffer = Kaine::mem::alloc( length ) ) ) {
                return;
            }

            //
            // write the formated string to the stdout buffer
            //
            va_start( args, format );
            length = Kaine::win32::call<int>( C_STR( "_vsnprintf" ), buffer, length, format, args );
            va_end( args );

            api::syscall( VM_SYSCALL::VM_DEBUG_PRINT, U_PTR( buffer ) );

            Kaine::mem::free( buffer );
        }
    }

}

#endif //KAINE_FIREBEAM_H
