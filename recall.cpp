#include <dlfcn.h>
#include <execinfo.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
    extern "C" {
#endif
        static void (*real_free)(void*) = NULL;
        static void* (*real_malloc)(size_t) = NULL;
#ifdef __cplusplus
    }
#endif

void backtrace() {
    void *callstack[128];
    int i, frames;
    char **strs = NULL;

    frames = ::backtrace(callstack, 128);
    strs = backtrace_symbols(callstack, frames);

    for (i = 0; i < frames && 0; ++i) {
        fprintf(stdout, "%d: %s\n", i, strs[i]);
        ////find first occurence of '(' or ' ' in message[i] and assume
        ////everything before that is the file name. (Don't go beyond 0 though
        ////* (string terminator)
        //size_t p = 0;
        //while(strs[i][p] != '(' && strs[i][p] != ' ' && strs[i][p] != 0) {
        //    ++p;
        //}
        //char syscom[256];
        //sprintf(syscom,"addr2line %p -e %.*s", callstack[i], p, strs[i]);
        ////last parameter is the file name of the symbol
        //system(syscom);
    }

    //real_free(strs);
}

#ifdef __cplusplus
    #include <array>
    #include <map>
    #include <mutex>

    namespace recall {
        // Use custom map allocator since standard map allocator will use
        // overriden new operator leading to infinite recursion
        template<typename T>
        struct map_alloc
            : std::allocator<T> {
            typedef typename std::allocator<T>::pointer pointer;
            typedef typename std::allocator<T>::size_type size_type;

            template<typename U>
            struct rebind {
                typedef map_alloc<U> other;
            };

            map_alloc() {}

            template<typename U>
            map_alloc(map_alloc<U> const& u)
                : std::allocator<T>(u) {}

            pointer allocate(size_type size, std::allocator<void>::const_pointer = 0) {
                auto msize = size * sizeof(T);
                void *ptr = NULL;
                if (real_malloc != NULL) {
                    ptr = real_malloc(msize == 0 ? 1 : msize);
                } else {
                    ptr = malloc(msize == 0 ? 1 : msize);
                }
                if(ptr == NULL) {
                    throw std::bad_alloc();
                }
                return static_cast<pointer>(ptr);
            }

            void deallocate(pointer p, size_type size) {
                    real_free(p);
            }
        };

        enum Op {
            cfree,
            cmalloc,
            cppdelete,
            cppnew,
            max
        };
        const char* _opText[recall::max] = { "cfree", "cmalloc", "cppdelete", "cppnew" };

        class MemMap {
        public:
            ~MemMap() {
                std::lock_guard<std::mutex> lock(_mutex);
                printStats(true);
            }

            static MemMap& getInstance() {
                static MemMap instance;
                return instance;
            }

            void free(void *ptr) {
                MemMap::deallocate(ptr, recall::cfree);
            }

            void cppdelete(void *ptr) {
                MemMap::deallocate(ptr, recall::cppdelete);
            }

            void allocate(void *ptr, size_t size, recall::Op op) {
                if (ptr != NULL) {
                    std::lock_guard<std::mutex> lock(_mutex);
                    _stats[op].ops++;
                    if (ptr != nullptr) {
                        auto it = _map.find(ptr);
                        if (it != _map.end()) {
                            // TODO: update free total?
                            _stats[op].sum -= size;
                        } else {
                            _map[ptr] = size;
                        }
                        _stats[op].sum += size;
                        _stats[op].max = std::max(_stats[op].max, static_cast<int64_t>(size));
                        if (_stats[op].min > static_cast<int64_t>(size) || _stats[op].min == 0) {
                           _stats[op].min = static_cast<int64_t>(size);
                        }
                        _stats[op].avg = _stats[op].ops > 0 ? _stats[op].sum / _stats[op].ops : 0;
                    }
                    printStats(false);
                }
            }

            void deallocate(void *ptr, recall::Op op) { 
                size_t size(0);
                if (ptr != NULL) {
                    std::lock_guard<std::mutex> lock(_mutex);
                    auto it = _map.find(ptr);
                    if (it != _map.end()) {
                        size = it->second;
                        _map.erase(ptr);
                        _stats[op].ops++;
                        _stats[op].sum += size;
                        _stats[op].max = std::max(_stats[op].max, static_cast<int64_t>(size));
                        if (_stats[op].min > static_cast<int64_t>(size) || _stats[op].min == 0) {
                           _stats[op].min = static_cast<int64_t>(size);
                        }
                        _stats[op].avg = _stats[op].ops > 0 ? _stats[op].sum / _stats[op].ops : 0;
                    }
                    printStats(false);
                }
            }

            void malloc(void *ptr, size_t size) {
                MemMap::allocate(ptr, size, recall::cmalloc);
            }

            void cppnew(void *ptr, size_t size) {
                MemMap::allocate(ptr, size, recall::cppnew);
            }


            MemMap(MemMap const&) = delete;
            MemMap(MemMap&&) = delete;
            MemMap& operator=(MemMap const&) = delete;
            MemMap& operator=(MemMap&&) = delete;

            const int64_t PRINT_BYTE_INTERVAL = 100 * 1000 * 1000;
            const char *STATS_HEADER = "\nfunction         total          use       max       min       avg     calls\n";
            const char *STATS_RECORD = "%-9s %12" PRId64 " %12" PRId64 " %9" PRId64 " %9" PRId64 " %9" PRId64 " %9" PRId64 "\n";
                  FILE *STATS_FILE = stdout;

            void printStatsHeader() {
                fprintf(STATS_FILE, STATS_HEADER); 
            }
            void printStatsRecord(recall::Op op) {
                int64_t use(0);
                switch (op) {
                case recall::cmalloc:
                    use = _stats[op].sum - _stats[recall::cfree].sum;
                    break;
                case recall::cppnew:
                    use = _stats[op].sum - _stats[recall::cppdelete].sum;
                    break;
                default:
                    break;
                }
                fprintf(STATS_FILE, STATS_RECORD, _opText[op], _stats[op].sum, use, _stats[op].max, _stats[op].min, _stats[op].avg, _stats[op].ops);
            }

            void printStats(bool force) {
                if (force || (_stats[recall::cmalloc].sum + _stats[recall::cfree].sum + _stats[recall::cppnew].sum + _stats[recall::cppdelete].sum) > _printByteInterval) {
                    printStatsHeader();
                    printStatsRecord(recall::cmalloc);
                    printStatsRecord(recall::cfree);
                    printStatsRecord(recall::cppnew);
                    printStatsRecord(recall::cppdelete);
                    _printByteInterval += PRINT_BYTE_INTERVAL;
                }
            }

        private:
            MemMap() : _printByteInterval(PRINT_BYTE_INTERVAL) {}
            // from /usr/include/c++/4.8.2/bits/stl_map.h
            using map_type = std::map< void*, std::size_t, std::less<void*>, map_alloc< std::pair<void* const, std::size_t> > >;

            map_type   _map;
            std::mutex _mutex;

            struct Stats {
                int64_t avg; // average bytes passed to/returned by operation
                int64_t max; // maximum bytes passed to/returned by operation
                int64_t min; // minimum bytes passed to/returned by operation
                int64_t ops; // number of operation calls
                int64_t sum; // sum total of bytes passed to/returned by operation 
            };
            std::array<Stats, recall::Op::max> _stats;
            int64_t _printByteInterval;
        };
    }
#endif

#ifdef __cplusplus
    extern "C" {
#endif
        //static unsigned char calloc_buffer[65536];
        //static void *calloc_buffer_ptr = calloc_buffer;
        //static void* (*real_calloc)(size_t, size_t) = NULL;
        //// called internally by dlsym
        //void* calloc(size_t nmemb, size_t size) {
        //    char *error;
        //    void *ptr = NULL;
        //    if (calloc_buffer_ptr != NULL) {
        //        memset(calloc_buffer_ptr, 0, sizeof(calloc_buffer_ptr)); // thread-safe?
        //        return  calloc_buffer_ptr;
        //    }

        //    // get address of libc calloc
        //    if (real_calloc == NULL) {
        //        real_calloc = (void* (*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
        //        if ((error = dlerror()) != NULL) {
        //            fputs(error, stderr);
        //            exit(1);
        //        }
        //    }

        //    ptr = real_calloc(nmemb, size);
        //    recall::MemMap::getInstance().malloc(ptr, nmemb * size);
        //    return ptr;
        //}

        void init_free() {
            char *error;
            if (real_free == NULL) {
                real_free = (void (*)(void*))dlsym(RTLD_NEXT, "free");
                if ((error = dlerror()) != NULL) {
                    fputs(error, stderr);
                    exit(1);
                }
            }
        }

        void init_malloc() {
            char *error;
            if (real_malloc == NULL) {
                real_malloc = (void* (*)(size_t))dlsym(RTLD_NEXT, "malloc");
                if ((error = dlerror()) != NULL) {
                    fputs(error, stderr);
                    exit(1);
                }
            }
        }

        void free(void* ptr) {
            //if (ptr == calloc_buffer_ptr) {
            //     fprintf(stderr, "freeing dummy\n");
            //     calloc_buffer_ptr = NULL;
            //     return;
            //}

            init_free();

            //if (ptr == calloc_buffer_ptr) {
            //     calloc_buffer_ptr = NULL;
            //}

            recall::MemMap::getInstance().free(ptr);
            real_free(ptr);
        }

        void* malloc(size_t size) {
            void *ptr = NULL;
            init_malloc();
            ptr = real_malloc(size);
            recall::MemMap::getInstance().malloc(ptr, size);
            return ptr;
        }
#ifdef __cplusplus
    }
#endif

#ifdef __cplusplus
    #include <new>

    void recallDelete(void *ptr) {
        init_free(); // init malloc for instance?
        recall::MemMap::getInstance().cppdelete(ptr); 
        real_free(ptr); //std::free(ptr)
    }

    void* recallNew(std::size_t size) {
        // required to return non-null
        init_malloc();
        void *ptr = real_malloc(size == 0 ? 1 : size);
        recall::MemMap::getInstance().cppnew(ptr, size);
        return ptr;
    }

    void operator delete(void* ptr) noexcept {
        recallDelete(ptr);
    }

    void  operator delete[](void *ptr) noexcept {
        recallDelete(ptr);
    }

    void operator delete(void* ptr, const std::nothrow_t& nothrow_constant) noexcept {
        recallDelete(ptr);
    }

    void operator delete[](void* ptr, const std::nothrow_t& nothrow_constant) noexcept {
        recallDelete(ptr);
    }

    void* operator new(std::size_t size) throw(std::bad_alloc) {
        void *ptr = recallNew(size);
        if(ptr == nullptr) {
            throw std::bad_alloc();
        }
        return ptr;
    }

    void* operator new[](std::size_t size) throw(std::bad_alloc) {
        void *ptr = recallNew(size);
        if(ptr == nullptr) {
            throw std::bad_alloc();
        }
        return ptr;
    }

    void* operator new(std::size_t size, const std::nothrow_t& nothrow_value) noexcept {
        return recallNew(size);
    }

    void* operator new[](std::size_t size, const std::nothrow_t& nothrow_value) noexcept {
        return recallNew(size);
    }
#endif
