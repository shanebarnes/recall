#include <dlfcn.h>
#include <execinfo.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifdef __cplusplus
    extern "C" {
#endif
        static void (*real_CRYPTO_free)(void*, const char*, int) = NULL;
        static void* (*real_crypto_malloc)(size_t, const char*, int) = NULL;
        static void* (*real_calloc)(size_t, size_t) = NULL;
        static void (*real_free)(void*) = NULL;
        static void* (*real_malloc)(size_t) = NULL;
        static void* (*real_realloc)(void*, size_t) = NULL;
#ifdef __cplusplus
    }
#endif

#ifdef __cplusplus
    #include <array>
    #include <atomic>
    #include <chrono>
    #include <map>
    #include <mutex>
    #include <thread>

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
            ccalloc,
            cmalloc,
            crealloc,
            cfree,
            cppnew,
            cppdelete,
            cryptomalloc,
            cryptofree,
            max
        };
        const char* _opText[recall::max] = {
            "c.calloc",
            "c.malloc",
            "c.realloc",
            "c.free",
            "cpp.new",
            "cpp.delete",
            "crypto.malloc",
            "crypto.free"
        };

        class MemMap {
        public:
            ~MemMap() {
                _run.store(false);
                if (_thread.joinable()) {
                    _thread.join();
                }
                std::lock_guard<std::mutex> lock(_mutex);
                auto it = _map.begin();
                while (it != _map.end()) {
                    displayBacktrace(it->second.first, &it->second.second);
                    releaseBacktrace(&it->second.second);
                    _map.erase(it++);
                }

                //size_t limit = 10;
                //size_t binSize = 1;
                //size_t binCount = 0;
                //fprintf(STATS_FILE, "\n");
                //for (auto it = _hist.begin(); it != _hist.end(); it++) {
                //    if (_hist.size() > limit) {
                //        if (it->first > binSize) {
                //            fprintf(STATS_FILE, "size: <= %lu, freq: %lu\n", binSize, binCount);
                //            binSize *= 10;
                //            binCount = it->second;
                //        } else {
                //            binCount += it->second;
                //        }
                //    } else {
                //        fprintf(STATS_FILE, "size: %lu, freq: %lu\n", it->first, it->second);
                //    }
                //}
                //if (binCount && _hist.size() > limit) {
                //    fprintf(STATS_FILE, "size: <= %lu, freq: %lu\n", binSize, binCount);
                //}
                printStats();
            }

            void allocate(void *ptr, size_t size, recall::Op op) {
                if (ptr != NULL && !ignoreOp(op)) {
                    std::lock_guard<std::mutex> lock(_mutex);
                    _stats[op].ops++;
                    auto it = _hist.find(size);
                    if (it != _hist.end()) {
                        _hist[size]++;
                    } else {
                        _hist[size] = 1;
                    }
                    if (ptr != nullptr) {
                        auto it = _map.find(ptr);
                        if (it != _map.end()) {
                            // TODO: update free total?
                            _stats[op].sum -= size;
                        } else {
                            _map[ptr].first = size;
                        }
                        if (size >= _minBtSize) {
                            captureBacktrace(op, &_map[ptr].second);
                        }
                        _stats[op].sum += size;
                        _stats[op].max = std::max(_stats[op].max, static_cast<int64_t>(size));
                        if (_stats[op].min > static_cast<int64_t>(size) || _stats[op].min == 0) {
                           _stats[op].min = static_cast<int64_t>(size);
                        }
                        _stats[op].avg = _stats[op].ops > 0 ? _stats[op].sum / _stats[op].ops : 0;
                        _totalCalls++;
                    }
                }
            }

            void deallocate(void *ptr, recall::Op op) {
                size_t size(0);
                if (ptr != NULL && !ignoreOp(op)) {
                    std::lock_guard<std::mutex> lock(_mutex);
                    auto it = _map.find(ptr);
                    if (it != _map.end()) {
                        size = it->second.first;
                        releaseBacktrace(&it->second.second);
                        auto it2 = _hist.find(size);
                        if (it2 != _hist.end()) {
                            if (it2->second == 1) {
                                _hist.erase(it2);
                            } else {
                                it2->second--;
                            }
                        }
                        _map.erase(ptr);
                        _stats[op].ops++;
                        _stats[op].sum += size;
                        _stats[op].max = std::max(_stats[op].max, static_cast<int64_t>(size));
                        if (_stats[op].min > static_cast<int64_t>(size) || _stats[op].min == 0) {
                           _stats[op].min = static_cast<int64_t>(size);
                        }
                        _stats[op].avg = _stats[op].ops > 0 ? _stats[op].sum / _stats[op].ops : 0;
                        _totalCalls++;
                    }
                }
            }

            static MemMap& getInstance() {
                static MemMap instance;
                return instance;
            }

            MemMap(MemMap const&) = delete;
            MemMap(MemMap&&) = delete;
            MemMap& operator=(MemMap const&) = delete;
            MemMap& operator=(MemMap&&) = delete;

            bool ignoreOp(recall::Op op) {
                return _ignoreOp[op].load();
            }

            void startThread() {
                if (!_run.load()) {
                    _run.store(true);
                    _thread = std::thread(&MemMap::statsWorker, this);
                }
            }

        private:
            MemMap()
                : _run(false)
                , _totalCalls(0)
                , _minBtSize(8192) {
                ignoreOps(false);
            }


            void statsWorker() {
                int64_t totalCalls(0);
                int64_t idleTicks(0);
                while (_run.load()) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    std::lock_guard<std::mutex> lock(_mutex);
                    if (totalCalls != _totalCalls) {
                        printStats();
                        totalCalls = _totalCalls;
                        idleTicks = 0;
                    } else {
                        idleTicks++;
                    }

                    if (idleTicks == 30) {
                        for (auto it = _map.begin(); it != _map.end(); it++) {
                            displayBacktrace(it->second.first, &it->second.second);
                        }
                        printStats();
                    }
                }
            }

            void ignoreAllocOps(bool ignore) {
                _ignoreOp[recall::ccalloc].store(ignore);
                _ignoreOp[recall::cmalloc].store(ignore);
                _ignoreOp[recall::crealloc].store(ignore);
                _ignoreOp[recall::cppnew].store(ignore);
                _ignoreOp[recall::cryptomalloc].store(ignore);
            }

            void ignoreFreeOps(bool ignore) {
                _ignoreOp[recall::cfree].store(ignore);
                _ignoreOp[recall::cryptofree].store(ignore);
                _ignoreOp[recall::cryptomalloc].store(ignore);
                _ignoreOp[recall::cppdelete].store(ignore);
                _ignoreOp[recall::cryptofree].store(ignore);
            }


            void ignoreOps(bool ignore) {
                ignoreAllocOps(ignore);
                ignoreFreeOps(ignore);
            }

            struct Backtrace {
                void  *buf[128];
                int    frames;
                char **strs;
            };

            // from /usr/include/c++/4.8.2/bits/stl_map.h
            using map_type = std::map< void*, std::pair< std::size_t, Backtrace >, std::less<void*>, map_alloc< std::pair<void* const, std::size_t> > >;
            using hist_type = std::map< size_t, size_t, std::less<size_t>, map_alloc< std::pair<std::size_t, std::size_t> > >;

            map_type   _map;
            hist_type  _hist;
            std::mutex _mutex;

            std::thread _thread;
            std::atomic<bool> _run;
            int64_t _totalCalls;
            struct Stats {
                int64_t avg; // average bytes passed to/returned by operation
                int64_t max; // maximum bytes passed to/returned by operation
                int64_t min; // minimum bytes passed to/returned by operation
                int64_t ops; // number of operation calls
                int64_t sum; // sum total of bytes passed to/returned by operation
            };
            std::array<Stats, recall::Op::max> _stats;
            std::array<std::atomic<bool>, recall::Op::max> _ignoreOp;
            const size_t _minBtSize;

            void captureBacktrace(recall::Op op, Backtrace *bt) {
                ignoreOps(true);
                bt->frames = backtrace(bt->buf, sizeof(bt->buf) / sizeof(bt->buf[0]));
                ignoreOps(false);
            }

            void displayBacktrace(size_t size, Backtrace *bt) {
                if (bt->frames > 0) {
                    fprintf(STATS_FILE, "\n\n\nrecall: possible leak of %lu bytes\n", size);
                    ignoreOps(true);
                    bt->strs = backtrace_symbols(bt->buf, bt->frames);
                    ignoreOps(false);
                    for (int i = 0; i < bt->frames; i++) {
                        fprintf(STATS_FILE, "    %2d: %s\n", i, bt->strs[i]);

                        ////find first occurence of '(' or ' ' in message[i] and assume
                        ////everything before that is the file name. (Don't go beyond 0 though
                        ////* (string terminator)
                        //size_t p = 0;
                        //while(bt->strs[i][p] != '(' && bt->strs[i][p] != ' ' && bt->strs[i][p] != 0) {
                        //    ++p;
                        //}
                        //char syscom[256];
                        //ignoreOps(true);
                        ////_ignoreOp[recall::cmalloc].store(true);
                        //sprintf(syscom,"addr2line %p -e %.*s", bt->buf[i], p, bt->strs[i]);

                        ////last parameter is the file name of the symbol
                        //system(syscom);
                        ////_ignoreOp[recall::cmalloc].store(false);
                        //ignoreOps(false);
                    }
                }
            }

            void releaseBacktrace(Backtrace *bt) {
                real_free(bt->strs);
                bt->frames = 0;
                bt->strs = NULL;
            }

            const char *STATS_HEADER = "\nfunction               total          use       max       min       avg     calls\n";
            const char *STATS_RECORD = "%-15s %12" PRId64 " %12" PRId64 " %9" PRId64 " %9" PRId64 " %9" PRId64 " %9" PRId64 "\n";
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
                case recall::cryptomalloc:
                    use = _stats[op].sum - _stats[recall::cryptofree].sum;
                    break;
                default:
                    break;
                }
                fprintf(STATS_FILE, STATS_RECORD, _opText[op], _stats[op].sum, use, _stats[op].max, _stats[op].min, _stats[op].avg, _stats[op].ops);
            }

            void printStatsFooter() {
                int64_t use(_stats[recall::ccalloc].sum + _stats[recall::cmalloc].sum + _stats[recall::crealloc].sum - _stats[recall::cfree].sum + _stats[recall::cryptomalloc].sum - _stats[recall::cryptofree].sum + _stats[recall::cppnew].sum - _stats[recall::cppdelete].sum);
                int64_t ops(_stats[recall::ccalloc].ops + _stats[recall::cmalloc].ops + _stats[recall::crealloc].ops - _stats[recall::cfree].ops + _stats[recall::cryptomalloc].ops - _stats[recall::cryptofree].ops + _stats[recall::cppnew].ops - _stats[recall::cppdelete].ops);
                fprintf(STATS_FILE, STATS_RECORD, "net total", use, use, 0LL, 0LL, 0LL, ops);
            }

            void printStats() {
                printStatsHeader();
                for (auto i = 0; i < recall::max; i++) {
                    printStatsRecord(recall::Op(i));
                }
                printStatsFooter();
            }
        };
    }
#endif

#ifdef __cplusplus
    extern "C" {
#endif
        static const int INIT_BUF_SIZE = 4 * 1024 * 1024;
        static unsigned char  init_buf[INIT_BUF_SIZE];
        static unsigned char *init_buf_head = &init_buf[0];
        static unsigned char *init_buf_tail = &init_buf[0] + INIT_BUF_SIZE;

        static void __attribute__((constructor))init(void) {
            fprintf(stdout, "Recall init: started\n");

            real_calloc = (void* (*)(size_t, size_t))dlsym(RTLD_NEXT, "calloc");
            fprintf(stdout, "Recall init: loaded calloc, %p\n", real_calloc);

            real_malloc = (void* (*)(size_t))dlsym(RTLD_NEXT, "malloc");
            fprintf(stdout, "Recall init: loaded malloc, %p\n", real_malloc);

            real_realloc = (void* (*)(void*, size_t))dlsym(RTLD_NEXT, "realloc");
            fprintf(stdout, "Recall init: loaded realloc, %p\n", real_realloc);

            real_free = (void (*)(void*))dlsym(RTLD_NEXT, "free");
            fprintf(stdout, "Recall init: loaded free, %p\n", real_free);

            real_CRYPTO_free = (void (*)(void*, const char*, int))dlsym(RTLD_NEXT, "CRYPTO_free");
            fprintf(stdout, "Recall init: loaded CRYPTO_free, %p\n", real_CRYPTO_free);

            real_crypto_malloc = (void* (*)(size_t, const char*, int))dlsym(RTLD_NEXT, "CRYPTO_malloc");
            fprintf(stdout, "Recall init: loaded CRYPTO_malloc, %p\n", real_crypto_malloc);

            recall::MemMap::getInstance().startThread();
            fprintf(stdout, "Recall init: finished\n");
        }

        static void __attribute__ ((destructor)) my_fini(void) {
            fprintf(stdout, "Recall fini: done\n");
        }

        void CRYPTO_free(void *ptr, const char *file, int line) {
            recall::MemMap::getInstance().deallocate(ptr, recall::cryptofree);
            real_CRYPTO_free(ptr, file, line);
        }

        void* CRYPTO_malloc(size_t size, const char *file, int line) {
            void *ptr = NULL;
            ptr = real_crypto_malloc(size, file, line);
            recall::MemMap::getInstance().allocate(ptr, size, recall::cryptomalloc);
            return ptr;
        }

        int init_free(void *ptr) {
            int rv = -1;
            if ((ptr >= (void*)&init_buf[0]) && (ptr <= (void*)init_buf_tail)) {
                rv = 0;
            }
            return rv;
        }

        void* init_malloc(size_t size) {
            void *ptr = NULL;
            if ((init_buf_head + size) <= init_buf_tail) {
                ptr = init_buf_head;
                init_buf_head += size;
            }
            return ptr;
        }

        void* init_realloc(void *ptr, size_t size) {
            void *rptr = init_malloc(size);
            memmove(rptr, ptr, size);
            return rptr;
        }

        void* calloc(size_t nmemb, size_t size) {
            void *ptr = NULL;
            if (real_calloc == NULL) {
                ptr = init_malloc(nmemb * size);
                bzero(ptr, nmemb * size);
                return ptr;
            }

            ptr = real_calloc(nmemb, size);
            recall::MemMap::getInstance().allocate(ptr, nmemb * size, recall::ccalloc);
            return ptr;
        }

        void free(void *ptr) {
            if (real_free == NULL || init_free(ptr) == 0) {
                return;
            }
            recall::MemMap::getInstance().deallocate(ptr, recall::cfree);
            real_free(ptr);
        }

        void* malloc(size_t size) {
            void *ptr = NULL;
            if (real_malloc == NULL) {
                return init_malloc(size);
            }
            ptr = real_malloc(size);
            recall::MemMap::getInstance().allocate(ptr, size, recall::cmalloc);
            return ptr;
        }

        void* realloc(void *ptr, size_t size) {
            void *rptr = NULL;
            if (ptr == NULL) {
                return malloc(size);
            } else if (real_realloc == NULL || init_free(ptr) == 0) {
                return init_realloc(ptr, size);
            }
            recall::MemMap::getInstance().deallocate(ptr, recall::cfree);
            rptr = real_realloc(ptr, size);
            recall::MemMap::getInstance().allocate(rptr, size, recall::crealloc);
            return rptr;
        }
#ifdef __cplusplus
    }
#endif

#ifdef __cplusplus
    #include <new>

    void recallDelete(void *ptr) {
        if (real_free == NULL || init_free(ptr) == 0) {
            return;
        }
        recall::MemMap::getInstance().deallocate(ptr, recall::cppdelete);
        real_free(ptr); //std::free(ptr)
    }

    void* recallNew(std::size_t size) {
        if (real_malloc == NULL) {
            return init_malloc(size == 0 ? 1 : size);
        }
        void *ptr = real_malloc(size == 0 ? 1 : size);
        recall::MemMap::getInstance().allocate(ptr, size, recall::cppnew);
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
