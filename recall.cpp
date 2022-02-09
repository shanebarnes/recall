#include <dlfcn.h>
#include <execinfo.h>
#include <inttypes.h>
#if defined(__APPLE__)
    #include <malloc/malloc.h>
#elif defined(__linux__)
    #include <malloc.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifdef __cplusplus
    extern "C" {
#endif
        static void  (*real_CRYPTO_free)(void*, const char*, int) = NULL;
        static void* (*real_CRYPTO_malloc)(size_t, const char*, int) = NULL;
        static void* (*real_CRYPTO_realloc)(void*, size_t, const char*, int) = NULL;
        static void* (*real_CRYPTO_zalloc)(size_t, const char*, int) = NULL;

        static void* (*real_calloc)(size_t, size_t) = NULL;
        static void  (*real_free)(void*) = NULL;
        static void* (*real_malloc)(size_t) = NULL;
        static void* (*real_realloc)(void*, size_t) = NULL;
#ifdef __cplusplus
    }
#endif

#ifdef __cplusplus
    #include <array>
    #include <atomic>
    #include <chrono>
    #include <cstdlib>
    #include <map>
    #include <mutex>
    #include <thread>

    namespace recall {
        enum Op {
            ccalloc,
            cmalloc,
            crealloc,
            cfree,
            cppnew,
            cppdelete,
            cryptomalloc,
            cryptorealloc,
            cryptozalloc,
            cryptofree,
            internalnew,
            internaldelete,
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
            "crypto.realloc",
            "crypto.zalloc",
            "crypto.free",
            "internal.new",
            "internal.delete"
        };

        class MemMap {
        public:
            ~MemMap() {
                _run.store(false);
                if (_thread.joinable()) {
                    _thread.join();
                }
            }

            void internalAllocate(size_t size) {
                _stats[recall::internalnew].ops++;
                _stats[recall::internalnew].sum += size;
            }

            void internalDeallocate(size_t size) {
                _stats[recall::internaldelete].ops++;
                _stats[recall::internaldelete].sum += size;
            }

            void allocate(void *ptr, size_t size, recall::Op op) {
                auto tid(getThreadId());
                if (ptr == NULL) {
                    // Do nothing
                } else if (ignoreOp(tid, op)) {
                    //fprintf(stdout, "%s: ignoring %p from %s of size %lu\n", __FUNCTION__, ptr, _opText[op], size);
                    //_stats[op].ops++;
                    //_stats[op].sum += size;
                } else {
                    std::lock_guard<std::mutex> lock(_mutex);
                    updateThreads(tid, op);
                    if (ptr != nullptr) {
                        auto it = _map.find(ptr);
                        if (it != _map.end()) {
                            _stats[it->second.op].sum -= size;
                            _stats[it->second.op].ops--;
                             //fprintf(stderr, "%s: moving %ld bytes from %s to %s\n", __FUNCTION__, size, _opText[it->second.op], _opText[op]);
                            if (it->second.op != op) {
                                it->second.op = op;
                            }
                            _stats[op].sum += size;
                            _stats[op].ops++;
                        } else {
                            _map[ptr].op = op;
                            auto it = _map.find(ptr);
                            it->second.size = size;
                            if (size >= _btMinSize) {
                                captureBacktrace(&it->second.bt);
                            }

                            _stats[op].sum += size;
                            _stats[op].max = std::max(_stats[op].max, static_cast<int64_t>(size));
                            if (_stats[op].min > static_cast<int64_t>(size) || _stats[op].min == 0) {
                               _stats[op].min = static_cast<int64_t>(size);
                            }
                            _stats[op].ops++;
                            _stats[op].avg = _stats[op].ops > 0 ? _stats[op].sum / _stats[op].ops : 0;
                            auto hit = _hist.find(size);
                            if (hit != _hist.end()) {
                               hit->second++;
                            } else {
                                _hist[size] = 1;
                            }
                            _totalCalls++;
                        }
                    }
                }
            }

            void updateThreads(size_t tid, recall::Op op) {
                _threads[tid]++;
            }

            size_t deallocate(void *ptr, recall::Op op) {
                auto tid(getThreadId());
                size_t size(0);
                if (ptr == NULL) {
                    // Do nothing
                } else if (ignoreOp(tid, op)) {
                    //fprintf(stdout, "%s: ignoring %p from %s\n", __FUNCTION__, ptr, _opText[op]);
                    /*std::lock_guard<std::mutex> lock(_mutex);
                    auto it = _map.find(ptr);
                    if (it != _map.end()) {
                        _stats[op].ops++;
                        _stats[op].sum += it->second.size;
                        _map.erase(it);
                    }*/
                    //_stats[op].ops++;
                } else {
                    std::lock_guard<std::mutex> lock(_mutex);
                    updateThreads(tid, op);
                    auto it = _map.find(ptr);
                    if (it != _map.end()) {
                        size = it->second.size;
                        releaseBacktrace(&it->second.bt);
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
                    } else {
                        //fprintf(stdout, "%s: ignoring 2 %p from %s\n", __FUNCTION__, ptr, _opText[op]);
                    }
                }

                return size;
            }

            static MemMap& getInstance() {
                static MemMap instance;
                return instance;
            }

            MemMap(MemMap const&) = delete;
            MemMap(MemMap&&) = delete;
            MemMap& operator=(MemMap const&) = delete;
            MemMap& operator=(MemMap&&) = delete;

            static size_t getThreadId() {
                return std::hash<std::thread::id>()(std::this_thread::get_id());
            }

            bool ignoreOp(size_t tid, recall::Op op) {
                return _threadId == 0 || tid == _threadId || _ignoreOp[op].load();
            }

            void startThread() {
                if (!_run.load()) {
                    _run.store(true);
                    try {
                        _thread = std::thread(&MemMap::statsWorker, this);
                    } catch (std::exception &e) {
                        fprintf(stderr, "Recall init: %s\n", e.what());
                    }
                }
            }

        private:
            //const int DEF_ST_DISPLAY_INTERVAL_SEC = 1;
            const int DEF_BT_DISPLAY_INTERVAL_SEC = 30;
            const int DEF_BT_CAPTURE_MINIMUM_SIZE = 8192;

            const char *ENV_BT_CAPTURE_MINIMUM_SIZE = "RECALL_BT_CAPTURE_MINSIZE";
            const char *ENV_BT_DISPLAY_INTERVAL_SEC = "RECALL_BT_DISPLAY_INTERVAL";

            MemMap()
                : _threadId(0)
                , _run(false)
                , _totalCalls(0)
                , _statsFile(stdout)
                , _btMinSize(DEF_BT_CAPTURE_MINIMUM_SIZE)
                , _btDisplayIntSec(DEF_BT_DISPLAY_INTERVAL_SEC) {
            }

            void statsWorker() {
                int64_t totalCalls(0);
                int64_t idleTicks(0);
                //FILE *fp = fopen("recall.log", "w+");
                //if (fp != NULL) {
                //    _statsFile = fp;
                //}

                if (const char *btMinSize = std::getenv(ENV_BT_CAPTURE_MINIMUM_SIZE)) {
                    try { _btMinSize = std::stoul(btMinSize); } catch (...) {}
                }
                if (const char *btDisplayIntSec = std::getenv(ENV_BT_DISPLAY_INTERVAL_SEC)) {
                    try { _btDisplayIntSec = std::stoi(btDisplayIntSec); } catch (...) {}
                }
                fprintf(_statsFile, "%s = %lu\n", ENV_BT_CAPTURE_MINIMUM_SIZE, _btMinSize);
                fprintf(_statsFile, "%s = %d\n", ENV_BT_DISPLAY_INTERVAL_SEC, _btDisplayIntSec);

                _threadId.store(getThreadId());

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

                    if (idleTicks == _btDisplayIntSec) {
                        int count = 0;
                        for (auto it = _map.begin(); it != _map.end(); it++) {
                            displayBacktrace(it->second.op, it->second.size, &it->second.bt);
                            if (++count > 100) {
                                break;
                            }
                        }

                        if (count) {
                            printStats();
                        }
                        idleTicks = 0;
                    }
                }

                std::lock_guard<std::mutex> lock(_mutex);
                auto it = _map.begin();
                while (it != _map.end()) {
                    displayBacktrace(it->second.op, it->second.size, &it->second.bt);
                    releaseBacktrace(&it->second.bt);
                    _map.erase(it++);
                }

                printStats();
                if (_statsFile != stdout) {
                    fclose(_statsFile);
                    _statsFile = stdout;
                }
            }

            void ignoreAllocOps(bool ignore) {
                _ignoreOp[recall::ccalloc].store(ignore);
                _ignoreOp[recall::cmalloc].store(ignore);
                _ignoreOp[recall::crealloc].store(ignore);
                _ignoreOp[recall::cppnew].store(ignore);
                _ignoreOp[recall::cryptomalloc].store(ignore);
                _ignoreOp[recall::cryptorealloc].store(ignore);
                _ignoreOp[recall::cryptozalloc].store(ignore);
            }

            void ignoreFreeOps(bool ignore) {
                _ignoreOp[recall::cfree].store(ignore);
                _ignoreOp[recall::cryptofree].store(ignore);
                _ignoreOp[recall::cryptofree].store(ignore);
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
                int    strSize;
            };

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
                        // init_malloc?
                        ptr = malloc(msize == 0 ? 1 : msize);
                    }
                    if(ptr == NULL) {
                        throw std::bad_alloc();
                    }
                    recall::MemMap::getInstance().internalAllocate(size);
                    return static_cast<pointer>(ptr);
                }
    
                void deallocate(pointer p, size_type size) {
                        if (p != nullptr) {
                            recall::MemMap::getInstance().internalDeallocate(size);
                        }
                        real_free(p);
                }
            };

            struct mem {
                recall::Op  op;
                std::size_t size;
                Backtrace   bt;
            };

            // from /usr/include/c++/4.8.2/bits/stl_map.h
            //using map_type = std::map< void*, std::pair< std::size_t, Backtrace >, std::less<void*>, map_alloc< std::pair<void* const, std::size_t> > >;
            using map_type = std::map<void*, struct mem, std::less<void*>, map_alloc<std::pair<void* const, struct mem>>>;
            using hist_type = std::map<size_t, size_t, std::less<size_t>, map_alloc< std::pair<const std::size_t, std::size_t> > >;

            map_type   _map;
            hist_type  _hist;
            hist_type  _threads;
            std::atomic<size_t> _threadId;
            std::mutex _mutex;

            // std::map<recall::Op, std::pair<const char*, int>>
            //using op_type = std::map <recall::Op, std::pair<const char*, int>, std::less<recall::Op>, map_alloc<std::pair<const char*, int>>>;
            //const op_type _opMap = {
            //    {recall::ccalloc,        {"c.calloc",         1}},
            //    {recall::cmalloc,        {"c.malloc",         1}},
            //    {recall::crealloc,       {"c.realloc",        1}},
            //    {recall::cfree,          {"c.free",          -1}},
            //    {recall::cppnew,         {"cpp.new",          1}},
            //    {recall::cppdelete,      {"cpp.delete",      -1}},
            //    {recall::cryptomalloc,   {"crypto.malloc",    1}},
            //    {recall::cryptorealloc,  {"crypto.realloc",   1}},
            //    {recall::cryptozalloc,   {"crypto.zalloc",    1}},
            //    {recall::cryptofree,     {"crypto.free",     -1}},
            //    {recall::internalnew,    {"internal.new",     1}},
            //    {recall::internaldelete, {"internal.delete", -1}}
            //};

            std::thread _thread;
            std::atomic<bool> _run;
            int64_t _totalCalls;
            FILE *_statsFile;
            struct Stats {
                int64_t avg; // average bytes passed to/returned by operation
                int64_t max; // maximum bytes passed to/returned by operation
                int64_t min; // minimum bytes passed to/returned by operation
                int64_t ops; // number of operation calls
                int64_t sum; // sum total of bytes passed to/returned by operation
            };
            std::array<Stats, recall::Op::max> _stats;
            std::array<std::atomic<bool>, recall::Op::max> _ignoreOp;
            size_t _btMinSize;
            int    _btDisplayIntSec;

            void captureBacktrace(Backtrace *bt) {
                ignoreOps(true);
                bt->frames = backtrace(bt->buf, sizeof(bt->buf) / sizeof(bt->buf[0]));
                ignoreOps(false);
            }

            void displayBacktrace(recall::Op op, size_t size, Backtrace *bt) {
                if (bt->frames > 0) {
                    fprintf(_statsFile, "\n\n\nrecall: %s possible leak of %lu bytes\n", _opText[op], size);
                    // TODO: hash strings so that not printed repeatedly
                    if (bt->strs == NULL) {
                        bt->strs = backtrace_symbols(bt->buf, bt->frames);
                        if (bt->strs != NULL) {
                            for (int i = 0; i < bt->frames; i++) {
                                bt->strSize += strlen(bt->strs[i]) + 1;
                            }
                            _stats[recall::internalnew].ops++;
                            _stats[recall::internalnew].sum += bt->strSize;
                        }
                    }
                    for (int i = 0; i < bt->frames; i++) {
                        fprintf(_statsFile, "    %2d: %s\n", i, bt->strs[i]);

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
                    fflush(_statsFile);
                }
            }

            void releaseBacktrace(Backtrace *bt) {
                if (bt->strs != NULL) {
                   _stats[recall::internaldelete].ops++;
                   _stats[recall::internaldelete].sum += bt->strSize;
                   real_free(bt->strs);
                   bt->strs = NULL;
                   bt->frames = 0;
                }
            }

            const char *STATS_HEADER = "\nfunction               total          use       max       min       avg     calls\n";
            const char *STATS_RECORD = "%-15s %12" PRId64 " %12" PRId64 " %9" PRId64 " %9" PRId64 " %9" PRId64 " %9" PRId64 "\n";

            void printStatsHeader() {
                fprintf(_statsFile, "%s", STATS_HEADER);
            }

            void printStatsRecord(recall::Op op) {
                int64_t use(0);
                switch (op) {
                case recall::cmalloc:
                    use = _stats[op].sum + _stats[recall::ccalloc].sum + _stats[recall::crealloc].sum - _stats[recall::cfree].sum;
                    break;
                case recall::cppnew:
                    use = _stats[op].sum - _stats[recall::cppdelete].sum;
                    break;
                case recall::cryptomalloc:
                    use = _stats[op].sum + _stats[recall::cryptorealloc].sum + _stats[recall::cryptozalloc].sum - _stats[recall::cryptofree].sum;
                    break;
                case recall::internalnew:
                    use = _stats[op].sum - _stats[recall::internaldelete].sum;
                    break;
                default:
                    break;
                }
                fprintf(_statsFile, STATS_RECORD, _opText[op], _stats[op].sum, use, _stats[op].max, _stats[op].min, _stats[op].avg, _stats[op].ops);
            }

            void printStatsFooter() {
                int64_t use(0), ops(0);
                //for (auto it = _opMap.begin(); it != _opMap.end(); it++) {
                //    switch(it->second.second) {
                //    case 1:
                //        ops += _stats[it->first].ops;
                //        use += _stats[it->first].sum;
                //        break;
                //    case -1:
                //        ops -= _stats[it->first].ops;
                //        use -= _stats[it->first].sum;
                //        break;
                //    default:
                //        break;
                //    }
                //}
                use = _stats[recall::ccalloc].sum +
                      _stats[recall::cmalloc].sum +
                      _stats[recall::crealloc].sum -
                      _stats[recall::cfree].sum +
                      _stats[recall::cryptomalloc].sum +
                      _stats[recall::cryptorealloc].sum +
                      _stats[recall::cryptozalloc].sum -
                      _stats[recall::cryptofree].sum +
                      _stats[recall::cppnew].sum -
                      _stats[recall::cppdelete].sum +
                      _stats[recall::internalnew].sum -
                      _stats[recall::internaldelete].sum;
                ops = _stats[recall::ccalloc].ops +
                      _stats[recall::cmalloc].ops +
                      _stats[recall::crealloc].ops -
                      _stats[recall::cfree].ops +
                      _stats[recall::cryptomalloc].ops +
                      _stats[recall::cryptorealloc].ops +
                      _stats[recall::cryptozalloc].ops -
                      _stats[recall::cryptofree].ops +
                      _stats[recall::cppnew].ops -
                      _stats[recall::cppdelete].ops +
                      _stats[recall::internalnew].ops -
                      _stats[recall::internaldelete].ops;
                fprintf(_statsFile, STATS_RECORD, "net total", use, use, 0LL, 0LL, 0LL, ops);
            }

            void printStats() {
                size_t limit = 10;
                size_t binSize = 1;
                size_t binCount = 0;
                fprintf(_statsFile, "\nMemory Size Distribution:\n");
                fprintf(_statsFile, "   %-12s %9s\n", "size", "frequency");
                for (auto it = _hist.begin(); it != _hist.end(); it++) {
                    if (_hist.size() > limit) {
                        if (it->first > binSize) {
                            fprintf(_statsFile, "<= %-12lu %-9lu\n", binSize, binCount);
                            binSize *= 10;
                            binCount = it->second;
                        } else {
                            binCount += it->second;
                        }
                    } else {
                        fprintf(_statsFile, "<= %-12lu %-9lu\n", it->first, it->second);
                    }
                }
                if (binCount && _hist.size() > limit) {
                    fprintf(_statsFile, "<= %-12lu %-9lu\n", binSize, binCount);
                }

                fprintf(_statsFile, "\nTotal unique threads: %lu\n", _threads.size());

                printStatsHeader();
                for (auto i = 0; i < recall::max; i++) {
                    printStatsRecord(recall::Op(i));
                }
                printStatsFooter();
                fflush(_statsFile);
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

            real_CRYPTO_malloc = (void* (*)(size_t, const char*, int))dlsym(RTLD_NEXT, "CRYPTO_malloc");
            fprintf(stdout, "Recall init: loaded CRYPTO_malloc, %p\n", real_CRYPTO_malloc);

            real_CRYPTO_realloc = (void* (*)(void*, size_t, const char*, int))dlsym(RTLD_NEXT, "CRYPTO_realloc");
            fprintf(stdout, "Recall init: loaded CRYPTO_realloc, %p\n", real_CRYPTO_realloc);

            real_CRYPTO_zalloc = (void* (*)(size_t, const char*, int))dlsym(RTLD_NEXT, "CRYPTO_zalloc");
            fprintf(stdout, "Recall init: loaded CRYPTO_zalloc, %p\n", real_CRYPTO_realloc);

            recall::MemMap::getInstance().startThread();
            fprintf(stdout, "Recall init: finished\n");
        }

        static void __attribute__ ((destructor)) my_fini(void) {
            fprintf(stdout, "Recall fini: done\n");
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

        void CRYPTO_free(void *ptr, const char *file, int line) {
            if (real_CRYPTO_free == NULL || init_free(ptr) == 0) {
                return;
            }
            recall::MemMap::getInstance().deallocate(ptr, recall::cryptofree);
            real_CRYPTO_free(ptr, file, line);
        }

        void* CRYPTO_malloc(size_t size, const char *file, int line) {
            void *ptr = NULL;
            if (real_CRYPTO_malloc == NULL) {
                return init_malloc(size);
            }
            ptr = real_CRYPTO_malloc(size, file, line);
            recall::MemMap::getInstance().allocate(ptr, size, recall::cryptomalloc);
            return ptr;
        }

        void* CRYPTO_realloc(void *ptr, size_t num, const char *file, int line) {
            void *rptr = NULL;
            if (ptr == NULL) {
                return CRYPTO_malloc(num, file, line);
            } else if (real_CRYPTO_realloc == NULL || init_free(ptr) == 0) {
                return init_realloc(ptr, num);
            }
            recall::MemMap::getInstance().deallocate(ptr, recall::cryptofree);
            rptr = real_CRYPTO_realloc(ptr, num, file, line);
            recall::MemMap::getInstance().allocate(rptr, num, recall::cryptorealloc);
            return rptr;
        }

        void* CRYPTO_zalloc(size_t num, const char *file, int line) {
            void *ptr = NULL;
            if (real_CRYPTO_zalloc == NULL) {
                ptr = CRYPTO_malloc(num, file, line);
                bzero(ptr, num);
                return ptr;
            }
            ptr = real_CRYPTO_zalloc(num, file, line);
            recall::MemMap::getInstance().allocate(ptr, num, recall::cryptozalloc);
            return ptr;
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
            //if (size >= 4064) {
            //    if (malloc_trim(0) == 1) {
            //        fprintf(stdout, "Trimmed %lu bytes\n", size);
            //    }
            //}
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

    void* operator new(std::size_t size) /*throw(std::bad_alloc)*/ {
        void *ptr = recallNew(size);
        if(ptr == nullptr) {
            throw std::bad_alloc();
        }
        return ptr;
    }

    void* operator new[](std::size_t size) /*throw(std::bad_alloc)*/ {
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
