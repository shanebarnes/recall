#include <chrono>
#include <thread>

int main() {
    int *p1(new int[32768]);
    if (p1 == nullptr) {
        // Intentionally leak the memory
    }

    int *p2(new int[16384]);
    delete [] p2;

    std::this_thread::sleep_for (std::chrono::seconds(2));
    return 0;
}
