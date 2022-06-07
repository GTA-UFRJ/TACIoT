#include <chrono>
#include <string>

class Timer {
    public:
        Timer(std::string);
        ~Timer();
        void Stop();
    private:
        std::string label; 
        std::chrono::time_point< std::chrono::high_resolution_clock> m_StartTimepoint;
};