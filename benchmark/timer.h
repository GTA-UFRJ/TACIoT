#pragma once

#include <chrono>
#include <string>
#include <vector>

using timelist_t = std::vector<long>;

class Timer {
    
    public:
        Timer(std::string);
        ~Timer();
        void Stop();

        static std::vector<std::string> labels; // function names
        static std::vector<timelist_t> times;
        static void print_times();
        static std::vector<unsigned> labels_occurrencies; // number of times a func is called
        static long compute_mean(timelist_t);
        static long compute_conf_int(timelist_t);
    
    private:
        std::string label; 
        unsigned label_index;
        std::chrono::time_point< std::chrono::high_resolution_clock> m_StartTimepoint;

        int search_label(std::string);
};