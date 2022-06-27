#include "timer.h"
#include <iostream>
#include <cmath>

std::vector<std::string> Timer::labels;
std::vector<unsigned> Timer::labels_occurrencies;
std::vector<timelist_t> Timer::times;

Timer::Timer(std::string label_arg) {
    this->m_StartTimepoint = std::chrono::high_resolution_clock::now();

    this->label = label_arg;
    int label_index = search_label(label_arg);
    
    // New label
    if(label_index == -1) {
        this->label_index = labels.size();
        labels.push_back(label_arg);
        
        size_t timers_count = times.size();
        timelist_t times_measurements(1);
        times_measurements[0] = 0;
        times.push_back(times_measurements);

        labels_occurrencies.push_back(1);
    }

    // Found an alredy existing label
    else {
        this->label_index = label_index;
        labels_occurrencies[label_index] += 1;
    }
    //std::cout << label_arg << " " << this->label_index << " " << labels_occurrencies[label_index] << std::endl;
}

Timer::~Timer() {
    Stop();
}

void Timer::Stop() {
    auto endTimepoint = std::chrono::high_resolution_clock::now();

    auto start = std::chrono::time_point_cast<std::chrono::nanoseconds>(m_StartTimepoint).time_since_epoch().count();
    auto end = std::chrono::time_point_cast<std::chrono::nanoseconds>(endTimepoint).time_since_epoch().count();

    auto duration = end - start;
    times.at(this->label_index).push_back(duration/1000);
/*
    double ms = duration * 0.001;
    std::cout << this->label << ": " << duration << "us (" << ms << "ms)\n";*/
}

void Timer::print_times() {
    for(unsigned count=0; count<labels.size(); count++) {
        std::cout << labels[count] << "(calls=" << labels_occurrencies[count] <<  "): "
        << compute_mean(times[count]) << " +- " << compute_conf_int(times[count]) << "us\n";
        /*
        std::cout << labels[count] << "(calls=" << labels_occurrencies[count] <<  "): "
        << times[count]/labels_occurrencies[count] << "us (" 
        << times[count]*0.001/labels_occurrencies[count] << "ms)\n";*/
    }
}

int Timer::search_label(std::string target_label) {
    for(unsigned count=0; count<labels.size(); count++) 
        if(labels[count] == target_label) return count;
    return -1;
}

long Timer::compute_mean(timelist_t times) {
    long sum = 0;
    times.erase(times.begin());
    for(long time : times)
        sum += time;
    
    if (times.size()>0) return sum/times.size();
    else return 0;
}

long Timer::compute_conf_int(timelist_t times) {
    times.erase(times.begin());
    long mean = compute_mean(times);
    long squared_error_sum = 0;
    for (long time : times) 
        squared_error_sum = (time-mean)*(time-mean);
    long variable_variance = 0;
    if (times.size()>1)
        variable_variance = squared_error_sum / (times.size()-1);
    else variable_variance=0;

    long mean_variance = variable_variance / times.size();
    long mean_stdev = (long)sqrt(mean_variance);
    return 1.96 * mean_stdev; // 95%
}
