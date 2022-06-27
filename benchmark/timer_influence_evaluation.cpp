#include "timer.h"

// g++ -Wall ./benchmark/timer.cpp ./benchmark/timer_influence_evaluation.cpp -o timer_test

int main() {
    for(unsigned count=0; count<100; count++)
        Timer t("test");
    Timer::print_times();
    return 0;
}