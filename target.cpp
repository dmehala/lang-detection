#include <Windows.h>
#include <iostream>

int main() {
  while (true) {
    printf("My PID is %d\n", GetCurrentProcessId());
    SleepEx(1000,
            true); // Call Sleep function with alertable flag to put the thread
                   // in suspended state for using in QueueUserAPC method
  }
}
