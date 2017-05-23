//
//  main.cpp
//  fakebeacon
//
//  Created by BlueCocoa on 2017/5/19.
//  Copyright © 2017 BlueCocoa. All rights reserved.
//

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    { "ssid-with-bssid",  optional_argument, NULL, 'b' },
    { "ifname",           optional_argument, NULL, 'i' },
    { "ssid",             optional_argument, NULL, 's' },
    { "help",             no_argument,       NULL, 'h' },
};

void split(const char * to_split, char by, char ** head, char ** tail);
void quit(int);

atomic_bool working;
condition_variable cond;
vector<BeaconFloodFrame> APs;

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
                char * ssid = NULL, * bssid = NULL;
                split(optarg, '@', &bssid, &ssid);
                if (bssid && ssid) {
                    MAC BSSID(bssid);
                    if (BSSID.is_valid()) APs.emplace_back(BeaconFloodFrame(AP(std::string(ssid), BSSID)));
                }
                if (ssid) free(ssid);
                if (bssid) free(bssid);
                break;
            }
            case 's' : {
                std::string SSID = std::string(optarg);
                APs.emplace_back(BeaconFloodFrame(AP(SSID)));
                break;
            }
            case 'i' : {
                ifname = std::string(optarg);
                break;
            }
            case 'h' : {
                fprintf(stdout, "%s [-i|--ifname en0] [-b|--ssid-with-bssid BB:BB:BB:BB:BB:BB@SSID] [-s|--ssid SSID]\nUse at your own risk & don't be jerk!", argv[0]);
                break;
            }
        }
    }
    
    if (ifname.open() && APs.size() > 0) {
        uint64_t count = 0;
        working = true;
        signal(SIGINT, quit);
        
        fprintf(stdout, "\n");
        std::thread faker{[&count, &ifname]{
            while (working) {
                for (BeaconFloodFrame & beacon : APs) {
                    beacon.beacon(ifname);
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
            fprintf(stdout, "\r%llu Beacon packets sent in total!\n", count);
        }).join();
    }
    
    return 0;
}

void split(const char * to_split, char by, char ** head, char ** tail) {
    for (size_t i = 0; i < strlen(to_split); ++i) {
        if (to_split[i] == by) {
            if (head) {
                char * h = new char[i];
                memcpy(h, to_split, i);
                *head = h;
            }
            if (tail) {
                char * t = new char[strlen(to_split) - i + 2];
                memcpy(t, to_split + i + 1, strlen(to_split) - i + 1);
                *tail = t;
            }
            break;
        }
    }
}

void quit(int) {
    working = false;
    cond.notify_one();
}
