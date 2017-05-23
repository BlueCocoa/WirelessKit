//
//  main.cpp
//  sniffer
//
//  Created by BlueCocoa on 2017/5/21.
//  Copyright © 2017 BlueCocoa. All rights reserved.
//

#include <getopt.h>
#include <pcap.h>
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
    #endif
#endif

const struct option options[] = {
    { "ifname", optional_argument, NULL, 'i' },
    { "help",   no_argument,       NULL, 'h' },
};

void quit(int);

atomic_bool working;
atomic_bool done;
condition_variable cond;

int main(int argc, const char * argv[]) {
    if (getuid()) {
        fprintf(stderr, "This tool requires root privileges\n");
        exit(EXIT_FAILURE);
    }
    
    Interface ifname(DEFAULT_WLAN);
    
    int arg, argslot;
    while (argslot = -1, (arg = getopt_long(argc, (char * const *)argv, "i:h", options, &argslot)) != -1) {
        switch (arg) {
            case 'i' : {
                ifname = Interface(optarg);
                break;
            }
            case 'h' : {
                fprintf(stdout, "%s [-i|--ifname " DEFAULT_WLAN "]\nUse at your own risk & don't be jerk!\n", argv[0]);
                break;
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
    
    if (ifname.open()) {
        working = true;
        done = false;
        signal(SIGINT, quit);
        Sniffer sniffer(ifname);

        sniffer.capture([&](const CapturedPacket & packet) -> bool {
            if (packet.is_valid()) {
                fprintf(stdout, "%s -> %s -> %s\n", packet.header()->source()->stringify().c_str(), packet.header()->transmitter()->stringify().c_str(), packet.header()->destination()->stringify().c_str());
                fflush(stdout);
            }
            if (!working) {
                done = true;
            }
            return working;
        });
        
        std::mutex mtx;
        std::thread ([&]{
            std::unique_lock<std::mutex> lock(mtx);
            cond.wait(lock);
            working = false;
            while (!done) this_thread::yield();
        }).join();
    }
    
    return 0;
}

void quit(int) {
    working = false;
    cond.notify_one();
}
