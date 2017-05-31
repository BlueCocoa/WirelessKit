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
    { "channel", optional_argument, NULL, 'c'},
    { "ifname",  optional_argument, NULL, 'i' },
    { "help",    no_argument,       NULL, 'h' },
};

void quit(int);

atomic_bool working;
atomic_bool sniffer_done;
atomic_bool channel_done;
condition_variable cond;
vector<uint32_t> channels;

int main(int argc, const char * argv[]) {
    if (getuid()) {
        fprintf(stderr, "This tool requires root privileges\n");
        exit(EXIT_FAILURE);
    }
    
    Interface ifname(DEFAULT_WLAN);
    
    int arg, argslot;
    while (argslot = -1, (arg = getopt_long(argc, (char * const *)argv, "c:i:h", options, &argslot)) != -1) {
        switch (arg) {
            case 'c' : {
                uint32_t chan = atoi(optarg);
                if (find(channels.begin(), channels.end(), chan) != channels.end()) {
                    channels.emplace_back(chan);
                }
                break;
            }
            case 'i' : {
                ifname = Interface(optarg);
                break;
            }
            case 'h' : {
                fprintf(stdout, "%s [-i|--ifname " DEFAULT_WLAN "] [-c|--channel D]\nUse at your own risk & don't be jerk!\n", argv[0]);
                return 0;
            }
        }
    }
    
    if (channels.size() == 0) {
#if defined(__APPLE__)
        channels = {1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48,52,56,60,64,149,153,157,161,165};
#elif defined(__RASPBIAN__)
        channels = {1,2,3,4,5,6,7,8,9,10,11};
#endif
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
        sniffer_done = false;
        channel_done = false;
        signal(SIGINT, quit);
        Sniffer sniffer(ifname);

        sniffer.capture([&](const CapturedPacket & packet) -> bool {
            if (packet.is_valid()) {
                fprintf(stdout, "%s -> %s -> %s [%d]\n", packet.header()->source()->stringify().c_str(), packet.header()->transmitter()->stringify().c_str(), packet.header()->destination()->stringify().c_str(), packet.RSSI());
                fflush(stdout);
            }
            if (!working) sniffer_done = true;
            return working;
        });
        
        std::thread channel_change([&]{
            while (working) {
                for (int i = 0; i < channels.size(); ++i) {
                    if (!working) break;
                    ifname.setChannel(channels[i]);
                    sleep(1);
                }
            }
            channel_done = true;
        });
        
        std::mutex mtx;
        std::thread ([&]{
            std::unique_lock<std::mutex> lock(mtx);
            cond.wait(lock);
            working = false;
            while (!sniffer_done || !channel_done) this_thread::yield();
            channel_change.join();
        }).join();
    }
    
    return 0;
}

void quit(int) {
    working = false;
    cond.notify_one();
}
