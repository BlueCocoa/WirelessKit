/*
 *  WirelessKit.hpp
 *  WirelessKit
 *
 *  Created by BlueCocoa on 2017/5/19.
 *  Copyright © 2017 BlueCocoa. All rights reserved.
 *
 */

#ifndef __WIRELESSKIT__
#define __WIRELESSKIT__

#include <stdint.h>
#include <pcap.h>
#include <functional>
#include <memory>
#include <string>
#include <thread>

/* The classes below are exported */
#pragma GCC visibility push(default)

namespace WirelessKit {
    /*
     *  @brief Types
     */
    class MAC {
    public:
        MAC(const uint8_t mac[6]);
        MAC(const std::string mac);
        MAC(const MAC & _);
        ~MAC();
        bool is_valid() const;
        std::string stringify() const;
        bool is_equal(const MAC & _);
        
        /**
         *  @brief returns a copy of STA's MAC address
         *  @note  please delete[] the pointer after use
         */
        uint8_t * mac_copy() const;
        uint8_t * mac();
        static MAC random();
        static MAC broadcast();
        static bool is_equal(const MAC & a, const MAC & b);
    /* private: */
    /**
     *  Variables below should be private
     *  But it would be easier for people whom knows what [s]he's doing
     */
        bool _valid;
        std::shared_ptr<uint8_t *> _data;
    };
    
    typedef struct BeaconCapabilitiesInfo {
        uint16_t ESS                        : 1;
        uint16_t IBSS_status                : 1;
        uint16_t CFP_lsb2                   : 2;
        uint16_t Privacy                    : 1;
        uint16_t ShortPreamble              : 1;
        uint16_t PBCC                       : 1;
        uint16_t ChannelAgility             : 1;
        uint16_t SpectrumManagement         : 1;
        uint16_t CFP_msb                    : 1;
        uint16_t ShortSlotTime              : 1;
        uint16_t AutomacticPowerSaveDelivery: 1;
        uint16_t RadioMeasurment            : 1;
        uint16_t DSSS_OFDM                  : 1;
        uint16_t DelayedBlockAck            : 1;
        uint16_t ImmediateBlockAck          : 1;
    } __attribute__((__packed__)) BeaconCapabilitiesInfo;
    
    class AP {
    public:
        AP();
        ~AP();
        AP(const MAC & mac);
        AP(const AP & _);
        AP(std::string SSID, const MAC & mac);
        bool setMAC(const MAC & mac);
        void setSSID(std::string SSID);
        
        /**
         *  @brief returns a copy of STA's MAC address
         *  @note  please delete[] the pointer after use
         */
        uint8_t * mac_copy() const;
        uint8_t * mac();
        
        BeaconCapabilitiesInfo beaconCapabilitiesInfo;
        
    /* private: */
    /*
     *  Variables below should be private
     *  But it would be easier for people whom knows what [s]he's doing
     */
        std::shared_ptr<MAC> _mac;
        std::string _SSID;
    };
    
    class STA {
    public:
        STA();
        ~STA();
        STA(const STA & _);
        STA(const MAC & mac);
        bool setMAC(const MAC & mac);
        
        /**
         *  @brief returns a copy of STA's MAC address
         *  @note  please delete[] the pointer after use
         */
        uint8_t * mac_copy() const;
        uint8_t * mac();
        
    /* private: */
    /*
     *  Variables below should be private
     *  But it would be easier for people whom knows what [s]he's doing
     */
        std::shared_ptr<MAC> _mac;
    };
    
    class Interface {
    public:
        Interface(std::string ifname);
        Interface(const Interface & _);
        ~Interface();
        bool open();
        bool setChannel(int channel);
        
    /* private: */
    /*
     *  Variables below should be private
     *  But it would be easier for people whom knows what [s]he's doing
     */
        std::string _ifname;
        pcap_t * _pcap_handle;
    };
    
    typedef struct FrameControl {
        uint16_t version        : 2;
        uint16_t type           : 2;
        uint16_t subtype        : 4;
        uint16_t to_ds          : 1;
        uint16_t from_ds        : 1;
        uint16_t more_fragments : 1;
        uint16_t retry          : 1;
        uint16_t PWR_MGT        : 1;
        uint16_t more_data      : 1;
        uint16_t protected_flag : 1;
        uint16_t order          : 1;
    } __attribute__((__packed__)) FrameControl;
    
    class MACHeader {
    public:
        MACHeader();
        MACHeader(const MACHeader & _);
        MACHeader(const uint8_t * data);
        ~MACHeader();
        void setDestination(const MAC & destination);
        void setDestination(const std::shared_ptr<MAC> destination);
        void setTransmitter(const MAC & transmitter);
        void setTransmitter(const std::shared_ptr<MAC> transmitter);
        void setSource(const MAC & source);
        void setSource(const std::shared_ptr<MAC> source);
        MAC * destination() const;
        MAC * transmitter() const;
        MAC * source() const;
        uint8_t * data() const;
        
        FrameControl fc;
        uint16_t duration;
        uint16_t sequence;
        
    /* private: */
    /*
     *  Variables below should be private
     *  But it would be easier for people whom knows what [s]he's doing
     */
        std::shared_ptr<MAC> _destination;
        std::shared_ptr<MAC> _transmitter;
        std::shared_ptr<MAC> _source;
    };
    
    class CapturedPacket {
    public:
        CapturedPacket(struct pcap_pkthdr * header, const u_char * buffer);
        CapturedPacket(const CapturedPacket & _);
        ~CapturedPacket();
        bool is_valid() const;
        MACHeader * header() const;
        const u_char * packet_data() const;
        const u_char * body_data() const;
        int packet_len() const;
        int body_len() const;
        
    /* private: */
    /*
     *  Variables below should be private
     *  But it would be easier for people whom knows what [s]he's doing
     */
        bool _valid;
        std::shared_ptr<MACHeader> _header;
        int _packet_len;
        const u_char * _packet_data;
        int _body_len;
        const u_char * _body_data;
    };
    
    /*
     *  @brief Utility
     */
    class Sniffer {
    public:
        Sniffer();
        Sniffer(const Interface ifname);
        ~Sniffer();
        CapturedPacket capture_block();
        void capture(std::function<bool(const CapturedPacket & captured)> callback);
        
    /* private: */
    /*
     *  Variables below should be private
     *  But it would be easier for people whom knows what [s]he's doing
     */
        std::shared_ptr<Interface> _ifname;
        std::shared_ptr<std::thread> _capturer;
    };
    
    /*
     *  @brief Extented types
     */
    class DeauthClient {
    public:
        DeauthClient(const AP & ap, const STA & station);
        DeauthClient(const DeauthClient & _);
        ~DeauthClient();
        uint8_t * packet(size_t * bytes) const;
        void deauth(const Interface & ifname) const;
        
    /* private: */
    /*
     *  Variables below should be private
     *  But it would be easier for people whom knows what [s]he's doing
     */
        std::shared_ptr<AP> _ap;
        std::shared_ptr<STA> _station;
    };
    
    class BeaconFloodFrame {
    public:
        BeaconFloodFrame(const AP & ap);
        uint8_t * packet(size_t * bytes) const;
        void beacon(const Interface & ifname) const;
        
    /* private: */
    /*
     *  Variables below should be private
     *  But it would be easier for people whom knows what [s]he's doing
     */
        std::shared_ptr<AP> _ap;
    };
    
    class AuthFloodFrame {
    public:
        AuthFloodFrame(const AP & ap);
        uint8_t * packet(size_t * bytes) const;
        void auth(const Interface & ifname) const;
        
    /* private: */
    /*
     *  Variables below should be private
     *  But it would be easier for people whom knows what [s]he's doing
     */
        std::shared_ptr<AP> _ap;
    };

    uint32_t crc32(const char *buf, size_t len);
}

#pragma GCC visibility pop
#endif
