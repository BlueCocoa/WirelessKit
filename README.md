# WirelessKit
A simple framework on Wi-Fi Availability / Security (Coming soon).

### ⚠️Before Your Compiling
As a matter of fact, you can make trouble to your neighbors easily with these codes. However, think about HOW WOULD YOU FEEL LIKE when there is something needs to be done online while your neighbors are DOING THE SAME THING TO YOU. 

DO NOT BE A JERK!

### Compile Static Library
```$ make && sudo make install```

#### For Raspberry Pi
There're some issues with the static library.

### Compile Demos
```$ make all && sudo make install-demo```

#### For Raspberry Pi
Please compile demos with

```$ PLATFORM=RaspberryPi make all && sudo make install-demo```

### Demos

#### authflood
Sending forged Authentication packets from random MACs to fill a target AP's authentication table.

[IEEE 802.11 Denial-of-Service: Authentication Flood](https://blog.0xbbc.com/2017/05/ieee-802-11-denial-of-service-authentication-flood/)

![Screenshots](https://raw.githubusercontent.com/BlueCocoa/WirelessKit/master/authentication-flood.png)

#### deauth
Flooding station(s) with forged Deauthentication packets to disconnecting users from an AP.

[IEEE 802.11 Denial-of-Service: Deauthentication Attack](https://blog.0xbbc.com/2017/05/ieee-802-11-denial-of-service-deauthentication-attack/)

![Screenshots](https://raw.githubusercontent.com/BlueCocoa/WirelessKit/master/deauth-flood.png)

#### fakebeacon
Generating thousands of counterfeit 802.11 beacons to make it hard for stations to find a legitimate AP.

[IEEE 802.11 Attack: Beacon Flood](https://blog.0xbbc.com/2017/05/ieee-802-11-attack-beacon-flood/)

![Screenshots](https://raw.githubusercontent.com/BlueCocoa/WirelessKit/master/beacon-flood.png)

#### sniffer
Just as its name suggested :)

### Usage
You may refer to these demos. 
