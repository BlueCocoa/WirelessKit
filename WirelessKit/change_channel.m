//
//  main.m
//  change_channel
//
//  Created by BlueCocoa on 2017/5/24.
//  Copyright © 2017 BlueCocoa. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <CoreWLAN/CoreWLAN.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated"

bool setChannel(const char * ifname, int channel) {
    // -[CWWiFiClient interfaceWithName:] has some weird error
    CWInterface * interface = [[CWInterface alloc] initWithInterfaceName:[[NSString alloc] initWithUTF8String:ifname]];
    NSSet<CWChannel *> * supported = [interface supportedWLANChannels];
    for (CWChannel * chan in supported) {
        if ([chan channelNumber] == channel) {
            NSError * error = nil;
            [interface disassociate];
            [interface setWLANChannel:chan error:&error];
            if (error) {
                return false;
            }
            return true;
        }
    }
    return false;
}

#pragma clang diagnostic pop

int main(int argc, const char * argv[]) {
    @autoreleasepool {
        if (argc == 3) {
            return setChannel(argv[1], atoi(argv[2])) == false;
        }
    }
    return 1;
}
