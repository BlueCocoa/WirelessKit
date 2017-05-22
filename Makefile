CXX = g++
AR = ar
RANLIB = ranlib

PREFIX ?= /usr/local
WirelessKitSource = WirelessKit/WirelessKit.cpp
WirelessKitHeader = WirelessKit/WirelessKit.hpp
WirelessKitObject = obj/WirelessKit.o
WirelessKitLib = lib/libWirelessKit.a

authflood = authflood

CPPFLAGS += -Os -I./WirelessKit -std=c++14 -fPIC
LDFLAGS += -lpcap -lpthread -Llib -lWirelessKit
ARFLAGS += -crv $(WirelessKitLib) $(WirelessKitObject)
RANLIBFLAGS += $(WirelessKitLib)

$(WirelessKitLib) : 
	@rm -f ./lib
	@rm -f ./obj
	@rm -f ./bin
	@mkdir lib
	@mkdir obj
	@mkdir bin
	$(CXX) $(CPPFLAGS) -c $(WirelessKitSource) -o $(WirelessKitObject)
	case `uname` in Darwin*) $(AR) crv $(WirelessKitLib) $(WirelessKitObject) ;; *) $(AR) cr $(WirelessKitLib) && $(AR) crv $(WirelessKitLib) $(WirelessKitObject) ;; esac
	$(RANLIB) $(RANLIBFLAGS)

authflood : $(WirelessKitLib)
	$(CXX) $(CPPFLAGS) $(LDFLAGS) authflood/authflood.cpp -o bin/authflood

deauth : $(WirelessKitLib)
	$(CXX) $(CPPFLAGS) $(LDFLAGS) deauth/deauth.cpp -o bin/deauth

fakebeacon : $(WirelessKitLib)
	$(CXX) $(CPPFLAGS) $(LDFLAGS) fakebeacon/fakebeacon.cpp -o bin/fakebeacon
	
sniffer : $(WirelessKitLib)
	$(CXX) $(CPPFLAGS) $(LDFLAGS) sniffer/sniffer.cpp -o bin/sniffer

all : $(WirelessKitLib) authflood deauth fakebeacon sniffer
	

install :
	install -m 775 $(WirelessKitLib) $(PREFIX)/lib
	install -m 644 $(WirelessKitHeader) $(PREFIX)/include

install-demo :
	install -m 775 $(wildcard bin/*) $(PREFIX)/bin
	
uninstall-demo :
	-rm -f $(PREFIX)/bin/authflood
	-rm -f $(PREFIX)/bin/deauth
	-rm -f $(PREFIX)/bin/fakebeacon
	-rm -f $(PREFIX)/bin/sniffer

uninstall :
	rm -f $(PREFIX)/lib/$(WirelessKitLib)
	rm -f $(PREFIX)/include/$(WirelessKitHeader)

clean :
	-rm -rf ./lib
	-rm -rf ./obj
	-rm -rf ./bin
