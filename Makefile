ccarm=mips-openwrt-linux-g++

x86:
	mkdir -p bin/x86
	g++ udp-forward.cpp -o bin/x86/udp-forward -static

arm:
	mkdir -p bin/arm
	${ccarm} udp-forward.cpp -o bin/arm/udp-forward -static -lgcc_eh