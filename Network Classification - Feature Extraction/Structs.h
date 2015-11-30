//
//  Structs.h
//  Network Classification - Feature Extraction
//
//  Created by Barış Yamansavaşçılar on 31.12.2014.
//  Copyright (c) 2014 Barış Yamansavaşçılar. All rights reserved.
//

#ifndef Network_Classification___Feature_Extraction_Structs_h
#define Network_Classification___Feature_Extraction_Structs_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <pcap.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <dirent.h>

//********************* tutorialdan alınan header'lar
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
//************************* tutorialdan alınan header'lar

typedef struct Packet{
    struct ip ip_packet;
    struct tcphdr tcp_Packet;
    struct udphdr udp_Packet;
    struct timeval ts;
    u_int len;
    int isTCP;
    struct Packet *nextPacket;
}Packet;


typedef struct Flow{
    unsigned key;
    in_addr_t sourceIP;
    Packet *forwardPackets;
    Packet *backwardPackets;
    int isClosed;
    int forwardPacketCount;
    int backwardPacketCount;
    int packetCount;
    int allPacketsCount;
    int allByteSize;
    Packet firstPacket;
    Packet lastPacket;
}Flow;

Flow **flowTable;
char *className;
char *subClass;

int sampleCount;
int flowCount;
int packetCount;
int isForward;
#endif
