//
//  handleFunctions.c
//  Network Classification - Feature Extraction
//
//  Created by Barış Yamansavaşçılar on 1.01.2015.
//  Copyright (c) 2015 Barış Yamansavaşçılar. All rights reserved.
//

#include "handleFunctions.h"
#include "FeatureExtractionFunctions.h"
#include <math.h>



void handleIP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet){
    struct ip *packetIP;
    struct tcphdr *packetTCP;
    struct udphdr *packetUDP;
    unsigned key;
    Packet *newPacket = (Packet *)malloc(sizeof(Packet));
    u_int length = pkthdr->len;
    if (DEBUG) {
        printf("Length: %d \n",length);
        printf("Raw packet length: %lu\n\n",sizeof(packet));
    }
    
    packetIP = (struct ip *)(packet+sizeof(struct ether_header)); //ip packet
    if ((int)packetIP->ip_p == 17) {
        packetUDP = (struct udphdr *)(packet+sizeof(struct ether_header)+sizeof(struct ip));
        newPacket->udp_Packet = *packetUDP;
        newPacket->isTCP = 0;
        key = calculateKeyUDP(*packetIP, *packetUDP);
    } else if ((int)packetIP->ip_p == 6){
        packetTCP = (struct tcphdr *)(packet+sizeof(struct ether_header)+packetIP->ip_hl*4); //tcp packet
        newPacket->tcp_Packet = *packetTCP;
        newPacket->isTCP = 1;
        key = calculateKeyTCP(*packetIP, *packetTCP);
    } else{
        return; //only udp or tcp packets
    }
    
    int index = hashAndPlace(key, HashSize, packetIP);
    flowTable[index]->packetCount++;
    newPacket->ip_packet = *packetIP;
    packetCount++;
    newPacket->nextPacket = NULL;
    newPacket->ts = pkthdr->ts;
    newPacket->len = pkthdr->len;
    
    addPacketToLinkedList(newPacket, index);
    
    //time-based operation
    if (isTimeBased) {
        double passedTime = 0;
        if (flowTable[index]->forwardPacketCount > 0 || flowTable[index]->backwardPacketCount > 0 ) {
            
            double lastPacketTime = newPacket->ts.tv_sec + (newPacket->ts.tv_usec * pow(10.0, -6));
            //printf("LastPacket Time : %f\n",lastPacketTime);
            if (newPacket->ip_packet.ip_src.s_addr == flowTable[index]->sourceIP) { //if true, then it is a forward packet
                
                if (flowTable[index]->forwardPacketCount > 0) {
                   // Packet *packet = flowTable[index]->forwardPackets;
                    
                    long double beginPacket = 0.0;
                    beginPacket =  flowTable[index]->forwardPackets->ts.tv_sec + flowTable[index]->forwardPackets->ts.tv_usec*pow(10.0, -6);
                    
                    passedTime = lastPacketTime - beginPacket;
                    
                                    if (passedTime < 0) {
                                        char buff[25];
                                        printf("First's time: %ld , %d\n",flowTable[index]->forwardPackets->ts.tv_sec,flowTable[index]->forwardPackets->ts.tv_usec);
                                        printf("Last's time:  %ld , %d\n",newPacket->ts.tv_sec,newPacket->ts.tv_usec);
                                        double deneme = mergeIntegersToDecimal( newPacket->ts.tv_sec - flowTable[index]->forwardPackets->ts.tv_sec , newPacket->ts.tv_usec -flowTable[index]->forwardPackets->ts.tv_usec);
                                        printf("First: ");
                                        strftime(buff, 20, "%Y-%m-%d %H:%M:%S\n", localtime(&flowTable[index]->forwardPackets->ts.tv_sec));
                                        printf("%s",buff);
                                        printf("Last: ");
                                        strftime(buff, 20, "%Y-%m-%d %H:%M:%S\n", localtime(&newPacket->ts.tv_sec));
                                        printf("%s",buff);
                                        printf("packet count : %d\n",packetCount);
                                        printf("olmamali\n");
                                    }
                    
                }else{
                    passedTime = 0;
                }

                
            }else{
                
                if (flowTable[index]->backwardPacketCount > 0 ) {
                    double long beginPacket = flowTable[index]->backwardPackets->ts.tv_sec + flowTable[index]->backwardPackets->ts.tv_usec*pow(10.0, -6);
                    passedTime = lastPacketTime - beginPacket;
//                                    if (lastPacketTime<beginPacket) {
//                                        printf("olmamali\n");
//                                    }
                    
                }else{
                    passedTime = 0;
                }
                
            }
            
            
        }
        
        //ya time ya da fixed-size calisacak!!
        
        if (passedTime>=TimeThreshold) {
            //printf("Passed Time: %f\n",passedTime);
            
            Packet **tempPacketArray = getFixedSizedPacketsFromFlow(index, 1);
            int *densityArray = (int *)malloc(sizeof(int)*10);
            densityArray = density(tempPacketArray, flowTable[index]->forwardPacketCount);
            FILE *arfFile;
            arfFile = fopen("time.txt","a");
            if (arfFile == NULL) {
                perror("fİLE ERROR");
            }
            /*
            char *tempStr1 = malloc(sizeof(char)*50);
            sprintf(tempStr1, "%f",(float)minIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount));
            float deneme131;
            deneme131 = (float)minIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount);
            char *tempStr12 = malloc(sizeof(char)*50);
            sprintf(tempStr12, "%f",deneme131);
            sscanf(tempStr1, "%f",&deneme131);
            //deneme131 = floor(deneme131 * 10000000) / 1000000;
            deneme131 = ceilf(deneme131*1000000);
            deneme131 = deneme131/1000000;
             */
            fprintf(arfFile, "%d, %d, %d, %d, %f, %f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d,",
                    flowTable[index]->forwardPacketCount, //number of packets
                    numberOfBytes(tempPacketArray, flowTable[index]->forwardPacketCount),
                    minPacketLength(tempPacketArray,flowTable[index]->forwardPacketCount),
                    maxPacketLength(tempPacketArray,flowTable[index]->forwardPacketCount),
                    averagePacketLength(tempPacketArray, flowTable[index]->forwardPacketCount),
                    standardDeviation(tempPacketArray, flowTable[index]->forwardPacketCount),
                    minIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount),
                    maxIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount),
                    averageIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount),
                    standardDeviationOfIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount),
                    newPacket->ip_packet.ip_p, //protocol
                    densityArray[0],densityArray[1],densityArray[2],densityArray[3],densityArray[4],
                    densityArray[5],densityArray[6],densityArray[7],densityArray[8],densityArray[9]
                    );
            
            // for backward packets
            
            Packet **tempArray2 = getFixedSizedPacketsFromFlow(index, 0);
            densityArray = density(tempArray2, flowTable[index]->backwardPacketCount);
            fprintf(arfFile, " %d, %d, %d, %d, %f, %f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %s, %s\n",
                    flowTable[index]->backwardPacketCount, //number of packets
                    numberOfBytes(tempArray2, flowTable[index]->backwardPacketCount),
                    minPacketLength(tempArray2,flowTable[index]->backwardPacketCount),
                    maxPacketLength(tempArray2,flowTable[index]->backwardPacketCount),
                    averagePacketLength(tempArray2, flowTable[index]->backwardPacketCount),
                    standardDeviation(tempArray2, flowTable[index]->backwardPacketCount),
                    minIntervalPacketTime(tempArray2, flowTable[index]->backwardPacketCount),
                    maxIntervalPacketTime(tempArray2, flowTable[index]->backwardPacketCount),
                    averageIntervalPacketTime(tempArray2, flowTable[index]->backwardPacketCount),
                    standardDeviationOfIntervalPacketTime(tempArray2, flowTable[index]->backwardPacketCount),
                    newPacket->ip_packet.ip_p, //protocol
                    densityArray[0],densityArray[1],densityArray[2],densityArray[3],densityArray[4],
                    densityArray[5],densityArray[6],densityArray[7],densityArray[8],densityArray[9],
                    subClass,
                    className
                    );
            
            //sıfırlama islemleri
            sampleCount++;
            flowTable[index]->packetCount = 0;
            if (flowTable[index]->forwardPacketCount != 0) {
                deleteLinkedList(&flowTable[index]->forwardPackets);
            }
            if (flowTable[index]->backwardPacketCount != 0) {
                deleteLinkedList(&flowTable[index]->backwardPackets);
            }
            
            
            flowTable[index]->forwardPackets = NULL;
            flowTable[index]->backwardPackets = NULL;
            flowTable[index]->forwardPacketCount = 0;
            flowTable[index]->backwardPacketCount = 0;
            
            
            fclose(arfFile);
        }
    }
    
    else {
    
    
    //fixed-based operation
    
    if (flowTable[index]->packetCount  == ThresholdOfPacketCount && (flowTable[index]->forwardPacketCount > 0 || flowTable[index]->backwardPacketCount > 0) ) {
        //feature extraction for fixed packet count
        // for forward packets
        //printf("Packet Count: %d \n",flowTable[index]->packetCount);//debug
        Packet **tempPacketArray = getFixedSizedPacketsFromFlow(index, 1);
        int *densityArray = (int *)calloc(10, sizeof(int));
        densityArray = density(tempPacketArray, flowTable[index]->forwardPacketCount);
        FILE *arfFile;
        arfFile = fopen("fixedSize.txt","a");
        if (arfFile == NULL) {
            perror("fİLE ERROR");
        }
        isForward = 1;
        fprintf(arfFile, "%d, %d, %d, %d, %f, %f, %f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d,%f, %f, %f, %f, %f, ",
                flowTable[index]->forwardPacketCount, //number of packets
                numberOfBytes(tempPacketArray, flowTable[index]->forwardPacketCount),
                minPacketLength(tempPacketArray,flowTable[index]->forwardPacketCount),
                maxPacketLength(tempPacketArray,flowTable[index]->forwardPacketCount),
                averagePacketLength(tempPacketArray, flowTable[index]->forwardPacketCount),
                standardDeviation(tempPacketArray, flowTable[index]->forwardPacketCount),
                minIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount),
                maxIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount),
                averageIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount),
                standardDeviationOfIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount),
                durationForFixedPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                newPacket->ip_packet.ip_p, //protocol
                densityArray[0],densityArray[1],densityArray[2],densityArray[3],densityArray[4],
                densityArray[5],densityArray[6],densityArray[7],densityArray[8],densityArray[9],
                numberOfBytesToPacketCount(numberOfBytes(tempPacketArray, flowTable[index]->forwardPacketCount), flowTable[index]->forwardPacketCount),
                minIntervalvsPacketCount(minIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount), flowTable[index]->forwardPacketCount),
                maxIntervalvsPacketCount(maxIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount), flowTable[index]->forwardPacketCount),
                maxPacketSizeToStandardDeviation(maxPacketLength(tempPacketArray,flowTable[index]->forwardPacketCount), standardDeviation(tempPacketArray, flowTable[index]->forwardPacketCount)),
                averagePacketSizeToStandardDeviation(averagePacketLength(tempPacketArray, flowTable[index]->forwardPacketCount), standardDeviationOfIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount))
                );
        
        // for backward packets
        isForward = 0;
        Packet ** tempPacketArray2 = getFixedSizedPacketsFromFlow(index, 0);
        densityArray = density(tempPacketArray2, flowTable[index]->backwardPacketCount);
        fprintf(arfFile, " %d, %d, %d, %d, %f, %f, %f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %f, %f, %f, %f, %f, %s, %s\n",
                flowTable[index]->backwardPacketCount, //number of packets
                numberOfBytes(tempPacketArray2, flowTable[index]->backwardPacketCount),
                minPacketLength(tempPacketArray2,flowTable[index]->backwardPacketCount),
                maxPacketLength(tempPacketArray2,flowTable[index]->backwardPacketCount),
                averagePacketLength(tempPacketArray2, flowTable[index]->backwardPacketCount),
                standardDeviation(tempPacketArray2, flowTable[index]->backwardPacketCount),
                minIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount),
                maxIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount),
                averageIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount),
                standardDeviationOfIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount),
                durationForFixedPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                newPacket->ip_packet.ip_p, //protocol
                densityArray[0],densityArray[1],densityArray[2],densityArray[3],densityArray[4],
                densityArray[5],densityArray[6],densityArray[7],densityArray[8],densityArray[9],
                numberOfBytesToPacketCount(numberOfBytes(tempPacketArray2, flowTable[index]->backwardPacketCount), flowTable[index]->backwardPacketCount),
                minIntervalvsPacketCount(minIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount), flowTable[index]->backwardPacketCount),
                maxIntervalvsPacketCount(maxIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount), flowTable[index]->backwardPacketCount),
                maxPacketSizeToStandardDeviation(maxPacketLength(tempPacketArray2,flowTable[index]->backwardPacketCount), standardDeviation(tempPacketArray2, flowTable[index]->backwardPacketCount)),
                averagePacketSizeToStandardDeviation(averagePacketLength(tempPacketArray2, flowTable[index]->backwardPacketCount), standardDeviationOfIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount)),
                subClass,
                className
                );
        
        //sampleCount += flowTable[index]->packetCount;
        sampleCount++;
        //sıfırlama islemleri
        flowTable[index]->packetCount = 0;
        if (flowTable[index]->forwardPacketCount != 0) {
            deleteLinkedList(&flowTable[index]->forwardPackets);
        }
        if (flowTable[index]->backwardPacketCount != 0) {
            deleteLinkedList(&flowTable[index]->backwardPackets);
        }
        flowTable[index]->forwardPackets = NULL;
        flowTable[index]->backwardPackets = NULL;
        flowTable[index]->forwardPacketCount = 0;
        flowTable[index]->backwardPacketCount = 0;
        
        
        fclose(arfFile);
        free(densityArray);
    }
    
    }
    
    
    
    
    if(DEBUG){
        printf("Source IP: %s\n",inet_ntoa(packetIP->ip_src));
        printf("Dest IP: %s\n",inet_ntoa(packetIP->ip_dst));
        unsigned char thflags = packetTCP->th_flags;
        /*
        printf("TCP source port: %d \nTCP dest port: %d ", ntohs(packetTCP->th_sport),
           ntohs(packetTCP->th_dport));
        printf("UDO source port: %d \nUDP dest port: %d",ntohs(packetUDP->uh_sport),
               ntohs(packetUDP->uh_dport));
        printf("\nProtocol: %d",packetIP->ip_p);
         */
        thflags = packetTCP->th_flags;
        printf("\nflags: ");
        if (thflags & TH_SYN)
            printf("SYN ");
        if (thflags & TH_ACK)
            printf("ACK ");
        if (thflags & TH_FIN)
            printf("FIN ");
        if (thflags & TH_RST)
            printf("RST ");
        if (thflags & TH_PUSH)
            printf("PUSH ");
        if (thflags & TH_URG)
            printf("URG ");
        if (thflags & TH_ECE)
            printf("ECE ");
        if (thflags & TH_CWR)
            printf("CWR ");
        printf("\n");
    }
}

u_int16_t handleEthernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
    struct ether_header *eptr;  /* net/ethernet.h */
    
    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    
    if (DEBUG) {
        fprintf(stdout,"ethernet header source: %s"
                ,ether_ntoa((const struct ether_addr *)&eptr->ether_shost));
        fprintf(stdout," destination: %s "
                ,ether_ntoa((const struct ether_addr *)&eptr->ether_dhost));
        
        /* check to see if we have an ip packet */
        if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
        {
            fprintf(stdout,"(IP)");
        }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
        {
            fprintf(stdout,"(ARP)");
        }else  if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP)
        {
            fprintf(stdout,"(RARP)");
        }else {
            fprintf(stdout,"Unknown Type");
            //exit(1);
        }
        fprintf(stdout,"\n");
    }
    
    
    
    return eptr->ether_type;
}

unsigned calculateKeyTCP (struct ip ipPacket, struct tcphdr tcpHeader){
    unsigned key;
    key = ipPacket.ip_src.s_addr / 313;
    key += ipPacket.ip_dst.s_addr / 313;
    key += tcpHeader.th_sport * 3;
    key += tcpHeader.th_dport * 3;
    key += ipPacket.ip_p * 7;
    
    return key;
}

unsigned calculateKeyUDP (struct ip ipPacket, struct udphdr udpHeader){
    unsigned key;
    key = ipPacket.ip_src.s_addr / 313;
    key += ipPacket.ip_dst.s_addr / 313;
    key += udpHeader.uh_sport* 3;
    key += udpHeader.uh_dport * 3;
    key += ipPacket.ip_p * 7;
    
    return key;
}

int hashAndPlace (unsigned key, int tableSize, struct ip * packetIP){
    int index;
    Flow *flow = (Flow *)malloc(sizeof(Flow));
    
    flow->forwardPackets = NULL;
    flow->backwardPackets = NULL;
    flow->isClosed = 0;
    flow->packetCount = 0;
    flow->forwardPacketCount = 0;
    flow->backwardPacketCount=0;
    
    index = key % tableSize;
    int i = index;
    while (flowTable[i] != NULL && flowTable[i]->key != key) { //if there is a collision in hashtable
        i++;
    }
    if (i==index && flowTable[i]==NULL) { //mevcut hashtable index'i tamamen bos ise (dolayisiyla bu akisin ilk paketi oluyor) ve collusion yoksa
        flow->key = key;
        flow->sourceIP = packetIP->ip_src.s_addr; //to assess forward and backward packets
        flowTable[index] = flow;
        flowCount++; //debug
        return index;
        
    }
    //tekrarlamisim sanki?
    else if (i!=index && flowTable[i] == NULL) { // mevcut hashtable index'i tamamen bos ise (dolayisiyla bu akisin ilk paketi oluyor) ve collusion varsa
        flow->key = key;
        flow->sourceIP = packetIP->ip_src.s_addr;
        flowTable[i] = flow;
        flowCount++; //debug
        return i;
    }else{
        free(flow);
        return i; // paket hashtable'in i. index'indeki n. eleman, addPacketToLinkedList fonksiyonu ile forwardPacket ya da backwardPacket linkli listesine     eklenecek
    }
    
}

void addPacketToLinkedList (Packet *packet, int index){
    if (flowTable[index]->sourceIP == packet->ip_packet.ip_src.s_addr) { //if it is true, forward packet
        flowTable[index]->forwardPacketCount++;
        if (flowTable[index]->forwardPackets == NULL) {
            flowTable[index]->forwardPackets = packet;
        }else{
            Packet *tempPacket = (Packet *)malloc(sizeof(Packet));
            tempPacket = flowTable[index]->forwardPackets; //forwardPackets'in ilk paketi
            while (tempPacket->nextPacket != NULL) {    //bu ilk paketten baslanarak listesinin sonuna kadar gidiliyor ve paket ekleniyor
                tempPacket = tempPacket->nextPacket;
            }
            tempPacket->nextPacket = packet;
        }
    }else{ //for backward packets (forwardPackets ile aynı mantık)
        flowTable[index]->backwardPacketCount++;
        if (flowTable[index]->backwardPackets == NULL) {
            flowTable[index]->backwardPackets = packet;
        }else{
            Packet *tempPacket = (Packet *)malloc(sizeof(Packet));
            tempPacket = flowTable[index]->backwardPackets;
            while (tempPacket->nextPacket != NULL) {
                tempPacket = tempPacket->nextPacket;
            }
            tempPacket->nextPacket = packet;
        }
    }
}

double mergeIntegersToDecimal(long a, int b){
    //int decimals = log10(b) + 1;
    int decimals = 6;
    return a + b*pow(10.0, -decimals);
}

Packet ** getFixedSizedPacketsFromFlow (int index, int isForward){
    int packetCount;
    int size;
    if (isForward) {
        size =  flowTable[index]->forwardPacketCount;
    }else{
        size =  flowTable[index]->backwardPacketCount;
    }
    Packet **tempPacketArray = (Packet **)malloc(size * sizeof(Packet));
    Packet *packet = (Packet *)malloc(sizeof(Packet));
    tempPacketArray[0] = (Packet *)malloc(sizeof(Packet));
    if (size == 0) {    //icinde hic paket yoksa
        tempPacketArray[0] = NULL;
        return tempPacketArray;
    }
    if (isForward) {
        tempPacketArray[0] = flowTable[index]->forwardPackets;
        packet = flowTable[index]->forwardPackets;
        packetCount = flowTable[index]->forwardPacketCount;
    }else{
        tempPacketArray[0] = flowTable[index]->backwardPackets;
        packet = flowTable[index]->backwardPackets;
        packetCount = flowTable[index]->backwardPacketCount;
    }
    
    for (int i=1; i < packetCount; i++) {
        tempPacketArray[i] = (Packet *)malloc(sizeof(Packet));
        packet = packet->nextPacket;
        tempPacketArray[i] = packet;
    }
    
    return tempPacketArray;
}

void deleteLinkedList (Packet **head){
    Packet **packet = (Packet **)malloc(sizeof(Packet));
    Packet **next =(Packet **)malloc(sizeof(Packet));
    *next = (*head)->nextPacket;
    
    while (*next) {
        *packet = *next;
        *next = (*next)->nextPacket;
        free(*packet);
        *packet = NULL;
    }
    free(*head);
    *head = NULL;
}

char * extractSubclassName(char *pcapFile){
    char *subclassName = (char *)calloc(20, sizeof(char));
    
    char aChar;
    int i=0;
    while (aChar!='_') {
        subclassName[i] = pcapFile[i];
        aChar = pcapFile[i+1];
        i++;
    }
    
    
    return subclassName;
}


void allocFlowtable(){
    flowTable = (Flow **)malloc(sizeof(Flow)*HashSize);
    for (int i = 0; i<HashSize; i++) {
        flowTable[i] = (Flow *)malloc(sizeof(Flow));
        flowTable[i] = NULL;
    }
}

void deallocFlowtable(){
    for (int i = 0; i<HashSize; i++) {
   //     flowTable[i] = NULL;
        free(flowTable[i]);
        flowTable[i] = NULL;
    }
    //flowTable = NULL;
    free(flowTable);
    flowTable = NULL;
    //flowTable = NULL;
}
