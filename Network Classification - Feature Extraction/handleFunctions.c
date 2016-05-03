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

#define MTU_SIZE 1506

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
    
    newPacket->ip_packet = *packetIP;
    packetCount++;
    newPacket->nextPacket = NULL;
    newPacket->ts = pkthdr->ts;
    newPacket->len = pkthdr->len;
    if (packetCount == 1) {
        veryFirstPacket = *newPacket;
    }else{
        veryLastPacket = *newPacket;
    }
    
    int index = hashAndPlace(key, HashSize, newPacket);
    flowTable[index]->packetCount++;
    newPacket->packetNumber = flowTable[index]->packetCount;
    flowTable[index]->allPacketsCount++;
    flowTable[index]->allByteSize += pkthdr->len;
    flowTable[index]->lastPacket = *newPacket;
    
    
    addPacketToLinkedList(newPacket, index);
    
    
    indexOfTheFlow = index;
    
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
    
    else if (!isFullFlow){
    
    
    //fixed-based operation
    
    if (flowTable[index]->packetCount  == ThresholdOfPacketCount && (flowTable[index]->forwardPacketCount > 0 || flowTable[index]->backwardPacketCount > 0) ) {
        //feature extraction for fixed packet count
        // for forward packets
        //printf("Packet Count: %d \n",flowTable[index]->packetCount);//debug
        Packet **tempPacketArray = getFixedSizedPacketsFromFlow(index, 1);
        int *densityArray = (int *)calloc(10, sizeof(int));
        densityArray = density(tempPacketArray, flowTable[index]->forwardPacketCount);
        int *binsOfBytesForward = (int *)calloc(10, sizeof(int));
        binsOfBytesForward = binsOfBytes(tempPacketArray, flowTable[index]->forwardPacketCount);
        FILE *arfFile;
        arfFile = fopen("fixedSize.txt","a");
        if (arfFile == NULL) {
            perror("fİLE ERROR");
        }
        isForward = 1;
        fprintf(arfFile, "%d, %d, %f, %f, %f, %f, %f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d,%f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %f, %d, %d, %d, %d, %f,",
                flowTable[index]->forwardPacketCount, //number of packets
                numberOfBytes(tempPacketArray, flowTable[index]->forwardPacketCount),
                (double)minPacketLength(tempPacketArray,flowTable[index]->forwardPacketCount)/MTU_SIZE,
                (double)maxPacketLength(tempPacketArray,flowTable[index]->forwardPacketCount)/MTU_SIZE,
                averagePacketLength(tempPacketArray, flowTable[index]->forwardPacketCount)/MTU_SIZE,
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
                averagePacketSizeToStandardDeviation(averagePacketLength(tempPacketArray, flowTable[index]->forwardPacketCount), standardDeviationOfIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount)),
                totalNumberOfACKPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalNumberOfPUSHPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                binsOfBytesForward[0],binsOfBytesForward[1],binsOfBytesForward[2],binsOfBytesForward[3],binsOfBytesForward[4],
                binsOfBytesForward[5],binsOfBytesForward[6],binsOfBytesForward[7],binsOfBytesForward[8],binsOfBytesForward[9],
                totalNumberOfURGPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalNumberOfECEPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalNumberOfCWRPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalNumberOfRSTPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalNumberOfSYNPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalSizeOfURGPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalNumberOfPureACKPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                optionSetCount(tempPacketArray, flowTable[index]->forwardPacketCount),
                countOfActualDataPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                averageWindowSize(tempPacketArray, flowTable[index]->forwardPacketCount),
                zeroWindowCount(tempPacketArray, flowTable[index]->forwardPacketCount),
                minWindowSize(tempPacketArray, flowTable[index]->forwardPacketCount),
                maxWindowSize(tempPacketArray, flowTable[index]->forwardPacketCount),
                activeFlowCount(),
                averageInFlowRate(tempPacketArray, flowTable[index]->forwardPacketCount)
                );
        //totalNumberOfPureACKPackets(tempPacketArray, flowTable[index]->forwardPacketCount);
        // for backward packets
        isForward = 0;
        Packet ** tempPacketArray2 = getFixedSizedPacketsFromFlow(index, 0);
        int *binsOfBytesBackward = (int *)calloc(10, sizeof(int));
        binsOfBytesBackward = binsOfBytes(tempPacketArray2, flowTable[index]->backwardPacketCount);
        densityArray = density(tempPacketArray2, flowTable[index]->backwardPacketCount);
        fprintf(arfFile, " %d, %d, %f, %f, %f, %f, %f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %f, %f, %f, %f, %f,%d, %d, %d, %d, %d, %d,%d, %d, %d, %d, %d, %d, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %f, %d, %d, %d, %f, %f, %f, %f, %d, %s, %s\n",
                flowTable[index]->backwardPacketCount, //number of packets
                numberOfBytes(tempPacketArray2, flowTable[index]->backwardPacketCount),
                (double)minPacketLength(tempPacketArray2,flowTable[index]->backwardPacketCount)/MTU_SIZE,
                (double)maxPacketLength(tempPacketArray2,flowTable[index]->backwardPacketCount)/MTU_SIZE,
                averagePacketLength(tempPacketArray2, flowTable[index]->backwardPacketCount)/MTU_SIZE,
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
                totalNumberOfACKPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalNumberOfPUSHPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                binsOfBytesBackward[0],binsOfBytesBackward[1],binsOfBytesBackward[2],binsOfBytesBackward[3],binsOfBytesBackward[4],
                binsOfBytesBackward[5],binsOfBytesBackward[6],binsOfBytesBackward[7],binsOfBytesBackward[8],binsOfBytesBackward[9],
                ratioOfForwardAndBackwardPacketCounts(flowTable[index]->forwardPacketCount, flowTable[index]->backwardPacketCount),
                ratioOfBytesFAndB(numberOfBytes(tempPacketArray, flowTable[index]->forwardPacketCount), numberOfBytes(tempPacketArray2, flowTable[index]->backwardPacketCount)),
                totalNumberOfURGPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalNumberOfECEPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalNumberOfCWRPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalNumberOfRSTPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalNumberOfSYNPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalSizeOfURGPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalNumberOfPureACKPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                optionSetCount(tempPacketArray2, flowTable[index]->backwardPacketCount),
                countOfActualDataPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                averageWindowSize(tempPacketArray2, flowTable[index]->backwardPacketCount),
                zeroWindowCount(tempPacketArray2, flowTable[index]->backwardPacketCount),
                minWindowSize(tempPacketArray2, flowTable[index]->backwardPacketCount),
                maxWindowSize(tempPacketArray2, flowTable[index]->backwardPacketCount),
                averageInFlowRate(tempPacketArray2, flowTable[index]->backwardPacketCount),
                averageFlowRate(flowTable[index]),
                ratioOfAllPacketCounts(flowTable[index]),
                ratioOfOpenFlows(),
                flowCountForConnection(flowTable[index]),
                subClass,
                className
                );
        //totalNumberOfPureACKPackets(tempPacketArray2, flowTable[index]->backwardPacketCount);
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
        free(binsOfBytesForward);
        free(binsOfBytesBackward);
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

void getFeaturesFromFlow(int index){
    
        //feature extraction for fixed packet count
        // for forward packets
        //printf("Packet Count: %d \n",flowTable[index]->packetCount);//debug
        Packet **tempPacketArray = getFixedSizedPacketsFromFlow(index, 1);
        int *densityArray = (int *)calloc(10, sizeof(int));
        densityArray = density(tempPacketArray, flowTable[index]->forwardPacketCount);
        int *binsOfBytesForward = (int *)calloc(10, sizeof(int));
        binsOfBytesForward = binsOfBytes(tempPacketArray, flowTable[index]->forwardPacketCount);
        FILE *arfFile;
        arfFile = fopen("fixedSize.txt","a");
        if (arfFile == NULL) {
            perror("fİLE ERROR");
        }
        isForward = 1;
        int protocol;
        if (flowTable[index]->backwardPacketCount != 0) {
            protocol = flowTable[index]->backwardPackets[0].ip_packet.ip_p;
        }else if(flowTable[index]->forwardPackets != 0){
            protocol = flowTable[index]->forwardPackets[0].ip_packet.ip_p;
        }
        fprintf(arfFile, "%d, %d, %f, %f, %f, %f, %f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d,%f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %f, %d, %d, %d, %d, %f,",
                flowTable[index]->forwardPacketCount, //number of packets
                numberOfBytes(tempPacketArray, flowTable[index]->forwardPacketCount),
                (double)minPacketLength(tempPacketArray,flowTable[index]->forwardPacketCount)/MTU_SIZE,
                (double)maxPacketLength(tempPacketArray,flowTable[index]->forwardPacketCount)/MTU_SIZE,
                averagePacketLength(tempPacketArray, flowTable[index]->forwardPacketCount)/MTU_SIZE,
                standardDeviation(tempPacketArray, flowTable[index]->forwardPacketCount),
                minIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount),
                maxIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount),
                averageIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount),
                standardDeviationOfIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount),
                durationForFixedPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                protocol, //protocol
                densityArray[0],densityArray[1],densityArray[2],densityArray[3],densityArray[4],
                densityArray[5],densityArray[6],densityArray[7],densityArray[8],densityArray[9],
                numberOfBytesToPacketCount(numberOfBytes(tempPacketArray, flowTable[index]->forwardPacketCount), flowTable[index]->forwardPacketCount),
                minIntervalvsPacketCount(minIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount), flowTable[index]->forwardPacketCount),
                maxIntervalvsPacketCount(maxIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount), flowTable[index]->forwardPacketCount),
                maxPacketSizeToStandardDeviation(maxPacketLength(tempPacketArray,flowTable[index]->forwardPacketCount), standardDeviation(tempPacketArray, flowTable[index]->forwardPacketCount)),
                averagePacketSizeToStandardDeviation(averagePacketLength(tempPacketArray, flowTable[index]->forwardPacketCount), standardDeviationOfIntervalPacketTime(tempPacketArray, flowTable[index]->forwardPacketCount)),
                totalNumberOfACKPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalNumberOfPUSHPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                binsOfBytesForward[0],binsOfBytesForward[1],binsOfBytesForward[2],binsOfBytesForward[3],binsOfBytesForward[4],
                binsOfBytesForward[5],binsOfBytesForward[6],binsOfBytesForward[7],binsOfBytesForward[8],binsOfBytesForward[9],
                totalNumberOfURGPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalNumberOfECEPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalNumberOfCWRPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalNumberOfRSTPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalNumberOfSYNPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalSizeOfURGPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                totalNumberOfPureACKPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                optionSetCount(tempPacketArray, flowTable[index]->forwardPacketCount),
                countOfActualDataPackets(tempPacketArray, flowTable[index]->forwardPacketCount),
                averageWindowSize(tempPacketArray, flowTable[index]->forwardPacketCount),
                zeroWindowCount(tempPacketArray, flowTable[index]->forwardPacketCount),
                minWindowSize(tempPacketArray, flowTable[index]->forwardPacketCount),
                maxWindowSize(tempPacketArray, flowTable[index]->forwardPacketCount),
                activeFlowCount(),
                averageInFlowRate(tempPacketArray, flowTable[index]->forwardPacketCount)
                );
        //totalNumberOfPureACKPackets(tempPacketArray, flowTable[index]->forwardPacketCount);
        // for backward packets
        isForward = 0;
        Packet ** tempPacketArray2 = getFixedSizedPacketsFromFlow(index, 0);
        int *binsOfBytesBackward = (int *)calloc(10, sizeof(int));
        binsOfBytesBackward = binsOfBytes(tempPacketArray2, flowTable[index]->backwardPacketCount);
        densityArray = density(tempPacketArray2, flowTable[index]->backwardPacketCount);
        fprintf(arfFile, " %d, %d, %f, %f, %f, %f, %f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %f, %f, %f, %f, %f,%d, %d, %d, %d, %d, %d,%d, %d, %d, %d, %d, %d, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %f, %d, %d, %d, %f, %f, %f, %f, %d, %s, %s\n",
                flowTable[index]->backwardPacketCount, //number of packets
                numberOfBytes(tempPacketArray2, flowTable[index]->backwardPacketCount),
                (double)minPacketLength(tempPacketArray2,flowTable[index]->backwardPacketCount)/MTU_SIZE,
                (double)maxPacketLength(tempPacketArray2,flowTable[index]->backwardPacketCount)/MTU_SIZE,
                averagePacketLength(tempPacketArray2, flowTable[index]->backwardPacketCount)/MTU_SIZE,
                standardDeviation(tempPacketArray2, flowTable[index]->backwardPacketCount),
                minIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount),
                maxIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount),
                averageIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount),
                standardDeviationOfIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount),
                durationForFixedPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                protocol, //protocol
                densityArray[0],densityArray[1],densityArray[2],densityArray[3],densityArray[4],
                densityArray[5],densityArray[6],densityArray[7],densityArray[8],densityArray[9],
                numberOfBytesToPacketCount(numberOfBytes(tempPacketArray2, flowTable[index]->backwardPacketCount), flowTable[index]->backwardPacketCount),
                minIntervalvsPacketCount(minIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount), flowTable[index]->backwardPacketCount),
                maxIntervalvsPacketCount(maxIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount), flowTable[index]->backwardPacketCount),
                maxPacketSizeToStandardDeviation(maxPacketLength(tempPacketArray2,flowTable[index]->backwardPacketCount), standardDeviation(tempPacketArray2, flowTable[index]->backwardPacketCount)),
                averagePacketSizeToStandardDeviation(averagePacketLength(tempPacketArray2, flowTable[index]->backwardPacketCount), standardDeviationOfIntervalPacketTime(tempPacketArray2, flowTable[index]->backwardPacketCount)),
                totalNumberOfACKPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalNumberOfPUSHPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                binsOfBytesBackward[0],binsOfBytesBackward[1],binsOfBytesBackward[2],binsOfBytesBackward[3],binsOfBytesBackward[4],
                binsOfBytesBackward[5],binsOfBytesBackward[6],binsOfBytesBackward[7],binsOfBytesBackward[8],binsOfBytesBackward[9],
                ratioOfForwardAndBackwardPacketCounts(flowTable[index]->forwardPacketCount, flowTable[index]->backwardPacketCount),
                ratioOfBytesFAndB(numberOfBytes(tempPacketArray, flowTable[index]->forwardPacketCount), numberOfBytes(tempPacketArray2, flowTable[index]->backwardPacketCount)),
                totalNumberOfURGPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalNumberOfECEPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalNumberOfCWRPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalNumberOfRSTPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalNumberOfSYNPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalSizeOfURGPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                totalNumberOfPureACKPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                optionSetCount(tempPacketArray2, flowTable[index]->backwardPacketCount),
                countOfActualDataPackets(tempPacketArray2, flowTable[index]->backwardPacketCount),
                averageWindowSize(tempPacketArray2, flowTable[index]->backwardPacketCount),
                zeroWindowCount(tempPacketArray2, flowTable[index]->backwardPacketCount),
                minWindowSize(tempPacketArray2, flowTable[index]->backwardPacketCount),
                maxWindowSize(tempPacketArray2, flowTable[index]->backwardPacketCount),
                averageInFlowRate(tempPacketArray2, flowTable[index]->backwardPacketCount),
                averageFlowRate(flowTable[index]),
                ratioOfAllPacketCounts(flowTable[index]),
                ratioOfOpenFlows(),
                flowCountForConnection(flowTable[index]),
                subClass,
                className
                );
        //totalNumberOfPureACKPackets(tempPacketArray2, flowTable[index]->backwardPacketCount);
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
        free(binsOfBytesForward);
        free(binsOfBytesBackward);
    
}

void getSubFlowFromActualFlow(int index) {
    Packet **forwardPackets = (Packet **)malloc(ThresholdOfPacketCount* sizeof(Packet *));
    Packet **backwardPackets = (Packet **)malloc(ThresholdOfPacketCount* sizeof(Packet *));
    //Packet **allForwardPacketArray = NULL, **allBackwardPacketArray = NULL;
    
    Packet **allForwardPacketArray = getFixedSizedPacketsFromFlow(index, 1);
    Packet **allBackwardPacketArray = getFixedSizedPacketsFromFlow(index, 0);
    
    if (flowTable[index]->packetCount >= ThresholdOfPacketCount){
        int i = 0;
        int j = 0;
        int count = 0;
        int indexForward = 0;
        int indexBackward = 0;
        
        if (location == 0) {
            i = 0;
            j = 0;
            count = 0;
            indexForward = 0;
            indexBackward = 0;
        }
        else if (location == 1){
            int middleOfFlow = flowTable[index]->packetCount / 2;
            count = 0;
            int indexCount = 0;
            int packetNumber = 0;
            while (indexCount < flowTable[index]->forwardPacketCount && packetNumber < middleOfFlow) {
                //to be continued
                packetNumber = allForwardPacketArray[indexCount]->packetNumber;
                indexCount++;
                
            }
            if (indexCount < flowTable[index]->forwardPacketCount ) {
                indexForward = indexCount;
            }else{
                indexForward = flowTable[index]->forwardPacketCount + 2; //hic girmesin buna
            }
            
            //indexForward = middleOfFlow;
            //indexBackward = middleOfFlow;
            
            indexCount = 0;
            packetNumber = 0;
            while (indexCount < flowTable[index]->backwardPacketCount && packetNumber < middleOfFlow) {
                //to be continued
                packetNumber = allBackwardPacketArray[indexCount]->packetNumber;
                indexCount++;
                
            }
            if (indexCount < flowTable[index]->backwardPacketCount ) {
                indexBackward = indexCount;
            }else{
                indexBackward = flowTable[index]->backwardPacketCount + 2; //hic girmesin buna
            }
            
            
        }
        else if (location == 2){
            int endOfTheFlow = flowTable[index]->packetCount - ThresholdOfPacketCount;
            count = 0;
            int indexCount = 0;
            int packetNumber = 0;
            while (indexCount < flowTable[index]->forwardPacketCount && packetNumber < endOfTheFlow) {
                //to be continued
                packetNumber = allForwardPacketArray[indexCount]->packetNumber;
                indexCount++;
                
            }
            if (indexCount < flowTable[index]->forwardPacketCount ) {
                indexForward = indexCount;
            }else{
                indexForward = flowTable[index]->forwardPacketCount + 2; //hic girmesin buna
            }
            
            //indexForward = middleOfFlow;
            //indexBackward = middleOfFlow;
            
            indexCount = 0;
            packetNumber = 0;
            while (indexCount < flowTable[index]->backwardPacketCount && packetNumber < endOfTheFlow) {
                //to be continued
                packetNumber = allBackwardPacketArray[indexCount]->packetNumber;
                indexCount++;
                
            }
            if (indexCount < flowTable[index]->backwardPacketCount ) {
                indexBackward = indexCount;
            }else{
                indexBackward = flowTable[index]->backwardPacketCount + 2; //hic girmesin buna
            }
        }
    
        while (count < ThresholdOfPacketCount && (indexForward < flowTable[index]->forwardPacketCount) && (indexBackward < flowTable[index]->backwardPacketCount)) {
            if (allForwardPacketArray[indexForward]->ts.tv_sec != allBackwardPacketArray[indexBackward]->ts.tv_sec) {
                if (allForwardPacketArray[indexForward]->ts.tv_sec > allBackwardPacketArray[indexBackward]->ts.tv_sec) {
                    backwardPackets[i] = (Packet *)malloc(sizeof(Packet));
                    backwardPackets[i] = allBackwardPacketArray[indexBackward];
                    i++;
                    indexBackward++;
                }else{
                    forwardPackets[j] = (Packet *)malloc(sizeof(Packet));
                    forwardPackets[j] = allForwardPacketArray[indexForward];
                    j++;
                    indexForward++;
                }
            }
            else if (allForwardPacketArray[j]->ts.tv_usec > allBackwardPacketArray[i]->ts.tv_usec){
                backwardPackets[i] = (Packet *)malloc(sizeof(Packet));
                backwardPackets[i] = allBackwardPacketArray[indexBackward];
                i++;
                indexBackward++;
            }else{
                forwardPackets[j] = (Packet *)malloc(sizeof(Packet));
                forwardPackets[j] = allForwardPacketArray[indexForward];
                j++;
                indexForward++;
            }
            count++;
        }
        
        if (count < ThresholdOfPacketCount) {
            if (indexBackward < flowTable[index]->backwardPacketCount) {
                while (count < ThresholdOfPacketCount && (indexBackward < flowTable[index]->backwardPacketCount)) {
                    backwardPackets[i] = (Packet *)malloc(sizeof(Packet));
                    backwardPackets[i] = allBackwardPacketArray[indexBackward];
                    i++;
                    count++;
                    indexBackward++;
                }
            }else{
                while (count < ThresholdOfPacketCount && (indexForward < flowTable[index]->forwardPacketCount)) {
                    forwardPackets[j] = (Packet *)malloc(sizeof(Packet));
                    forwardPackets[j] = allForwardPacketArray[indexForward];
                    j++;
                    count++;
                    indexForward++;
                }
            }
        }
        
        
        //feature extraction for fixed packet count
        // for forward packets
        //printf("Packet Count: %d \n",flowTable[index]->packetCount);//debug
        int *densityArray = (int *)calloc(10, sizeof(int));
        densityArray = density(forwardPackets, j);
        int *binsOfBytesForward = (int *)calloc(10, sizeof(int));
        binsOfBytesForward = binsOfBytes(forwardPackets, j);
        FILE *arfFile;
        arfFile = fopen("fixedSize.txt","a");
        if (arfFile == NULL) {
            perror("fİLE ERROR");
        }
        isForward = 1;
        int protocol;
        if (flowTable[index]->backwardPacketCount != 0) {
            protocol = flowTable[index]->backwardPackets[0].ip_packet.ip_p;
        }else if(flowTable[index]->forwardPackets != 0){
            protocol = flowTable[index]->forwardPackets[0].ip_packet.ip_p;
        }
        fprintf(arfFile, "%d, %d, %f, %f, %f, %f, %f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d,%f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %f, %d, %d, %d, %d, %f,",
                j, //number of packets
                numberOfBytes(forwardPackets, j),
                (double)minPacketLength(forwardPackets,j)/MTU_SIZE,
                (double)maxPacketLength(forwardPackets,j)/MTU_SIZE,
                averagePacketLength(forwardPackets, j)/MTU_SIZE,
                standardDeviation(forwardPackets, j),
                minIntervalPacketTime(forwardPackets, j),
                maxIntervalPacketTime(forwardPackets, j),
                averageIntervalPacketTime(forwardPackets, j),
                standardDeviationOfIntervalPacketTime(forwardPackets, j),
                durationForFixedPackets(forwardPackets, j),
                protocol, //protocol
                densityArray[0],densityArray[1],densityArray[2],densityArray[3],densityArray[4],
                densityArray[5],densityArray[6],densityArray[7],densityArray[8],densityArray[9],
                numberOfBytesToPacketCount(numberOfBytes(forwardPackets, j), j),
                minIntervalvsPacketCount(minIntervalPacketTime(forwardPackets, j), j),
                maxIntervalvsPacketCount(maxIntervalPacketTime(forwardPackets, j), j),
                maxPacketSizeToStandardDeviation(maxPacketLength(forwardPackets, j), standardDeviation(forwardPackets, j)),
                averagePacketSizeToStandardDeviation(averagePacketLength(forwardPackets, j), standardDeviationOfIntervalPacketTime(forwardPackets, j)),
                totalNumberOfACKPackets(forwardPackets, j),
                totalNumberOfPUSHPackets(forwardPackets, j),
                binsOfBytesForward[0],binsOfBytesForward[1],binsOfBytesForward[2],binsOfBytesForward[3],binsOfBytesForward[4],
                binsOfBytesForward[5],binsOfBytesForward[6],binsOfBytesForward[7],binsOfBytesForward[8],binsOfBytesForward[9],
                totalNumberOfURGPackets(forwardPackets, j),
                totalNumberOfECEPackets(forwardPackets, j),
                totalNumberOfCWRPackets(forwardPackets, j),
                totalNumberOfRSTPackets(forwardPackets, j),
                totalNumberOfSYNPackets(forwardPackets, j),
                totalSizeOfURGPackets(forwardPackets, j),
                totalNumberOfPureACKPackets(forwardPackets, j),
                optionSetCount(forwardPackets, j),
                countOfActualDataPackets(forwardPackets, j),
                averageWindowSize(forwardPackets, j),
                zeroWindowCount(forwardPackets, j),
                minWindowSize(forwardPackets, j),
                maxWindowSize(forwardPackets, j),
                activeFlowCount(),
                averageInFlowRate(forwardPackets, j)
                );
        //totalNumberOfPureACKPackets(tempPacketArray, flowTable[index]->forwardPacketCount);
        // for backward packets
        isForward = 0;
        //Packet ** tempPacketArray2 = getFixedSizedPacketsFromFlow(index, 0);
        int *binsOfBytesBackward = (int *)calloc(10, sizeof(int));
        binsOfBytesBackward = binsOfBytes(backwardPackets, i);
        densityArray = density(backwardPackets, i);
        fprintf(arfFile, " %d, %d, %f, %f, %f, %f, %f, %f, %f, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %f, %f, %f, %f, %f,%d, %d, %d, %d, %d, %d,%d, %d, %d, %d, %d, %d, %f, %f, %d, %d, %d, %d, %d, %d, %d, %d, %d, %f, %d, %d, %d, %f, %f, %f, %f, %d, %s, %s\n",
                i, //number of packets
                numberOfBytes(backwardPackets, i),
                (double)minPacketLength(backwardPackets, i)/MTU_SIZE,
                (double)maxPacketLength(backwardPackets, i)/MTU_SIZE,
                averagePacketLength(backwardPackets, i)/MTU_SIZE,
                standardDeviation(backwardPackets, i),
                minIntervalPacketTime(backwardPackets, i),
                maxIntervalPacketTime(backwardPackets, i),
                averageIntervalPacketTime(backwardPackets, i),
                standardDeviationOfIntervalPacketTime(backwardPackets, i),
                durationForFixedPackets(backwardPackets, i),
                protocol, //protocol
                densityArray[0],densityArray[1],densityArray[2],densityArray[3],densityArray[4],
                densityArray[5],densityArray[6],densityArray[7],densityArray[8],densityArray[9],
                numberOfBytesToPacketCount(numberOfBytes(backwardPackets, i), i),
                minIntervalvsPacketCount(minIntervalPacketTime(backwardPackets, i), i),
                maxIntervalvsPacketCount(maxIntervalPacketTime(backwardPackets, i), i),
                maxPacketSizeToStandardDeviation(maxPacketLength(backwardPackets, i), standardDeviation(backwardPackets, i)),
                averagePacketSizeToStandardDeviation(averagePacketLength(backwardPackets, i), standardDeviationOfIntervalPacketTime(backwardPackets, i)),
                totalNumberOfACKPackets(backwardPackets, i),
                totalNumberOfPUSHPackets(backwardPackets, i),
                binsOfBytesBackward[0],binsOfBytesBackward[1],binsOfBytesBackward[2],binsOfBytesBackward[3],binsOfBytesBackward[4],
                binsOfBytesBackward[5],binsOfBytesBackward[6],binsOfBytesBackward[7],binsOfBytesBackward[8],binsOfBytesBackward[9],
                ratioOfForwardAndBackwardPacketCounts(j, i),
                ratioOfBytesFAndB(numberOfBytes(forwardPackets, j), numberOfBytes(backwardPackets, i)),
                totalNumberOfURGPackets(backwardPackets, i),
                totalNumberOfECEPackets(backwardPackets, i),
                totalNumberOfCWRPackets(backwardPackets, i),
                totalNumberOfRSTPackets(backwardPackets, i),
                totalNumberOfSYNPackets(backwardPackets, i),
                totalSizeOfURGPackets(backwardPackets, i),
                totalNumberOfPureACKPackets(backwardPackets, i),
                optionSetCount(backwardPackets, i),
                countOfActualDataPackets(backwardPackets, i),
                averageWindowSize(backwardPackets, i),
                zeroWindowCount(backwardPackets, i),
                minWindowSize(backwardPackets, i),
                maxWindowSize(backwardPackets, i),
                averageInFlowRate(backwardPackets, i),
                averageFlowRate(flowTable[index]),
                ratioOfAllPacketCounts(flowTable[index]),
                ratioOfOpenFlows(),
                flowCountForConnection(flowTable[index]),
                subClass,
                className
                );
        //totalNumberOfPureACKPackets(tempPacketArray2, flowTable[index]->backwardPacketCount);
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
        free(binsOfBytesForward);
        free(binsOfBytesBackward);
        
    }
    else{
        getFeaturesFromFlow(index);
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

int hashAndPlace (unsigned key, int tableSize, Packet * newPacket){
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
        flow->sourceIP = newPacket->ip_packet.ip_src.s_addr; //to assess forward and backward packets
        flow->firstPacket = *newPacket;
        flowTable[index] = flow;
        addToConnection(newPacket, index);
        flowCount++; //debug
        return index;
        
    }
    //tekrarlamisim sanki?
    else if (i!=index && flowTable[i] == NULL) { // mevcut hashtable index'i tamamen bos ise (dolayisiyla bu akisin ilk paketi oluyor) ve collusion varsa
        flow->key = key;
        flow->sourceIP = newPacket->ip_packet.ip_src.s_addr;
        flow->firstPacket = *newPacket;
        flowTable[i] = flow;
        addToConnection(newPacket, index);
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
            flowTable[index]->lastForwardPacket = packet; //yama
        }else{
            /* eski kod
            Packet *tempPacket = (Packet *)malloc(sizeof(Packet));
            tempPacket = flowTable[index]->forwardPackets; //forwardPackets'in ilk paketi
            while (tempPacket->nextPacket != NULL) {    //bu ilk paketten baslanarak listesinin sonuna kadar gidiliyor ve paket ekleniyor
                tempPacket = tempPacket->nextPacket;
            }
            tempPacket->nextPacket = packet;
             */
            flowTable[index]->lastForwardPacket->nextPacket = packet; //yama
            flowTable[index]->lastForwardPacket = packet; //yama
        }
    }else{ //for backward packets (forwardPackets ile aynı mantık)
        flowTable[index]->backwardPacketCount++;
        if (flowTable[index]->backwardPackets == NULL) {
            flowTable[index]->backwardPackets = packet;
            flowTable[index]->lastBackwardPacket = packet; //yama
        }else{
            /* eski kod
            Packet *tempPacket = (Packet *)malloc(sizeof(Packet));
            tempPacket = flowTable[index]->backwardPackets;
            while (tempPacket->nextPacket != NULL) {
                tempPacket = tempPacket->nextPacket;
            }
            tempPacket->nextPacket = packet;
             */
            flowTable[index]->lastBackwardPacket->nextPacket = packet; //yama
            flowTable[index]->lastBackwardPacket = packet; //yama
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

void allocConnectionTable(){
    connectionTable = (Connection **)malloc(sizeof(Connection)*HashSize);
    for (int i = 0; i<HashSize; i++) {
        connectionTable[i] = (Connection *)malloc(sizeof(Connection));
        connectionTable[i] = NULL;
    }
}

void deallocConnectionTable(){
    for (int i = 0; i<HashSize; i++) {
        
        if (connectionTable[i] != NULL) {
            connectionTable[i]->flowCount = NULL;
            connectionTable[i]->destIP = NULL;
            connectionTable[i]->sourceIP = NULL;
            connectionTable[i]->index = NULL;
            free(connectionTable[i]->indexNumbers);
            connectionTable[i]->indexNumbers = NULL;
        }
        
        free(connectionTable[i]);
        connectionTable[i] = NULL;
        
    }
    free(connectionTable);
    connectionTable = NULL;
}

void addToConnection(Packet *newPacket, int index){
    unsigned key;
    key = newPacket->ip_packet.ip_src.s_addr / 313;
    key += newPacket->ip_packet.ip_dst.s_addr / 313;
    int connectionIndex = key % HashSize;
    //Connection debugConnection = *connectionTable[connectionIndex];
        int found = 0;
        while (connectionTable[connectionIndex] != NULL && found == 0) {
            if ((connectionTable[connectionIndex]->sourceIP == newPacket->ip_packet.ip_src.s_addr && connectionTable[connectionIndex]->destIP == newPacket->ip_packet.ip_dst.s_addr) || (connectionTable[connectionIndex]->destIP == newPacket->ip_packet.ip_src.s_addr && connectionTable[connectionIndex]->sourceIP == newPacket->ip_packet.ip_dst.s_addr)){
                found = 1;
            }else{
                connectionIndex++;
            }
        }
        if (found) { //mevcut connection var ise
            connectionTable[connectionIndex]->flowCount++;
            connectionTable[connectionIndex]->indexNumbers[connectionTable[connectionIndex]->index] = index;
            connectionTable[connectionIndex]->index++;
        }else{ //null ise
            Connection *newConnection = (Connection *)malloc(sizeof(Connection));
            newConnection->sourceIP = newPacket->ip_packet.ip_src.s_addr;
            newConnection->destIP = newPacket->ip_packet.ip_dst.s_addr;
            newConnection->indexNumbers = calloc(100000, sizeof(int));
            newConnection->indexNumbers[0] = index;
            newConnection->index = 1; //bos gozu gosteriyor
            newConnection->flowCount = 1;
            connectionTable[connectionIndex] = newConnection;
        }
}
