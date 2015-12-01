//
//  FeatureExtractionFunctions.c
//  Network Classification - Feature Extraction
//
//  Created by Barış Yamansavaşçılar on 8.01.2015.
//  Copyright (c) 2015 Barış Yamansavaşçılar. All rights reserved.
//

#include "FeatureExtractionFunctions.h"
#include "handleFunctions.h"


int numberOfBytes(Packet *packetArray[],int size){
    int count = 0;
    for (int i=0; i < size; i++) {
        count += packetArray[i]->len;
    }
    
    return count;
}

int minPacketLength(Packet *packetArray[],int size){
    if (size == 0) {
        return 0;
    }
    int minPacketSize = packetArray[0]->len;
    for (int i= 1; i < size; i++) {
        if (packetArray[i]->len < minPacketSize) {
            minPacketSize = packetArray[i]->len;
        }
    }
    return minPacketSize;
}

int maxPacketLength(Packet *packetArray[],int size){
    if (size == 0) {
        return 0;
    }
    int maxPacketSize = packetArray[0]->len;
    for (int i= 1; i < size; i++) {
        if (packetArray[i]->len > maxPacketSize) {
            maxPacketSize = packetArray[i]->len;
        }
    }
    return maxPacketSize;
}

double averagePacketLength(Packet *packetArray[],int size){
    double average = 0;
    if (size == 0) {
        return 0;
    }
    for (int i=0; i < size; i++) {
        average += (double)packetArray[i]->len;
    }
    
    average = average/(double)size;
    
    return average;
}

double standardDeviation(Packet *packetArray[],int size){
    double sDeviation = 0.0;
    if (size == 0) {
        return 0;
    }
    if (size == 1) {
        return 0;
    }
    
    double average = averagePacketLength(packetArray, size);
    for (int i=0; i<size; i++) {
        sDeviation += pow((packetArray[i]->len - average), 2);
    }
    sDeviation = sDeviation/(double)(size-1); //varyans
    sDeviation = sqrt(sDeviation);
    
    return sDeviation;
}

double minIntervalPacketTime(Packet *packetArray[],int size){
    double minInterval, temptInterval;
    if (size == 0 || size == 1) {
        return 0;
    }
    long double secondPacket = packetArray[1]->ts.tv_sec + (packetArray[1]->ts.tv_usec*pow(10.0, -6));
    long double firstPacket = packetArray[0]->ts.tv_sec + (packetArray[0]->ts.tv_usec*pow(10.0, -6));
    minInterval = secondPacket - firstPacket;
    if (!isForward) {
        //printf("%lf ",minInterval); //sonuc cikarma paper
    }
    
    for (int i=2; i<size; i++) {
        secondPacket = packetArray[i]->ts.tv_sec + (packetArray[i]->ts.tv_usec*pow(10.0, -6));
        firstPacket = packetArray[i-1]->ts.tv_sec + (packetArray[i-1]->ts.tv_usec*pow(10.0, -6));
        temptInterval = secondPacket - firstPacket;
        if (!isForward) {
           // printf("%lf ",temptInterval); //sonuc cikarma paper
        }
        
        if (temptInterval < minInterval) {
            minInterval = temptInterval;
        }
    }
    //printf("\n"); //sonuc cikarma paper
    return minInterval;
}

double maxIntervalPacketTime(Packet *packetArray[],int size){
    if (size == 0 || size == 1) {
        return 0;
    }
    double maxInterval, temptInterval;
    
    long double secondPacket = packetArray[1]->ts.tv_sec + (packetArray[1]->ts.tv_usec*pow(10.0, -6));
    long double firstPacket = packetArray[0]->ts.tv_sec + (packetArray[0]->ts.tv_usec*pow(10.0, -6));
    maxInterval = secondPacket - firstPacket;
    
    for (int i=2; i<size; i++) {
        secondPacket = packetArray[i]->ts.tv_sec + (packetArray[i]->ts.tv_usec*pow(10.0, -6));
        firstPacket = packetArray[i-1]->ts.tv_sec + (packetArray[i-1]->ts.tv_usec*pow(10.0, -6));
        temptInterval = secondPacket - firstPacket;
        if (temptInterval > maxInterval) {
            maxInterval = temptInterval;
        }
    }
    return maxInterval;
}

double averageIntervalPacketTime(Packet *packetArray[],int size){
    if (size == 0 || size == 1) {
        return 0;
    }
    double average=0.0;
    for (int i=0; i<size-1; i++) {
        long double firstPacket = packetArray[i]->ts.tv_sec + (packetArray[i]->ts.tv_usec*pow(10.0, -6));
        long double secondPacket = packetArray[i+1]->ts.tv_sec + (packetArray[i+1]->ts.tv_usec*pow(10.0, -6));
        average += (secondPacket - firstPacket);
    }
    average = average / size;
    return average;
}

double standardDeviationOfIntervalPacketTime(Packet *packetArray[],int size){
    if (size == 0 || size == 1) {
        return 0;
    }
    double sDeviation = 0.0;
    double average = averageIntervalPacketTime(packetArray, size);
    for (int i=0; i<size-1; i++) {
        long double firstPacket = packetArray[i]->ts.tv_sec + (packetArray[i]->ts.tv_usec*pow(10.0, -6));
        long double secondPacket = packetArray[i+1]->ts.tv_sec + (packetArray[i+1]->ts.tv_usec*pow(10.0, -6));
        sDeviation += pow(((secondPacket - firstPacket)- average),2);
    }
    sDeviation = sDeviation/(double)(size-1); //varyans
    sDeviation = sqrt(sDeviation);
    //printf("\n%lf\n\n",sDeviation);
    return sDeviation;
}

double durationForFixedPackets(Packet *packetArray[],int size){
    if (size == 0) {
        return 0;
    }
    double duration = 0.0;
    long double firstPacket = packetArray[0]->ts.tv_sec + (packetArray[0]->ts.tv_usec*pow(10.0, -6));
    long double secondPacket = packetArray[size-1]->ts.tv_sec + (packetArray[size-1]->ts.tv_usec*pow(10.0, -6));

    duration = secondPacket - firstPacket;
    return duration;
}

int * density(Packet *packetArray[],int size){
    int *density = calloc(10,sizeof(int));
    if (size == 0) {
        return density;
    } else if (size == 1){
        density[0] = 1;
        return density;
    }
    double passedTime;
    double duration;
    if (isTimeBased) {
        duration = TimeThreshold;
    }else{
        duration = durationForFixedPackets(packetArray, size);
    }
    if (duration == 0) {
        return density;
    }
    double threshold = duration/10.0;
    
    for (int i=0; i<size; i++) {
        long double packetTime = packetArray[i]->ts.tv_sec + (packetArray[i]->ts.tv_usec*pow(10.0, -6));
        long double firstPacket = packetArray[0]->ts.tv_sec + (packetArray[0]->ts.tv_usec*pow(10.0, -6));
        passedTime = packetTime - firstPacket;
        int index = (int)floor(passedTime / threshold);
        if (index>9) {
            index=9;
           // printf("bug");
        }
        if (index>10) {
            perror("Mistake");
        }
        density[index]+=1;
    }
    
    return density;
}

double numberOfBytesToPacketCount(double byteCount, double pcktCount){
    if (pcktCount != 0) {
        return byteCount / pcktCount;
    }else{
        return byteCount;
    }
    
}

double minIntervalvsPacketCount(double minInterval, double pcktCount){
    return minInterval * pcktCount;
}

double maxIntervalvsPacketCount(double maxInterval, double pcktCount){
    return maxInterval * pcktCount;
}

double maxPacketSizeToStandardDeviation(double maxPacketSize, double stdDeviation){
    if (stdDeviation != 0) {
        return maxPacketSize / stdDeviation;
    }else{
        return maxPacketSize;
    }

}

double averagePacketSizeToStandardDeviation(double averagePacketSize, double stdDeviation){
    if (stdDeviation != 0) {
        return averagePacketSize / stdDeviation;
    }else{
        return averagePacketSize;
    }
}

int totalNumberOfACKPackets(Packet *packetArray[],int size){
    int ackCount = 0;
    if (size) {
        if (packetArray[0]->isTCP) {
            
            int i;
            for (i = 0; i<size; i++) {
                if (packetArray[i]->tcp_Packet.th_flags  & TH_ACK){
                    ackCount++;
                }
            }
        }
    }
    
    return ackCount;
}

int totalNumberOfPUSHPackets(Packet *packetArray[],int size){
    int pushCount = 0;
    if (size) {
        if (packetArray[0]->isTCP) {
            int i;
            for (i = 0; i<size; i++) {
                if (packetArray[i]->tcp_Packet.th_flags  & TH_PUSH){
                    pushCount++;
                }
            }
        }
    }
    return pushCount;
}

double ratioOfForwardAndBackwardPacketCounts(int forwardPacketCount, int backwardPacketCount){
    if (backwardPacketCount == 0) {
        return forwardPacketCount;
    }else{
        return (double)forwardPacketCount / backwardPacketCount;
    }
    
}

double ratioOfBytesFAndB(int packetLengthF, int packetLengthB){
    if (packetLengthB == 0) {
        return packetLengthF;
    }else{
        return (double)packetLengthF / packetLengthB;
    }
    
}

int * binsOfBytes(Packet *packetArray[],int size){
    int *bins = calloc(10,sizeof(int));
    if (size) {
        int i;
        for (i=0; i<size; i++) {
            int section = packetArray[i]->len / 150;
            if (section > 9) {
                section = 9;
            }
            bins[section]++;
        }
    }
    return bins;
}


/* After the Tcptrace */
int totalNumberOfURGPackets(Packet *packetArray[],int size){
    int urgCount = 0;
    if (size) {
        if (packetArray[0]->isTCP) {
            int i;
            for (i = 0; i<size; i++) {
                if (packetArray[i]->tcp_Packet.th_flags  & TH_URG){
                    urgCount++;
                }
            }
        }
    }
    return urgCount;
}

int totalNumberOfECEPackets(Packet *packetArray[],int size){
    int eceCount = 0;
    if (size) {
        if (packetArray[0]->isTCP) {
            int i;
            for (i = 0; i<size; i++) {
                if (packetArray[i]->tcp_Packet.th_flags  & TH_ECE){
                    eceCount++;
                }
            }
        }
    }
    return eceCount;
}

int totalNumberOfCWRPackets(Packet *packetArray[],int size){
    int cwrCount = 0;
    if (size) {
        if (packetArray[0]->isTCP) {
            int i;
            for (i = 0; i<size; i++) {
                if (packetArray[i]->tcp_Packet.th_flags  & TH_CWR){
                    cwrCount++;
                }
            }
        }
    }
    return cwrCount;
}

int totalSizeOfURGPackets(Packet *packetArray[],int size){
    int urgSize = 0;
    if (size) {
        if (packetArray[0]->isTCP) {
            int i;
            for (i = 0; i<size; i++) {
                if (packetArray[i]->tcp_Packet.th_flags  & TH_URG){
                    urgSize += ntohs(packetArray[i]->ip_packet.ip_len);
                }
            }
        }
    }
    return urgSize;
}

int totalNumberOfRSTPackets(Packet *packetArray[],int size){
    int rstCount = 0;
    if (size) {
        if (packetArray[0]->isTCP) {
            int i;
            for (i = 0; i<size; i++) {
                if (packetArray[i]->tcp_Packet.th_flags  & TH_RST){
                    rstCount++;
                }
            }
        }
    }
    return rstCount;
}

int totalNumberOfSYNPackets(Packet *packetArray[],int size){
    int synCount = 0;
    if (size) {
        if (packetArray[0]->isTCP) {
            int i;
            for (i = 0; i<size; i++) {
                if (packetArray[i]->tcp_Packet.th_flags  & TH_SYN){
                    synCount++;
                }
            }
        }
    }
    return synCount;
}

int totalNumberOfPureACKPackets(Packet *packetArray[],int size){
    int pureACKcount = 0;
    if (size && packetArray[0]->isTCP) {
        int i;
        for (i=0; i < size; i++) {
            int tcpHeaderSize = packetArray[i]->tcp_Packet.th_off*4;
            int ipLength = ntohs(packetArray[i]->ip_packet.ip_len);
            int ipHeaderLength = packetArray[i]->ip_packet.ip_hl*4;
            int tcpPayloadsize = ipLength - ipHeaderLength - tcpHeaderSize;
            if (!tcpPayloadsize) {
                if ((packetArray[i]->tcp_Packet.th_flags  & TH_SYN) || (packetArray[i]->tcp_Packet.th_flags  & TH_FIN) || (packetArray[i]->tcp_Packet.th_flags  & TH_RST) == 0){
                    pureACKcount++;
                }
            }
        }
    }
    return pureACKcount;
}

int optionSetCount(Packet *packetArray[],int size){
    int optionCount = 0;
    if (size && packetArray[0]->isTCP) {
        int i;
        for (i=0; i < size; i++) {
            int tcpHeaderSize = packetArray[i]->tcp_Packet.th_off*4;
            if (tcpHeaderSize > 20) {
                optionCount++;
            }
        }
    }
    return optionCount;
}

int countOfActualDataPackets(Packet *packetArray[],int size){
    int actualDataPackets = 0;
    if (size && packetArray[0]->isTCP) {
        int i;
        for (i=0; i < size; i++) {
            int tcpHeaderSize = packetArray[i]->tcp_Packet.th_off*4;
            int ipLength = ntohs(packetArray[i]->ip_packet.ip_len);
            int ipHeaderLength = packetArray[i]->ip_packet.ip_hl*4;
            int tcpPayloadsize = ipLength - ipHeaderLength - tcpHeaderSize;
            if (tcpPayloadsize > 0) {
                actualDataPackets++;
            }
        }
    }
    return actualDataPackets;
}

double averageWindowSize(Packet *packetArray[],int size){
    double windowSize = 0;
    if (size && packetArray[0]->isTCP) {
        int i;
        for (i=0; i < size; i++) {
            windowSize += ntohs(packetArray[i]->tcp_Packet.th_win);
            }
        }
    return windowSize;
}

int zeroWindowCount(Packet *packetArray[],int size){
    double zeroWindowCount = 0;
    if (size && packetArray[0]->isTCP) {
        int i;
        for (i=0; i < size; i++) {
            if (ntohs(packetArray[i]->tcp_Packet.th_win) == 0) {
                zeroWindowCount++;
            }
        }
    }
    return zeroWindowCount;
}

int minWindowSize(Packet *packetArray[],int size){
    int minWindowSize;
    if (size && packetArray[0]->isTCP) {
        minWindowSize = ntohs(packetArray[0]->tcp_Packet.th_win);
        int i;
        for (i=1; i < size; i++) {
            if (ntohs(packetArray[i]->tcp_Packet.th_win) < minWindowSize) {
                minWindowSize = ntohs(packetArray[i]->tcp_Packet.th_win);
            }
        }
        return minWindowSize;
    } else{
        return 0; //udp packet
    }
}

int maxWindowSize(Packet *packetArray[],int size){
    int maxWindowSize;
    if (size && packetArray[0]->isTCP) {
        maxWindowSize = ntohs(packetArray[0]->tcp_Packet.th_win);
        int i;
        for (i=1; i < size; i++) {
            if (ntohs(packetArray[i]->tcp_Packet.th_win) > maxWindowSize) {
                maxWindowSize = ntohs(packetArray[i]->tcp_Packet.th_win);
            }
        }
        return maxWindowSize;
    } else{
        return 0; //udp packet
    }
}

int activeFlowCount(){
    return flowCount;
}

double averageInFlowRate(Packet *packetArray[],int size){
    if (size) {
        return (numberOfBytes(packetArray, size) / durationForFixedPackets(packetArray, size));
    }else{
        return 0;
    }
    
}

double averageFlowRate(Flow *flow){
    double flowRate;
    double elapsedTime = 0.0;
    long double firstPacket = flow->firstPacket.ts.tv_sec + (flow->firstPacket.ts.tv_usec*pow(10.0, -6));
    long double secondPacket = flow->lastPacket.ts.tv_sec + (flow->lastPacket.ts.tv_usec*pow(10.0, -6));
    
    elapsedTime = secondPacket - firstPacket;
    flowRate = flow->allByteSize / elapsedTime;
    
    return flowRate;
}

double ratioOfAllPacketCounts(Flow *flow){
    double ratio;
    
    double elapsedTime = 0.0;
    long double firstPacket = flow->firstPacket.ts.tv_sec + (flow->firstPacket.ts.tv_usec*pow(10.0, -6));
    long double secondPacket = flow->lastPacket.ts.tv_sec + (flow->lastPacket.ts.tv_usec*pow(10.0, -6));
    
    elapsedTime = secondPacket - firstPacket;
    
    ratio = flow->allPacketsCount / elapsedTime;
    
    return ratio;
}

double ratioOfOpenFlows(){
    double ratio;
    
    double elapsedTime = 0.0;
    long double firstPacket = veryFirstPacket.ts.tv_sec + (veryFirstPacket.ts.tv_usec*pow(10.0, -6));
    long double secondPacket = veryLastPacket.ts.tv_sec + (veryLastPacket.ts.tv_usec*pow(10.0, -6));
    
    elapsedTime = secondPacket - firstPacket;
    ratio = flowCount / elapsedTime;
    
    return ratio;
}

int flowCountForConnection(Flow *flow){
    unsigned key;
    key = flow->sourceIP / 313;
    key += flow->firstPacket.ip_packet.ip_dst.s_addr / 313;
    int connectionIndex = key % HashSize;
    int found = 0;
    while (connectionTable[connectionIndex] != NULL && found == 0) {
        if ((connectionTable[connectionIndex]->sourceIP == flow->sourceIP && connectionTable[connectionIndex]->destIP == flow->firstPacket.ip_packet.ip_dst.s_addr) || (connectionTable[connectionIndex]->destIP == flow->sourceIP && connectionTable[connectionIndex]->sourceIP == flow->firstPacket.ip_packet.ip_dst.s_addr)){
            found = 1;
        }else{
            connectionIndex++;
        }
    }
    if (!found) {
        perror("olmamali");
    }
    
    return connectionTable[connectionIndex]->flowCount;
}
/* After the Tcptrace */
