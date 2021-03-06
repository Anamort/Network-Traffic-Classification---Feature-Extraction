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

double maxPacketTime (Packet *packetArray[],int size){
    if (size == 0) {
        return 0;
    }
    double max;
    int secondsInterval, microSecondsInterval;
    if (packetArray[0]->ts.tv_sec >= INT_MIN && packetArray[0]->ts.tv_sec <= INT_MAX) {
        secondsInterval = (int)packetArray[0]->ts.tv_sec;
    }else{
        printf("Undefined condition\n");
        perror("Undefined condition\n");
    }
    microSecondsInterval = packetArray[0]->ts.tv_usec;
    max = mergeIntegersToDecimal(secondsInterval, microSecondsInterval);
    
    for (int i=1; i<size; i++) {
        if (packetArray[i]->ts.tv_sec >= INT_MIN && packetArray[i]->ts.tv_sec <= INT_MAX) {
            secondsInterval = (int)packetArray[i]->ts.tv_sec;
        }else{
            printf("Undefined condition\n");
            perror("Undefined condition\n");
        }
        microSecondsInterval = packetArray[i]->ts.tv_usec;
        double tempt = mergeIntegersToDecimal(secondsInterval, microSecondsInterval);
        if (tempt>max) {
            max = tempt;
        }
    }
    return max;
}

double minPacketTime (Packet *packetArray[],int size){
    if (size == 0) {
        return 0;
    }
    double min;
    int secondsInterval, microSecondsInterval;
    if (packetArray[0]->ts.tv_sec >= INT_MIN && packetArray[0]->ts.tv_sec <= INT_MAX) {
        secondsInterval = (int)packetArray[0]->ts.tv_sec;
    }else{
        printf("Undefined condition\n");
        perror("Undefined condition\n");
    }
    microSecondsInterval = packetArray[0]->ts.tv_usec;
    min = mergeIntegersToDecimal(secondsInterval, microSecondsInterval);
    
    for (int i=1; i<size; i++) {
        if (packetArray[i]->ts.tv_sec >= INT_MIN && packetArray[i]->ts.tv_sec <= INT_MAX) {
            secondsInterval = (int)packetArray[i]->ts.tv_sec;
        }else{
            printf("Undefined condition\n");
            perror("Undefined condition\n");
        }
        microSecondsInterval = packetArray[i]->ts.tv_usec;
        double tempt = mergeIntegersToDecimal(secondsInterval, microSecondsInterval);
        if (tempt<min) {
            min = tempt;
        }
    }
    
    
    return min;
}