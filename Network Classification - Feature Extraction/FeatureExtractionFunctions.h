//
//  FeatureExtractionFunctions.h
//  Network Classification - Feature Extraction
//
//  Created by Barış Yamansavaşçılar on 8.01.2015.
//  Copyright (c) 2015 Barış Yamansavaşçılar. All rights reserved.
//

#ifndef __Network_Classification___Feature_Extraction__FeatureExtractionFunctions__
#define __Network_Classification___Feature_Extraction__FeatureExtractionFunctions__

#include "Structs.h"
#include <limits.h>

int numberOfBytes(Packet *packetArray[],int size);
int minPacketLength(Packet *packetArray[],int size);
int maxPacketLength(Packet *packetArray[],int size);
double averagePacketLength(Packet *packetArray[],int size);
double standardDeviation(Packet *packetArray[],int size);
double minIntervalPacketTime(Packet *packetArray[],int size); //based on arrival time
double maxIntervalPacketTime(Packet *packetArray[],int size); //based on arrival time
double averageIntervalPacketTime(Packet *packetArray[],int size); //based on arrival time
double standardDeviationOfIntervalPacketTime(Packet *packetArray[],int size); //based on arrival time
double durationForFixedPackets(Packet *packetArray[],int size); //dogrulugundan emin olamadigim fonksiyon,maxPacketTime ve maxPacketTime kaynaklı

double numberOfBytesToPacketCount(double byteCount, double pcktCount);
double minIntervalvsPacketCount(double minInterval, double pcktCount);
double maxIntervalvsPacketCount(double maxInterval, double pcktCount);
double maxPacketSizeToStandardDeviation(double maxPacketSize, double stdDeviation);
double averagePacketSizeToStandardDeviation(double averagePacketSize, double stdDeviation);


double ratioOfForwardAndBackwardPacketCounts(int forwardPacketCount, int backwardPacketCount);
double ratioOfBytesFAndB(int packetLengthF, int packetLengthB);
int totalNumberOfACKPackets(Packet *packetArray[],int size);
int totalNumberOfPUSHPackets(Packet *packetArray[],int size);
int * binsOfBytes(Packet *packetArray[],int size);


/* After the Tcptrace */
int totalNumberOfURGPackets(Packet *packetArray[],int size);
int totalNumberOfECEPackets(Packet *packetArray[],int size);
int totalNumberOfCWRPackets(Packet *packetArray[],int size);
int totalNumberOfRSTPackets(Packet *packetArray[],int size);
int totalNumberOfSYNPackets(Packet *packetArray[],int size);
int totalSizeOfURGPackets(Packet *packetArray[],int size);
int totalNumberOfPureACKPackets(Packet *packetArray[],int size);
int optionSetCount(Packet *packetArray[],int size);
int countOfActualDataPackets(Packet *packetArray[],int size);
double averageWindowSize(Packet *packetArray[],int size);
int zeroWindowCount(Packet *packetArray[],int size);
int minWindowSize(Packet *packetArray[],int size);
int maxWindowSize(Packet *packetArray[],int size);

//flowBased
int activeFlowCount();
double averageInFlowRate(Packet *packetArray[],int size);
double averageFlowRate();
/* After the Tcptrace */

/*
 density: gecen zamani 10 esit parcaya bolerek her parcaya kac paket düstügünü hesaplayan fonksiyon
 ancak minPacketTime ve maxPacketTime fonksiyonlarının dogru oldugundan emin olamadigim(mantiksal olarak) icin
 duzgun calistigi konusunda suphelerim var
 */
int * density(Packet *packetArray[],int size);
//numberOfPackets = size
//protocol = inside the packet


#endif /* defined(__Network_Classification___Feature_Extraction__FeatureExtractionFunctions__) */
