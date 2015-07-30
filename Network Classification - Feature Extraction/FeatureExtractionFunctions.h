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

/*
 density: gecen zamani 10 esit parcaya bolerek her parcaya kac paket düstügünü hesaplayan fonksiyon
 ancak minPacketTime ve maxPacketTime fonksiyonlarının dogru oldugundan emin olamadigim(mantiksal olarak) icin
 duzgun calistigi konusunda suphelerim var
 */
int * density(Packet *packetArray[],int size);
//numberOfPackets = size
//protocol = inside the packet


#endif /* defined(__Network_Classification___Feature_Extraction__FeatureExtractionFunctions__) */
