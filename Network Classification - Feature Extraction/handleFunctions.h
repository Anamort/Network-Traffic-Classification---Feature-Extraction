//
//  handleFunctions.h
//  Network Classification - Feature Extraction
//
//  Created by Barış Yamansavaşçılar on 1.01.2015.
//  Copyright (c) 2015 Barış Yamansavaşçılar. All rights reserved.
//

#ifndef __Network_Classification___Feature_Extraction__handleFunctions__
#define __Network_Classification___Feature_Extraction__handleFunctions__

#include "Structs.h"
#define HashSize 10013
#define DEBUG 0
#define ThresholdOfPacketCount 80
#define TimeThreshold 1
#define isTimeBased 0
#define isFullFlow 1
#define isSubFlow 1
#define location 2 // 0 flow'Un baslangıcı, 1 ortasi, 2 sonu

u_int16_t handleEthernet (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);//alinan paketin hangi tipte oldugunu belirlemek icin (IP,ARP vb)

//IP paketini isleyen ve sonrasında sartlar uygunsa etiketli olarak dosyaya yazan fonksiyon
void handleIP (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);

// TCP protokolğndeki paketten key yaratan fonksiyon
unsigned calculateKeyTCP (struct ip ipPacket, struct tcphdr tcpHeader);

// UDP protokolğndeki paketten key yaratan fonksiyon
unsigned calculateKeyUDP (struct ip ipPacket, struct udphdr udpHeader);

// yeni gelen paketin hashtable'daki hangi flow'a ait oldugunu belirtip index'i donduren ve flow'u initilize edip hashtable'a yerlestiren fonksiyon
int hashAndPlace (unsigned key, int tableSize, Packet *);

//gelen paketin ileri ya da geri yonlu olduguna karar verilip ilgili flow'un linkli listesine (forward ya da backward) yerlestirilmesi
void addPacketToLinkedList (Packet *, int index);

//iki integer sayiyi double olarak (tamsayi1,tamsayi2) yendien duzenleyen fonksiyon. paketin second ve microsecond bilgisini tek bir sayı degeriyle
//belirtmek icin
double mergeIntegersToDecimal(long a, int b);

//flow icerisindeki ileri ya da geri yonlu paketleri cikartip dizi olarak donduren fonksiyon. Feature extraction islemleri bu donen dizinin elemanlari
//uzerinden yapiliyor
Packet ** getFixedSizedPacketsFromFlow (int index, int isForward);

//getFixedSizedPacketsFromFlow fonksiyonundan donen dizinin ozellikleri cikartildiktan sonra bu linkli listeyi silen ve hafizada yer acan fonksiyon
void deleteLinkedList (Packet **head);

//mevcut dosyadan altbasligi cikartan fonksiyon
char * extractSubclassName(char *pcapFile);

void addToConnection(Packet *newPacket, int index);

void getFeaturesFromFlow(int index);

void getSubFlowFromActualFlow(int index);

void allocFlowtable();
void deallocFlowtable();
void allocConnectionTable();
void deallocConnectionTable();
#endif /* defined(__Network_Classification___Feature_Extraction__handleFunctions__) */
