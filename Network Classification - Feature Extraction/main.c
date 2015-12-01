//
//  main.c
//  Network Classification - Feature Extraction
//
//  Created by Barış Yamansavaşçılar on 6.11.2014.
//  Copyright (c) 2014 Barış Yamansavaşçılar. All rights reserved.
//


#include "Structs.h"
#include "handleFunctions.h"



void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
                 packet)
{
    static int count = 1;
    //static int temp = 0;
    
    u_int16_t type = handleEthernet(args,pkthdr,packet);
    //printf("TYPE: %d, ETHERNET_IP: %d",ntohs (type),ETHERTYPE_IP);
    if(ntohs (type) == ETHERTYPE_IP)
    {/* handle IP packet */
        handleIP(args, pkthdr, packet);
    }else if(ntohs (type) == ETHERTYPE_ARP)
    {/* handle arp packet */
    }
    else if(ntohs (type) == ETHERTYPE_REVARP)
    {/* handle reverse arp packet */
    }/* ignorw */
    if(DEBUG){
        printf("Packet number: %d\n",count);
    }
    count++;
    
    
}

int main(int argc, const char * argv[]) {
   
    
    /*char *dev; */ //for real application
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    FILE *sshPcapFile;
    
    packetCount = 0;
    sampleCount = 0;
    flowCount = 0;
    isForward = 1;
    //beginning
    className = malloc(sizeof(char)*15);
    
    const char *folder[26];
    
    /************Crypttech verisi ****************/
    folder[0] = "CrypttechData/BruteForce/";
    folder[1] = "CrypttechData/CommandInjection/";
    folder[2] = "CrypttechData/DDos/";
    folder[3] = "CrypttechData/Dos/";
    
    folder[4] = "CrypttechData/Normal/";
    
    folder[5] = "CrypttechData/PortTaramaVeExploitation/";
    
    folder[6] = "CrypttechData/SQLInjection/";
    
    /************Crypttech verisi ****************/
    /*
    folder[0] = "SingleFlow/InstantMessaging/";
    folder[1] = "SingleFlow/Mail/";
    folder[2] = "SingleFlow/Music/";
    folder[3] = "SingleFlow/P2P/";
    
    folder[4] = "SingleFlow/SocialMedia/";
    
    folder[5] = "SingleFlow/Video/";
    
    folder[6] = "SingleFlow/WebBrowsing/";
    */
    DIR *dir;
    struct dirent *ent;
    
    for (int i=0; i<7; i++) {
        if (i==0) {
            //className = "InstantMessaging";
            className = "BruteForce";
        }else if (i==1){
            //className = "Mail";
            className = "CommandInjection";
        }else if (i==2){
            //className = "Music";
            className = "DDos";
        }else if (i==3){
            //className = "P2P";
            className = "Dos";
        }else if (i==4){
            //className = "SocialMedia";
            className = "Normal";
        }else if (i==5){
            //className = "VideoStream";
            className = "PortTaramaVeExploitation";
        }else if (i==6){
            //className = "WebBrowsing";
            className = "SQLInjection";
        }
        printf("Class Name: %s\n",className);
        
        if ((dir = opendir(folder[i])) != NULL) {
            while ((ent = readdir (dir)) != NULL) {
                if (strcmp(ent->d_name, ".")!=0 && strcmp(ent->d_name, "..")!=0 && strcmp(ent->d_name, ".DS_Store")!=0) {
                    //printf ("%s\n", ent->d_name);
                    subClass = extractSubclassName(ent->d_name);
                    printf("Reading subclass: %s\n",subClass);
                    char *absolutePath = (char *)calloc(100, sizeof(char));
                    strcat(absolutePath, folder[i]);
                    strcat(absolutePath, ent->d_name);
                    allocFlowtable();
                    allocConnectionTable();
                    printf("Absolute path: %s\n",absolutePath);
                    sshPcapFile = fopen(absolutePath, "r");
                    if (sshPcapFile == NULL) {
                        perror("Dosya okunmadi!");
                    }
                    printf("Reading...\n");
                    descr = pcap_fopen_offline(sshPcapFile, errbuf);
                    pcap_loop(descr, -1, my_callback, NULL);
                    fprintf(stdout,"\nfinished\n\n");
                    
                    
                    printf("Sample Count: %d\n\n",sampleCount);
                    //sampleCount = 0;
                    printf("Flow Count: %d\n\n",flowCount);
                    flowCount = 0;
                    packetCount = 0;
                    //hashTable sifirlanacak
                    deallocFlowtable();
                    deallocConnectionTable();
                    absolutePath = NULL;
                    free(absolutePath);
                    
                }
                
                
            }
            closedir (dir);
        }
    else {
        /* could not open directory */
        perror ("dkcmdcmskld");
        return EXIT_FAILURE;
    }

    }
    
    
    
    
    
    return 0;
}
