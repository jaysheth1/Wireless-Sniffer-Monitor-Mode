


#define APP_NAME		"Packet sniffer"
#define APP_DESC		"Description : This C program captures the packet in the monitor mode, and provides the count of each type of packet sniffed."
#define APP_COPYRIGHT		"Author : Jay Sheth, SIOTLAB, Santa Clara University"
#define APP_DISCLAIMER		"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <netinet/in.h>
#include <time.h>
#define SNAP_LEN 65535


struct radiotap_header { //only first few bytes
	uint8_t it_rev;
	uint8_t it_pad;
	uint16_t it_len;
};


struct bsslist {
  u_char *bssid;
  long t;
  struct bsslist *next;
};


/* Global Variables */
pcap_t *capturehandle; /* packet capture handle */
struct bpf_program fp;	/* compiled filter program (expression) */
pcap_dumper_t *pcapfile;   /* output file */
pcap_t *filehandle;   /* output file handle */
char *filename = NULL; /* output file name */
struct bsslist *blist = NULL; /* list of beacons */
int pcaptype = -1;
int beacons = 0;
int eapols = 0;
int data = 0;
int probereq =0;
int proberes =0;
int nullp =0;
int ack =0;
int qosdata =0;
int cts =0;
int rts =0;

int areq =0;
int ares =0;
int auth =0;
int qosnull = 0;


void print_app_usage(char *app_name) {
	printf("Usage: %s interface [-o output_file]\n", app_name);
	printf("\n");
	return;
}


/**
 * Returns the current time in microseconds.
 */
long getMicrotime(){
	long m ;
	struct timeval currentTime;
	gettimeofday(&currentTime, NULL);
	m = currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;
	//printf("current time :: %ld\n", m);
	return currentTime.tv_sec * (int)1e6 + currentTime.tv_usec;
}


struct bsslist *is_in_list(struct bsslist *bsl, const u_char *bssid) {
	long time_sincelastbeacon ;
	long t1;

  while (bsl != NULL) {
    if (! memcmp(bsl->bssid, bssid, 6)) 
    	{ 
    		t1 = getMicrotime();
    		time_sincelastbeacon = t1- bsl->t;
    		printf("delay since the last beacon : %ld \n", time_sincelastbeacon);
    		bsl->t = getMicrotime();
  			//double time_sincelastbeacon = ((double)bsl->t )/CLOCKS_PER_SEC;
			//printf("delay since the last beacon : %f \n", time_sincelastbeacon);
    		//getMicrotime();
    		return bsl; 
    	}
    bsl = bsl->next;
  }
  
  return NULL;
}


struct bsslist *add_to_list(struct bsslist *bsl, const u_char *bssid) {
  struct bsslist *new, *search;
  
  new = malloc(sizeof(struct bsslist));
  new->bssid = malloc(6);
   new->t - clock();
  memcpy(new->bssid, bssid, 6);
  new->next = NULL;

  if (bsl == NULL) { return new; }
  else {
    search = bsl;
    while (search->next) { search = search->next; }
    search->next = new;
    return bsl;
  }
}


void free_bsslist(struct bsslist *bsl) {
  if (! bsl) return;
  
  if (bsl->next) free_bsslist(bsl->next);
  
  free(bsl->bssid);
  free(bsl);
}


void terminate_process(int signum) {
	printf("\nCapture complete.\n\nOther packets: %d\nBeacon packets: %d \nData packets: %d \nQos data packets: %d \nQos NULL data packets: %d \nNULL packets: %d \nCTS packets: %d \nRTS packets: %d \nACK packets: %d \nProbe Req. packets: %d\nProbe Res. packets: %d\nAssociation Req: %d \nAssociation Response: %d \nAuthentication: %d \n\n\n", eapols, beacons, data, qosdata,qosnull, nullp,cts, rts, ack, probereq, proberes, areq, ares, auth);

	pcap_breakloop(capturehandle);
	pcap_close(capturehandle);
	pcap_freecode(&fp);
	pcap_dump_close(pcapfile);
	pcap_close(filehandle);
	free_bsslist(blist);
	
	exit(signum);
} 


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	const u_char *bssid;
	int offset = 0;
	struct radiotap_header *rtaphdr;
	
	/* determine offset based on link type*/
	switch (pcaptype) {
		case DLT_PRISM_HEADER:
			offset = 144;
			break;
		case DLT_IEEE802_11:
			offset = 0;
			break;
		case DLT_IEEE802_11_RADIO:
			rtaphdr = (struct radiotap_header *) packet;
			offset = rtaphdr->it_len;
            
            //----------------------------------------Printing RSSI channel and data radio, basically parsing radiotap header
            // These are placeholders for offset values:
            const u_char *bssid; // a place to put our BSSID \ these are bytes
            const u_char *essid; // a place to put our ESSID / from the packet
            const u_char *essidLen;
            const u_char *channel; // the frequency (in Mhz) of the AP Radio
            const u_char *rssi; // received signal strength
            const u_char *data_rate; // received signal strength
            
            int offset = 0;
            
            offset = rtaphdr->it_len; // 26 bytes on my machine
            
            bssid = packet + 42;
            essid = packet + 64;
            essidLen = packet + 63;
            rssi = packet + 34;
            signed int rssiDbm = rssi[0] - 256;
            data_rate = packet + 25;
            channel = packet + 26;
            int channelFreq = channel[1] * 256 + channel[0];
            char *ssid = malloc(63);
            unsigned int i = 0;
            int dataratedec = data_rate[0];
            ssid[i] = '\0'; // terminate the string
            fprintf(stdout,"RSSI: %d dBm",rssiDbm);
            fprintf(stdout,"    AP Frequency: %iMhz",channelFreq);
            fprintf(stdout,"    Data RAte: %dMhz\n", dataratedec/2);
            

            
            
            
            //-------------parsing radiotap header end
			break;
		default:
			fprintf(stderr, "Error: Unrecognized data link type: %d\n", pcaptype);
			return;
	}
	// if( (packet[offset] != 0x80) ) { 
	// 	printf(" * Packet captured ..............................................(%10X)\n", packet[offset]);
	// }

	//printf(" * Packet captured (%02X)\n", packet[offset]);
	// printf(" * Beacon captured ........\n");
	/* verify packet and save to output */
	


	if( (packet[offset] == 0x80) ) 
	{ // beacon frame
		bssid = packet + offset + 10;
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
		//	printf(" * Beacon captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
		//	blist = add_to_list(blist, bssid);


		if (is_in_list(blist, bssid) ) 
		{
			printf(" * Beacon captured (%02X:%02X:%02X:%02X:%02X:%02X) ", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
		}
		else
		{
			blist = add_to_list(blist, bssid);
			//bsslist->t = clock();
		}
		
			beacons += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	} 

	else if( (packet[offset] == 0x00) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * Association Request Captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist\n = add_to_list(blist, bssid);
			areq += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	
	else if( (packet[offset] == 0x10) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * Association Respose captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist = add_to_list(blist, bssid);
			ares += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	
	else if( (packet[offset] == 0xB0) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * Authentication Packet captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist = add_to_list(blist, bssid);
			auth += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	







	else if( (packet[offset] == 0x08) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * Data Packet captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist = add_to_list(blist, bssid);
			data += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	
		else if( (packet[offset] == 0x40) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * Probe Request captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist = add_to_list(blist, bssid);
			probereq += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	
		else if( (packet[offset] == 0x50) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * Probe Response captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist = add_to_list(blist, bssid);
			proberes += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	
		else if( (packet[offset] == 0x48) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * Null Packet captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist = add_to_list(blist, bssid);
			nullp += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	
		else if( (packet[offset] == 0xd4) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * ACK captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist = add_to_list(blist, bssid);
			ack += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	
		else if( (packet[offset] == 0x88) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * QoS Data Packet captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist = add_to_list(blist, bssid);
			qosdata += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	
		else if( (packet[offset] == 0xc4) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * CTS captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist = add_to_list(blist, bssid);
			cts += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	
		else if( (packet[offset] == 0xb4) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * RTS captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist = add_to_list(blist, bssid);
			rts += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	
		else if( (packet[offset] == 0x08) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * Data Packet captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist = add_to_list(blist, bssid);
			data += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	
			else if( (packet[offset] == 0xC8) ) 
	{
		bssid = packet + offset + 10; //remeber to tally the offset.
		//if ( !is_in_list(blist, bssid) ) { // not previously stored
			printf(" * QoS NULL Packet captured (%02X:%02X:%02X:%02X:%02X:%02X)\n", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			//blist = add_to_list(blist, bssid);
			qosnull += 1;
			pcap_dump((u_char *) pcapfile, header, packet);
		//}
	}	
	else { // eapol, multiple can be stored. Might be useful if channel hoping
		
			int type = packet[offset];
		
		printf("TYPE IN HEX :: %d\n", type);

		bssid = packet + offset + 4;
		//printf(" * Type: Unknown- packet captured (%02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X)\n"), 
		//			bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
		//			bssid[6], bssid[7], bssid[8], bssid[9], bssid[10], bssid[11] );
		eapols += 1;
		pcap_dump((u_char *) pcapfile, header, packet);
	}
	
	return;
}


int main(int argc, char **argv)
{
	char *dev = NULL;   /* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];   /* error buffer */
	char filter_exp[1000] = "(type data) or (subtype beacon)";//" or (ether proto 0x888e) or ip";  /* default filter expression - only get beacon and handshakes */
	struct bsslist *target = NULL;
	printf("-------------------------------------------------------------------------------------------------------------- \n");
	printf("%s\n", APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	//printf("%s\n", APP_DISCLAIMER);
	//printf("\n");
	char *filename = NULL; /* output file name */
printf("-------------------------------------------------------------------------------------------------------------- \n\n\n");
	// argv[1] = device name
	// option -f -> capture filter, default "(type data) or (subtype beacon)" 
	// option -o -> capture file name, default "test.pcap"
printf("-------------------------------------------------------------------------------------------------------------- \n");

	/* check for capture device name on command-line */
        if (argc >= 2) {
		int i, n;
		char s[2];
		dev = argv[1];
		filename = "test.pcap"; // default output name
		
		for( i = 2; i < argc; i++ ) {
			 
			if( strcmp(argv[i], "-o") == 0  && argv[i+1] ){
				filename = argv[++i];    
			         
			} else if( strcmp(argv[i], "-t") == 0 && argv[i+1] ){
			         
				target = malloc(sizeof(struct bsslist));
				target->bssid = malloc(6);
				target->next = NULL;

				n = sscanf(argv[++i], "%02x%[.:-]%02x%[.:-]%02x%[.:-]%02x%[.:-]%02x%[.:-]%02x",
								(unsigned int*)&target->bssid[0], s, (unsigned int*)&target->bssid[1], s,
								(unsigned int*)&target->bssid[2], s, (unsigned int*)&target->bssid[3], s,
								(unsigned int*)&target->bssid[4], s, (unsigned int*)&target->bssid[5]);
				if (n != 11) {
					fprintf(stderr, "Error: unable to parse MAC address (ex. 01:23:45:67:89:ab)\n\n");
					exit(EXIT_FAILURE);
				}
        
			}else if( strcmp(argv[i], "-f") == 0 && argv[i+1] )
			{
				//size_t destination_size = sizeof(argv[++i]);
				strcpy(filter_exp, argv[++i]);
				//filter_exp[destination_size - 1] = '\0';
				printf("Filter Expression = %s \n", filter_exp);
				
			} 
			else {
			 	fprintf(stderr, "Error: unrecognized command-line options\n\n");
				print_app_usage(argv[0]);
				exit(EXIT_FAILURE);
			}
		}
        } else {
		fprintf(stderr, "Error: unrecognized command-line options\n\n");
		print_app_usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	
	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Output file: %s\n", filename);
	
	/* configure targeted capture */
	if( target ) {
        	printf("Target BSSID: %02x:%02x:%02x:%02x:%02x:%02x\n",
					target->bssid[0], target->bssid[1],
					target->bssid[2], target->bssid[3],
					target->bssid[4], target->bssid[5] );
		sprintf(filter_exp, "ether host %02x:%02x:%02x:%02x:%02x:%02x and ( (subtype beacon) or (ether proto 0x888e) )",
					target->bssid[0], target->bssid[1],
					target->bssid[2], target->bssid[3],
					target->bssid[4], target->bssid[5] );	
	} else {
		//printf("Target BSSID: All stations\n");
	}
	
	//printf("Capture filter: %s\n", filter_exp);
	
	/* open capture device */
	if ((capturehandle = pcap_open_live(dev, SNAP_LEN, 1, -1, errbuf)) == NULL) {
		fprintf(stderr, "\nError: unable to open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* determine link type */
	pcaptype = pcap_datalink(capturehandle);
	
	/* make sure we're capturing on an wireless device */
	if (pcaptype == DLT_IEEE802_11) {
		printf("Data Link Type: DLT_IEEE802_11\n");
		filehandle = pcap_open_dead(DLT_IEEE802_11, BUFSIZ);
	} else if (pcaptype == DLT_PRISM_HEADER) {
		printf("Data Link Type: DLT_PRISM_HEADER (Experimental - not tested!)\n");
		filehandle = pcap_open_dead(DLT_PRISM_HEADER, BUFSIZ);
	} else if (pcaptype == DLT_IEEE802_11_RADIO) {
		printf("Data Link Type: DLT_IEEE802_11_RADIO\n");
		filehandle = pcap_open_dead(DLT_IEEE802_11_RADIO, BUFSIZ);
	} else {
		fprintf(stderr, "\nError: %s is not a supported wireless device.\n", dev);
		exit(EXIT_FAILURE);
	}
printf("-------------------------------------------------------------------------------------------------------------- \n\n\n");
	printf("\n");
	
	/* open output file */
	if ((pcapfile = pcap_dump_open(filehandle, filename)) == NULL) {
		fprintf(stderr, "Error: unable to open file %s: %s\n", filename, pcap_geterr(filehandle));
		exit(EXIT_FAILURE);
    	}
	
	/* compile the filter expression */
	if (pcap_compile(capturehandle, &fp, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Error: unable to parse filter %s: %s\n", filter_exp, pcap_geterr(capturehandle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(capturehandle, &fp) == -1) {
		fprintf(stderr, "Error: unable to install filter %s: %s\n", filter_exp, pcap_geterr(capturehandle));
		exit(EXIT_FAILURE);
	}

	/* sniff until user terminates */
	signal(SIGINT, terminate_process);
	
	printf("Sniffing in progress...\n");
	
	/* start sniffing */
	pcap_loop(capturehandle, -1, got_packet, NULL);

   return EXIT_SUCCESS;
}
