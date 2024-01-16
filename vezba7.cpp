#ifdef _MSC_VER
	#define _CRT_SECURE_NO_WARNINGS
#endif

// Include libraries
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "pcap.h"
#include "conio.h"

// Function declarations
void print_interface(pcap_if_t* dev);
char* convert_sockaddr_to_string(struct sockaddr* addr);


int main()
{
	pcap_if_t* devices;					// List of network interface controllers
	pcap_if_t* device;					// Network interface controller
	char errorMsg[PCAP_ERRBUF_SIZE + 1];	// Error buffer

	/* Retrieve the device list */
	if (pcap_findalldevs(&devices, errorMsg) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", errorMsg);
		return -1;
	}

	/* Print all available network interfaces */
	for (device = devices; device; device = device->next)
	{
		/* Print all the available information on the given interface */
		print_interface(device);
	}

	/* Free the device list */
	pcap_freealldevs(devices);


	// For demonstration purpose
	printf("\nPress any key to exit: ");
	_getch();

	return 0;
}


void print_interface(pcap_if_t* dev)
{
	pcap_addr_t* addr;

	printf("\n\t ============================= Interface ====================================\n\n");

	/* Name */
	printf("\t Name: \t\t %s\n", dev->name);

	/* Description */
	if (dev->description)
		printf("\t Description: \t %s\n", dev->description);

	/* Loopback Address*/
	printf("\t Loopback: \t %s\n", (dev->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

	/* IP addresses */
	for (addr = dev->addresses; addr; addr = addr->next)
	{
		printf("\n\t ADDRESS\n");

		switch (addr->addr->sa_family)
		{
		case AF_INET:

			printf("\t # Address Type: \t IPv4\n");

			if (addr->addr)
				printf("\t # Address: \t\t %s\n", convert_sockaddr_to_string(addr->addr));

			if (addr->netmask)
				printf("\t # Subnet mask: \t %s\n", convert_sockaddr_to_string(addr->netmask));

			if (addr->broadaddr)
				printf("\t # Broadcast Address: \t %s\n", convert_sockaddr_to_string(addr->broadaddr));

			break;

		case AF_INET6:
			printf("\t # Address Type: \t IPv6\n");
			break;

		default:
			printf("\t # Address Type: \t Other\n");
			break;
		}
	}
}

char* convert_sockaddr_to_string(struct sockaddr* address)
{
	return inet_ntoa(((struct sockaddr_in*)address)->sin_addr);
}
//----------------------------------------------------------V7-------



int packet_counter = 0;	// numerates each packet

// Function declarations
pcap_if_t* select_device(pcap_if_t* devices);
void packet_handler(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);

int main1()
{
	pcap_if_t* devices;						// List of network interface controllers
	pcap_if_t* device;						// Network interface controller
	pcap_t* device_handle;					// Descriptor of capture device
	char error_buffer[PCAP_ERRBUF_SIZE];	// Error buffer

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	// Chose one device from the list
	device = select_device(devices);

	// Check if device is valid
	if (device == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}

	// Open the capture device
	if ((device_handle = pcap_open_live(device->name,		// name of the device
		65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
		1,							// promiscuous mode
		500,							// read timeout
		error_buffer					// buffer where error message is stored
	)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by WinPcap\n", device->name);
		pcap_freealldevs(devices);
		return -1;
	}

	// TODO 1
	// Set expression for filtering in order to capture only packets which satisfy filter expression
	unsigned int netmask;
	char filter_exp[] = "ip dst host 192.168.1.100 and tcp";  //remark: use ipconfig to get ip address of host running the program
	struct bpf_program fcode;

	if (device->addresses != NULL)
		// Retrieve the mask of the first address of the interface 
		netmask = ((struct sockaddr_in*)(device->addresses->netmask))->sin_addr.s_addr;
	else
		// If the interface is without an address, we suppose to be in a C class network 
		netmask = 0xffffff;

	// Compile the filter
	if (pcap_compile(device_handle, &fcode, filter_exp, 1, netmask) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// Set the filter
	if (pcap_setfilter(device_handle, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}

	printf("\nListening on %s...\n", device->description);

	// At this point, we don't need any more the device list. Free it 
	pcap_freealldevs(devices);

	// Start the capture
	pcap_loop(device_handle, 0, packet_handler, NULL);

	return 0;
}

// This function provide possibility to chose device from the list of available devices
pcap_if_t* select_device(pcap_if_t* devices)
{
	int i = 0;	// Count devices and provide jumping to the selected device 
	pcap_if_t* device;

	// Print the list
	for (device = devices; device; device = device->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return NULL;
	}

	// Pick one device from the list
	int device_number;
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &device_number);

	if (device_number < 1 || device_number > i)
	{
		printf("\nInterface number out of range.\n");
		return NULL;
	}

	// Jump to the selected device
	for (device = devices, i = 0; i < device_number - 1; device = device->next, i++);

	return device;
}

// Callback function invoked by WinPcap for every incoming packet
void packet_handler(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	// Print timestamp and length of the packet
	time_t timestamp;			// Raw time (bits) when packet is received 
	struct tm* local_time;		// Local time when packet is received
	char time_string[16];		// Local time converted to string

	// Convert the timestamp to readable format
	timestamp = packet_header->ts.tv_sec;
	local_time = localtime(&timestamp);
	strftime(time_string, sizeof time_string, "%H:%M:%S", local_time);

	printf("\n-------------------------------------------");
	printf("\nPacket (%d): %s, %d byte\n", ++packet_counter, time_string, packet_header->len);


	// TODO 2: print content of each packet
	for (int i = 0; i < packet_header->len; i++)
	{
		// Print each byte with two hexadecimal number
		printf("%.2x ", packet_data[i]);

		// 32 bytes per line
		if ((i + 1) % 32 == 0)
			printf("\n");
	}

}

//---------------------------------------------------------V8-------------------------------------
pcap_if_t* select_device(pcap_if_t* devices);
void print_raw_data(unsigned char* data, int data_length);

// Print packet headers
void print_winpcap_header(const struct pcap_pkthdr* packet_header, int packet_counter);
void print_ethernet_header(ethernet_header* eh);
void print_ip_header(ip_header* ih);
void print_icmp_header(icmp_header* icmph);
void print_udp_header(udp_header* uh);
void print_application_data(unsigned char* data, long data_length);


int main2()
{
	pcap_if_t* devices;
	pcap_if_t* device;
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	// Chose one device from the list
	device = select_device(devices);

	// Check if device is valid
	if (device == NULL)
	{
		pcap_freealldevs(devices);
		return -1;
	}

	// Open the capture device
	if ((device_handle = pcap_open_live(device->name,		// name of the device
		65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
		1,							// promiscuous mode
		500,							// read timeout
		error_buffer					// buffer where error message is stored
	)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by WinPcap\n", device->name);
		pcap_freealldevs(devices);
		return -1;
	}

	// Check the link layer. We support only Ethernet for simplicity.
	if (pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	unsigned int netmask;
	char filter_exp[] = "ip and (udp or icmp)";
	struct bpf_program fcode;

	if (device->addresses != NULL)
		// Retrieve the mask of the first address of the interface 
		netmask = ((struct sockaddr_in*)(device->addresses->netmask))->sin_addr.s_addr;
	else
		// If the interface is without an address, we suppose to be in a C class network 
		netmask = 0xffffff;

	// Compile the filter
	if (pcap_compile(device_handle, &fcode, filter_exp, 1, netmask) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// Set the filter
	if (pcap_setfilter(device_handle, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}

	printf("\nListening on %s...\n", device->description);

	// At this point, we don't need any more the device list. Free it
	pcap_freealldevs(devices);

	int result;							// result of pcap_next_ex function
	int packet_counter = 0;				// counts packets in oreder to have numerated packets
	struct pcap_pkthdr* packet_header;	// header of packet (timestamp and length)
	const unsigned char* packet_data;	// packet content

	// Retrieve the packets
	while ((result = pcap_next_ex(device_handle, &packet_header, &packet_data)) >= 0) {

		// Check if timeout has elapsed
		if (result == 0)
			continue;


		// WINPCAP

		// Print winpcap pseudo header
		print_winpcap_header(packet_header, ++packet_counter);


		/* DATA LINK LAYER - Ethernet */

		// Retrive the position of the ethernet header
		ethernet_header* eh = (ethernet_header*)packet_data;

		// Print ethernet header
		print_ethernet_header(eh);


		/* NETWORK LAYER - IPv4 */

		// Retrieve the position of the ip header
		ip_header* ih = (ip_header*)(packet_data + sizeof(ethernet_header));

		// Print ip header
		print_ip_header(ih);


		/* TRANSPORT LAYER - UDP */

		// Retrieve the position of the udp header
		int ip_len = ih->header_length * 4; // header length is calculated using words (1 word = 4 bytes)

		//if ICMP
		if (ih->next_protocol == 1)
		{
			// TODO 1: Print ICMP header
			icmp_header* icmph = (icmp_header*)((unsigned char*)ih + ip_len);

			print_icmp_header(icmph);
		}
		//if udp 
		else if (ih->next_protocol == 17)
		{
			udp_header* uh = (udp_header*)((unsigned char*)ih + ip_len);

			// TODO 1: Print UDP header
			print_udp_header(uh);


			/* APPLICATION LAYER */

			// TODO 2:  Retrieve the position of application data
			unsigned char* app_data = (unsigned char*)uh + sizeof(udp_header);

			// TODO 3: Total length of application header and data
			int app_length = ntohs(uh->datagram_length) - sizeof(udp_header);

			// TODO 4:  Print application header and data
			print_application_data(app_data, app_length);
		}


		// For demonstration purpose
		printf("\n\nPress enter to receive new packet\n");
		getchar();
	}

	if (result == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(device_handle));
		return -1;
	}

	return 0;
}

// This function provide possibility to choose device from the list of available devices
pcap_if_t* select_device(pcap_if_t* devices)
{
	int i = 0;			// Count devices and provide jumping to the selected device 
	pcap_if_t* device;	// Iterator for device list

	// Print the list
	for (device = devices; device; device = device->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	// Check if list is empty
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return NULL;
	}

	// Pick one device from the list
	int device_number;
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &device_number);

	if (device_number < 1 || device_number > i)
	{
		printf("\nInterface number out of range.\n");
		return NULL;
	}

	// Jump to the selected device
	for (device = devices, i = 0; i < device_number - 1; device = device->next, i++);

	return device;
}

// Print raw data of headers and applications
void print_raw_data(unsigned char* data, int data_length)
{
	printf("\n-------------------------------------------------------------\n\t");
	for (int i = 0; i < data_length; i = i + 1)
	{
		printf("%.2x ", ((unsigned char*)data)[i]);

		// 16 bytes per line
		if ((i + 1) % 16 == 0)
			printf("\n\t");
	}
	printf("\n-------------------------------------------------------------");
}

// Print pseudo header which is generated by WinPcap driver
void print_winpcap_header(const struct pcap_pkthdr* packet_header, int packet_counter)
{
	printf("\n\n=============================================================");
	printf("\n\tWINPCAP PSEUDO LAYER");
	printf("\n-------------------------------------------------------------");

	time_t timestamp;			// Raw time (bits) when packet is received 
	struct tm* local_time;		// Local time when packet is received
	char time_string[16];		// Local time converted to string

	// Convert the timestamp to readable format
	timestamp = packet_header->ts.tv_sec;
	local_time = localtime(&timestamp);
	strftime(time_string, sizeof time_string, "%H:%M:%S", local_time);

	// Print timestamp and length of the packet
	printf("\n\tPacket number:\t\t%u", packet_counter);
	printf("\n\tTimestamp:\t\t%s.", time_string);
	printf("\n\tPacket length:\t\t%u ", packet_header->len);
	printf("\n=============================================================");
	return;
}

//Print content of Ethernet header
void print_ethernet_header(ethernet_header* eh)
{
	printf("\n=============================================================");
	printf("\n\tDATA LINK LAYER  -  Ethernet");

	print_raw_data((unsigned char*)eh, sizeof(ethernet_header));

	printf("\n\tDestination address:\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eh->dest_address[0], eh->dest_address[1], eh->dest_address[2], eh->dest_address[3], eh->dest_address[4], eh->dest_address[5]);
	printf("\n\tSource address:\t\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eh->src_address[0], eh->src_address[1], eh->src_address[2], eh->src_address[3], eh->src_address[4], eh->src_address[5]);
	printf("\n\tNext protocol:\t\t0x%.4x", ntohs(eh->type));

	printf("\n=============================================================");

	return;
}

// Print content of ip header
void print_ip_header(ip_header* ih)
{
	printf("\n=============================================================");
	printf("\n\tNETWORK LAYER  -  Internet Protocol (IP)");

	print_raw_data((unsigned char*)ih, ih->header_length * 4);

	printf("\n\tVersion:\t\t%u", ih->version);
	printf("\n\tHeader Length:\t\t%u", ih->header_length * 4);
	printf("\n\tType of Service:\t%u", ih->tos);
	printf("\n\tTotal length:\t\t%u", ntohs(ih->length));
	printf("\n\tIdentification:\t\t%u", ntohs(ih->identification));
	printf("\n\tFragments:\t\t%u", ntohs(ih->fragm_fo));
	printf("\n\tTime-To-Live:\t\t%u", ih->ttl);
	printf("\n\tNext protocol:\t\t%u", ih->next_protocol);
	printf("\n\tHeader checkSum:\t%u", ntohs(ih->checksum));
	printf("\n\tSource:\t\t\t%u.%u.%u.%u", ih->src_addr[0], ih->src_addr[1], ih->src_addr[2], ih->src_addr[3]);
	printf("\n\tDestination:\t\t%u.%u.%u.%u", ih->dst_addr[0], ih->dst_addr[1], ih->dst_addr[2], ih->dst_addr[3]);

	printf("\n=============================================================");

	return;
}
// Print content of icmp header
void print_icmp_header(icmp_header* icmph) {
	printf("\n=============================================================");
	printf("\n\tNETWORK LAYER  -  Internet Control Messaging Protocol (ICMP)");

	print_raw_data((unsigned char*)icmph, sizeof(icmp_header));

	printf("\n\tType:\t\t%u", icmph->type);
	printf("\n\tCode:\t%u", icmph->code);
	printf("\n\tChecksum:\t%u", ntohs(icmph->checksum));
	printf("\n\tData:\t\t%u %u %u %u", icmph->data[0], icmph->data[1], icmph->data[2], icmph->data[3]);

	printf("\n=============================================================");

	return;
}
// Print content od UDP header
void print_udp_header(udp_header* uh)
{
	printf("\n=============================================================");
	printf("\n\tTRANSPORT LAYER  -  User Datagram Protocol (UDP)");

	print_raw_data((unsigned char*)uh, sizeof(udp_header));

	printf("\n\tSource Port:\t\t%u", ntohs(uh->src_port));
	printf("\n\tDestination Port:\t%u", ntohs(uh->dest_port));
	printf("\n\tDatagram Length:\t%u", ntohs(uh->datagram_length));
	printf("\n\tChecksum:\t\t%u", ntohs(uh->checksum));

	printf("\n=============================================================");

	return;
}



// Print content of application layer
void print_application_data(unsigned char* data, long data_length)
{
	printf("\n=============================================================");
	printf("\n\tAPPLICATION LAYER");

	print_raw_data(data, data_length);

	printf("\n=============================================================");
}
//---------------------------------------------------------V9----------------------------------------------
int packet_counter = 0;				// counts packets in oreder to have numerated packets

// Function declarations
void packet_handler(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);

int main()
{
	pcap_if_t* devices;
	pcap_if_t* device;
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs(&devices, error_buffer) == -1)
	{
		printf("Error in pcap_findalldevs: %s\n", error_buffer);
		return -1;
	}

	int i = 0;			// Count devices and provide jumping to the selected device 

	// Print the list
	for (device = devices; device; device = device->next)
	{
		printf("%d. %s", ++i, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}

	// Check if list is empty
	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return NULL;
	}

	// Pick one device from the list
	int device_number;
	printf("Enter the interface number (1-%d):", i);
	scanf_s("%d", &device_number);

	if (device_number < 1 || device_number > i)
	{
		printf("\nInterface number out of range.\n");
		return NULL;
	}

	// Select first device...
	device = devices;

	// ...and then jump to chosen devices
	for (i = 1; i < device_number; i++)
	{
		device = device->next;
	}

	printf("\nChosen adapter is:  %s\n", device->description);

	// Open the capture device
	if ((device_handle = pcap_open_live(device->name,		// name of the device
		65536,						// portion of the packet to capture (65536 guarantees that the whole packet will be captured on all the link layers)
		0,							// non-promiscuous (normal) mode
		1000,							// read timeout
		error_buffer					// buffer where error message is stored
	)) == NULL)
	{
		printf("\nUnable to open the adapter. %s is not supported by WinPcap\n", device->name);
		pcap_freealldevs(devices);
		return -1;
	}

	// Check the link layer. We support only Ethernet for simplicity.
	if (pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(devices);
		return -1;
	}

	unsigned int netmask;
	char filter_exp[] = "ether src host BC-5F-F4-B7-57-84 and ip and (udp or tcp)";  //find out your own MAC address using ipconfig
	struct bpf_program fcode;

	if (device->addresses != NULL)
		// Retrieve the mask of the first address of the interface 
		netmask = ((struct sockaddr_in*)(device->addresses->netmask))->sin_addr.s_addr;
	else
		// If the interface is without an address, we suppose to be in a C class network 
		netmask = 0xffffff;

	// Compile the filter
	if (pcap_compile(device_handle, &fcode, filter_exp, 1, netmask) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// Set the filter
	if (pcap_setfilter(device_handle, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}


	// At this point, we don't need any more the device list. Free it
	pcap_freealldevs(devices);

	// Start capturing packets
	pcap_loop(device_handle, 10, packet_handler, NULL);

	printf("\nPress any key to close application...");
	getchar();

	return 0;
}



// Callback function invoked by WinPcap for every incoming packet
void packet_handler(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	printf("\n\t Packet No.  \t%d", ++packet_counter);

	/* DATA LINK LAYER - Ethernet */

	// Retrive the position of the ethernet header
	ethernet_header* eh = (ethernet_header*)packet_data;

	printf("\nEthernet\n\tDestination MAC address:\t%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", eh->dest_address[0], eh->dest_address[1], eh->dest_address[2], eh->dest_address[3], eh->dest_address[4], eh->dest_address[5]);

	/* NETWORK LAYER - IPv4 */

	// Retrieve the position of the ip header
	ip_header* ih = (ip_header*)(packet_data + sizeof(ethernet_header));

	printf("\nIP\n\t Source IP address:\t\t%u.%u.%u.%u", ih->src_addr[0], ih->src_addr[1], ih->src_addr[2], ih->src_addr[3]);

	/* TRANSPORT LAYER */

	unsigned char* app_data;
	int app_length;

	/* UDP */
	if (ih->next_protocol == 17)
	{
		udp_header* uh = (udp_header*)((unsigned char*)ih + ih->header_length * 4);

		printf("\nUDP\n\tDestination Port:\t\t%u", ntohs(uh->dest_port));

		// Retrieve the position of application data
		app_data = (unsigned char*)uh + sizeof(udp_header);

		// Total length of application header and data
		app_length = ntohs(uh->datagram_length) - sizeof(udp_header);
	}

	/* TCP */
	else if (ih->next_protocol == 6)
	{
		tcp_header* th = (tcp_header*)((unsigned char*)ih + ih->header_length * 4);

		printf("\nTCP\n\tDestination Port:\t\t%u", ntohs(th->dest_port));

		// Retrieve the position of application data
		app_data = (unsigned char*)th + th->header_length * 4;

		// Total length of application header and data
		app_length = packet_header->len - (sizeof(ethernet_header) + ih->header_length * 4 + th->header_length * 4);
	}
	else
	{
		return;
	}

	/* APPLICATION LAYER */

	// Print application header and data
	printf("\n-------------------------------------------------------------\n\t");
	for (int i = 0; i < app_length; i = i + 1)
	{
		printf("%.2x ", (app_data)[i]);

		// 16 bytes per line
		if ((i + 1) % 16 == 0)
			printf("\n\t");
	}
	printf("\n-------------------------------------------------------------");

	// For demonstration purpose
	printf("\n\nPress enter to receive new packet\n");
	getchar();

}//-------------------------------------------------------------------------------V10--------------

void packet_handler(unsigned char* param, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);

pcap_dumper_t* icmp_dumper;
pcap_dumper_t* udp_dumper;
pcap_dumper_t* tcp_dumper;
pcap_dumper_t* arp_dumper;

int main()
{
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];

	// Open the capture file 
	if ((device_handle = pcap_open_offline("example.pcap", // Name of the device
		error_buffer	  // Error buffer
	)) == NULL)
	{
		printf("\n Unable to open the file %s.\n", "example.pcap");
		return -1;
	}

	// Open the dump file 
	arp_dumper = pcap_dump_open(device_handle, "arp_packets.pcap");
	icmp_dumper = pcap_dump_open(device_handle, "icmp_packets.pcap");
	udp_dumper = pcap_dump_open(device_handle, "udp_packets.pcap");
	tcp_dumper = pcap_dump_open(device_handle, "tcp_packets.pcap");


	if (icmp_dumper == NULL || udp_dumper == NULL || tcp_dumper == NULL || arp_dumper == NULL)
	{
		printf("\n Error opening output file\n");
		return -1;
	}

	// Check the link layer. We support only Ethernet for simplicity.
	if (pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}

	struct bpf_program fcode;

	// Compile the filter
	if (pcap_compile(device_handle, &fcode, "arp or (ip and (icmp or udp or tcp))", 1, 0xffffff) < 0)
	{
		printf("\n Unable to compile the packet filter. Check the syntax.\n");
		return -1;
	}

	// Set the filter
	if (pcap_setfilter(device_handle, &fcode) < 0)
	{
		printf("\n Error setting the filter.\n");
		return -1;
	}

	// Read and dispatch packets until EOF is reached
	pcap_loop(device_handle, 0, packet_handler, NULL);

	// Close the file associated with device_handle and deallocates resources
	pcap_close(device_handle);

	printf("\nFile: example.pcap is successfully processed.\n");

	return 0;
}

// Callback function invoked by WinPcap for every incoming packet
void packet_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	/* DATA LINK LAYER - Ethernet */

	// Retrive the position of the ethernet header
	ethernet_header* eh = (ethernet_header*)packet_data;

	// ARP
	if (ntohs(eh->type) == 0x806)
	{
		pcap_dump((unsigned char*)arp_dumper, packet_header, packet_data);
		return;
	}

	/* NETWORK LAYER - IPv4 */

	// Retrieve the position of the ip header
	ip_header* ih = (ip_header*)(packet_data + sizeof(ethernet_header));

	// TRANSPORT LAYER
	switch (ih->next_protocol)
	{
		// ICMP
	case 1:
		pcap_dump((unsigned char*)icmp_dumper, packet_header, packet_data);
		break;

		// TCP
	case 6:
		pcap_dump((unsigned char*)tcp_dumper, packet_header, packet_data);
		break;

		// UDP
	case 17:
		pcap_dump((unsigned char*)udp_dumper, packet_header, packet_data);
		break;
	}
}
//-----------------------------------------------------------------------V11
// We do not want the warnings about the old deprecated and unsecure CRT functions since these examples can be compiled under *nix as well
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

// Include libraries
#include <stdlib.h>
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include "conio.h"
#include "pcap.h"
#include "protocol_headers.h"

// Function declarations
void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data);
const char* plejfer(char* poruka);

// Plejfer matrica
char kljuc[5][5] = { {'P', 'R', 'I', 'M', 'E'},
					 {'N', 'A', 'B', 'C', 'D'},
					 {'F', 'G', 'H', 'K', 'L'},
					 {'O', 'Q', 'S', 'T', 'U'},
					 {'V', 'W', 'X', 'Y', 'Z'} };

int icmpBrojac = 0;

//referenca na fajl u koji se upisuje
pcap_dumper_t* file_dumper;

int main()
{
	pcap_t* device_handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	// Open the capture file
	if ((device_handle = pcap_open_offline("packetsv12.pcap", // Name of the device
		error_buffer)) == NULL) // Error buffer
	{
		printf("\n Unable to open the file %s.\n", "packetsv12.pcap");
		return -1;
	}

	file_dumper = pcap_dump_open(device_handle, "encrypackets.pcap");
	if (file_dumper == NULL)
	{
		printf("\n Error opening output file\n");
		return -1;
	}

	// Check the link layer. We support only Ethernet for simplicity. 
	if (pcap_datalink(device_handle) != DLT_EN10MB)
	{
		printf("\nThis program works only on Ethernet networks.\n");
		return -1;
	}
	// Read and dispatch packets until EOF is reached 
	pcap_loop(device_handle, 0, dispatcher_handler, NULL);

	printf("Broj ICMP paketa: %d\n", icmpBrojac);

	// Close the file associated with device_handle and deallocates resources 
	pcap_close(device_handle);

	getchar();
}

void dispatcher_handler(unsigned char* user, const struct pcap_pkthdr* packet_header, const unsigned char* packet_data)
{
	// Print packet timestamp
	printf("Paket pristigao: %ld:%ld\n", packet_header->ts.tv_sec,
		packet_header->ts.tv_usec);

	//and get its length
	int velicinaPaketa = packet_header->len;

	//kopija paketa, postavlja se na vrednosti 0
	char kopija[1000];
	memset(kopija, 0, velicinaPaketa * sizeof(char));

	//preuzimanje podataka iz Ethernet okvira i smestanje zaglavlja u kopiju
	ethernet_header* eh = (ethernet_header*)packet_data;
	memcpy(kopija, eh, sizeof(ethernet_header) * sizeof(char));

	//provera da li je IPv4
	if (ntohs(eh->type) == 0x0800)
	{
		//pristupanje IP zaglavlju i smestanje u kopiju
		ip_header* ih = (ip_header*)((unsigned char*)eh + sizeof(ethernet_header));
		memcpy(kopija + sizeof(ethernet_header), ih, (ih->header_length * 4) * sizeof(char));

		printf("Logicka adresa primaoca: %d.%d.%d.%d\n", ih->dst_addr[0], ih->dst_addr[1], ih->dst_addr[2], ih->dst_addr[3]);

		//Provera sledeceg protokola: ICMP - 1; TCP - 6; UDP - 17
		if (ih->next_protocol == 1)
		{
			printf("Protokol: ICMP");
			icmpBrojac++;
		}
		else if (ih->next_protocol == 6)
		{
			//pristupanje TCP zaglavlju
			tcp_header* th = (tcp_header*)((unsigned char*)ih + ih->header_length * 4);

			printf("Protokol: TCP\n");
			printf("Zaglavlje:");
			// Print the packet
			for (int i = 0; i < th->header_length * 4; i++)
			{
				printf("%.2x ", th[i]);
				if ((i + 1) % 16 == 0)
					printf("\n");
			}
			printf("\n");

			//Provera da li je port 80 -> HTTP (vidi se u Wireshark-u)
			if (ntohs(th->src_port) == 80 || ntohs(th->dest_port) == 80)
			{
				printf("HTTP sadrzaj: ");
				char* app_data = (char*)((unsigned char*)th + th->header_length * 4);
				for (int i = 0; i < 16; i++)
				{
					printf("%c", app_data[i]);
				}
				printf("\n");
			}
		}
		else if (ih->next_protocol == 17)
		{
			//Pristupanje UDP zaglavlju i smestanje u kopiju
			printf("Protokol: UDP\n");
			udp_header* uh = (udp_header*)((unsigned char*)ih + ih->header_length * 4);
			memcpy(kopija + sizeof(ethernet_header) + ih->header_length * 4, uh, sizeof(udp_header));

			//Aplikativni deo
			char* app_data = (char*)((unsigned char*)uh + sizeof(udp_header));
			int app_length = ntohs(uh->datagram_length) - sizeof(udp_header);

			printf("Aplikativni deo: ");
			for (int i = 0; i < app_length; i++)
			{
				printf("%c", app_data[i]);
				if ((i + 1) % 16 == 0)
					printf("\n");
			}
			printf("\n");

			app_data[app_length] = '\0';

			//sifrovanje poruke
			char cipher[200] = "\0";
			strcpy(cipher, plejfer(app_data));
			printf("Sifrovano: %s", cipher);

			//kopiranje sifrovane poruke u kopiju aplikativnog dela paketa
			memcpy(kopija + sizeof(ethernet_header) + ih->header_length * 4 + sizeof(udp_header), cipher, app_length);

			//zapisivanje kopije u fajl
			pcap_dump((unsigned char*)file_dumper, packet_header, (const unsigned char*)kopija);
		}
	}
	//Provera da li je protokol ARP
	else if (ntohs(eh->type) == 0x0806)
	{
		printf("Protokol: ARP");
	}
	printf("\n\n");
}


const char* plejfer(char* poruka)
{
	//pozicija slova u redovima i kolonama matrice
	int r1 = -1, r2 = -1, k1 = -1, k2 = -1;

	int duzinaPoruke = strlen(poruka);

	//Ako je poruka neparne duzine, na kraj se dodaje neutralni karakter
	char neutralniKarakter = 'Z';
	if (duzinaPoruke % 2 == 1)
	{
		strncat(poruka, &neutralniKarakter, 1);
		duzinaPoruke += 1;
	}

	char kriptovanaPoruka[200];

	for (int i = 0; i < duzinaPoruke; i++)
	{
		//ako se u poruci pojavi slovo J menja se u slovo I
		if (poruka[i] == 'J')
		{
			poruka[i] = 'I';
		}
	}

	//Trazenje pozicije parova slova u matrici
	for (int i = 0; i < duzinaPoruke; i += 2)
	{
		for (int j = 0; j < 5; j++)
		{
			for (int k = 0; k < 5; k++)
			{
				if (kljuc[j][k] == poruka[i])
				{
					r1 = j;
					k1 = k;
				}
				if (kljuc[j][k] == poruka[i + 1])
				{
					r2 = j;
					k2 = k;
				}
			}
		}

		//ako su dva ista slova
		if (r1 == r2 && k1 == k2)
		{
			//ono ostaje isto, i dodaje se X
			kriptovanaPoruka[i] = poruka[i];
			kriptovanaPoruka[i + 1] = 'X';
		}
		else
		{
			//ako su slova u istom redu
			if (r1 == r2)
			{
				//ako je poslednja kolona, pomera se na prvu
				if (k1 == 4)
				{
					kriptovanaPoruka[i] = kljuc[r1][0];
				}
				//u suprotnom, pomera se u kolonu desno
				else
				{
					kriptovanaPoruka[i] = kljuc[r1][k1 + 1];
				}
				if (k2 == 4)
				{
					kriptovanaPoruka[i + 1] = kljuc[r2][0];
				}
				else
				{
					kriptovanaPoruka[i + 1] = kljuc[r2][k2 + 1];
				}
			}
			//ako su slova u istoj koloni
			else if (k1 == k2)
			{
				//ako je poslednji red, pomera se na prvi
				if (r1 == 4)
				{
					kriptovanaPoruka[i] = kljuc[0][k1];
				}
				//u suprotnom, pomera se u red dole
				else
				{
					kriptovanaPoruka[i] = kljuc[r1 + 1][k1];
				}
				if (r2 == 4)
				{
					kriptovanaPoruka[i + 1] = kljuc[0][k2];
				}
				else
				{
					kriptovanaPoruka[i + 1] = kljuc[r2 + 1][k2];
				}
			}
			//u slucaju da su u razlicitim redovima i kolonama, menjaju se kolone
			else
			{
				kriptovanaPoruka[i] = kljuc[r1][k2];
				kriptovanaPoruka[i + 1] = kljuc[r2][k1];
			}
		}
	}
	//zavrsava se poruka
	kriptovanaPoruka[duzinaPoruke] = '\0';
	return kriptovanaPoruka;
	//------------------------Dodatna kriptofunkcija
	char* homophone_cipher(char* message) {
		int length = strlen(message);
		char* encoded_message = (char*)malloc((length * 5 + 1) * sizeof(char)); // Each character can be replaced by up to 5 characters in this example

		if (encoded_message == NULL) {
			printf("Memory allocation failed.\n");
			exit(EXIT_FAILURE);
		}


		const char* homophones[] = {
			"1", "2", "3", "4", "5",
			"6", "7", "8", "9", "10",
			"11", "12", "13", "14", "15",
			"16", "17", "18", "19", "20",
			"21", "22", "23", "X-24", "25", "26"
		};

		int index;
		int position = 0;

		for (int i = 0; i < length; i++) {
			if (isalpha(message[i])) {
				if (isupper(message[i])) {
					index = message[i] - 'A';
				}
				else {
					index = message[i] - 'a';
				}

				if (index >= 0 && index < 26) {

					position += sprintf(encoded_message + position, "%s ", homophones[index]);
				}
				else {

					encoded_message[position++] = message[i];
				}
			}
			else {

				encoded_message[position++] = message[i];
			}
		}



		return encoded_message;
	}
	//---------------------------------------------------
}