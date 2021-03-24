#include <iostream>

extern "C" {
    #include <pcap.h>
}



using namespace std;

static int packetCount = 0;

void packetHandler(u_char *useprData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  cout << ++packetCount << " packet(s) captured" << endl;
  cout<<"Packet length:"<<pkthdr->len<<", time interval:" << pkthdr->ts.tv_sec <<endl;
//   cout<<"useprData:"<<useprData<<endl;
  cout<<"Packet:"<<string((char*)packet)<<endl;
}

int main() {
  char *dev;
  pcap_t *descr;
  char errbuf[PCAP_ERRBUF_SIZE];

  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
      cout << "pcap_lookupdev() failed: " << errbuf << endl;
      return 1;
  }

  descr = pcap_open_live(dev, BUFSIZ, 0, -1, errbuf);
  if (descr == NULL) {
      cout << "pcap_open_live() failed: " << errbuf << endl;
      return 1;
  }

  if (pcap_loop(descr, 20, packetHandler, NULL) < 0) {
      cout << "pcap_loop() failed: " << pcap_geterr(descr);
      return 1;
  }

  cout << "capture finished" << endl;

  return 0;
}
