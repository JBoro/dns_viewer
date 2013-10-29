#ifndef __PCAPIMPL_H
#define __PCAPIMPL_H

#include <memory>
#include <map>
#include <string>

#include "ifcapimpl.h"

typedef struct pcap pcap_t;
typedef struct pcap_if pcap_if_t;

namespace DNSView
{

class PCapImpl : public IFCapImpl
{
public:
    PCapImpl();
    ~PCapImpl();

protected:
    virtual int doInit(const std::string &dev, std::string errmsg);
    virtual std::map<std::string, std::string> doGetDeviceList(std::string &errmsg);
    virtual int doGetNextPkt(const u_char* &data, u_int &tv_sec);
    virtual void doShutDown();

private:
    pcap_t *pPCapH_;
    pcap_if_t *pDevsH_;
};

}

#endif
