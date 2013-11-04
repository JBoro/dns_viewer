#ifndef __IFCAPIMPL_H
#define __IFCAPIMPL_H

#include <memory>
#include <map>
#include <string>

namespace DNSView
{
class IFCapImpl
{
public:
    IFCapImpl();
    ~IFCapImpl();

    void getDeviceList(std::map<std::string, std::string>& devMap, 
            std::string &errmsg);
    int init(const std::string &dev, std::string &errmsg);
    void shutDown();

    unsigned long long getNBytes();
    int getNextPacket(std::string &pktStr);

    typedef unsigned char u_char;
    typedef unsigned short u_short;
    typedef unsigned int u_int;


protected:
    
    virtual int doInit(const std::string &dev, std::string errmsg) = 0;
    virtual std::map<std::string, std::string> doGetDeviceList(std::string &errmsg) = 0;
    virtual int doGetNextPkt(const u_char* &data, u_int &tv_sec) = 0;
    virtual void doShutDown() = 0;

private:
    unsigned long long nBytes_;
};

}

#endif
