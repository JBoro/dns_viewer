/*
Copyright (c) 2013, Justin Borodinsky
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

  Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright notice, this
  list of conditions and the following disclaimer in the documentation and/or
  other materials provided with the distribution.

  Neither the name of the {organization} nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <iostream>
#include <iterator>
#include <map>
#include <vector>
#include <string>
#include <sstream>
#include <QDateTime>

#include "dnsviewer.h"
#ifdef _HAS_ARPA_INET_H
#   include <arpa/inet.h>
#elif defined(_HAS_WSOCK2_H)
#   include <Winsock2.h>
#else
#   error no ntohs
#endif
#include "ifcapimpl.h"

namespace DNSView
{

namespace
{

#ifdef _MSC_VER
#   pragma pack(push,1)
#endif
struct nibbles
{
#ifdef _BIG_ENDIAN
    IFCapImpl::u_char nib2:4;
    IFCapImpl::u_char nib1:4;
#else
    IFCapImpl::u_char nib1:4;
    IFCapImpl::u_char nib2:4;
#endif
}
#ifdef __GNUC__
    __attribute__( (packed) )
#endif
    ;
#ifdef _MSC_VER
#   pragma pack(pop)
#endif

struct ip_address
{
    IFCapImpl::u_char byte1;
    IFCapImpl::u_char byte2;
    IFCapImpl::u_char byte3;
    IFCapImpl::u_char byte4;
};

/* ipv4 header */
struct ip_header
{
    nibbles ver_ihl;
    IFCapImpl::u_char  tos; 
    IFCapImpl::u_short tlen;
    IFCapImpl::u_short identification;
    IFCapImpl::u_short flags_fo;
    IFCapImpl::u_char  ttl;
    IFCapImpl::u_char  proto;
    IFCapImpl::u_short crc;
    ip_address  saddr;
    ip_address  daddr;
    IFCapImpl::u_int   op_pad;
};

/* ipv6 header */
struct ipv6_header
{
    nibbles ver_prio;
    IFCapImpl::u_char  flow_lbl[3];
    IFCapImpl::u_short len;
    IFCapImpl::u_char  nexthdr;
    IFCapImpl::u_char  hop_limit;
    IFCapImpl::u_char  saddr[16];
    IFCapImpl::u_char  daddr[16];
};


struct udp_header
{
    IFCapImpl::u_short sport;          
    IFCapImpl::u_short dport;     
    IFCapImpl::u_short len;            
    IFCapImpl::u_short crc;            
};

struct dns_header
{
    IFCapImpl::u_short id;
    IFCapImpl::u_short flags;
    IFCapImpl::u_short qrrc;
    IFCapImpl::u_short arrc;
    IFCapImpl::u_short aurrc;
    IFCapImpl::u_short adrrc;
};

}

IFCapImpl::IFCapImpl()
{}

IFCapImpl::~IFCapImpl() 
{}

int IFCapImpl::init(const std::string &dev, std::string &errmsg)
{
    return doInit(dev, errmsg);
}

void IFCapImpl::shutDown()
{
    doShutDown();
}

unsigned long long IFCapImpl::getNBytes()
{
    return nBytes_;
}

void IFCapImpl::getDeviceList(std::insert_iterator<std::map<std::string, std::string> > oit, std::string &errmsg)
{
    std::map<std::string, std::string> _devMap( doGetDeviceList(errmsg) );
    if (errmsg.empty() )
        std::copy(_devMap.begin(), _devMap.end(), oit);
}

int IFCapImpl::getNextPacket(std::string &pktStr)
{
    /* Parse the current packet */
    const u_char *pData;
    u_int tv_sec;
    int ret = doGetNextPkt(pData, tv_sec);
    if ( 0 >= ret )
        return ret;
    nBytes_ += ret;
    pData += 14;
    int proto, ver = reinterpret_cast<const nibbles*>(pData)->nib2;
            
    /* IPv6 */
    if ( ver == 6 )
    {
        const ipv6_header *pIP6Hdr = reinterpret_cast<const ipv6_header*>(pData);
        pData += 40;
        proto = pIP6Hdr->nexthdr;
        while ( proto == 43 || proto == 44 || proto == 50 || 
                            proto == 51 || proto == 60 )
        {
            std::cerr << "Got extension header " << proto << std::endl;
            proto = *pData++;
            pData += 7 + ( *pData * 8);
        }
    } /* IPv4 */
    else
    {
        const ip_header *pIPHdr = reinterpret_cast<const ip_header*>(pData);    
        pData += pIPHdr->ver_ihl.nib1 * 4;
        proto = pIPHdr->proto;
    }
            
    /* If this is UDP get the header */
    if ( 17 == proto )
    {
        const udp_header *pUDPHdr = reinterpret_cast<const udp_header*>(pData);
        int destPort = ntohs(pUDPHdr->dport);
        pData += sizeof(udp_header);

        /* If this is DNS get the header */
        if ( 53 == destPort )
        {
            const dns_header *pDNSHdr = reinterpret_cast<const dns_header*>(pData);
            pData += sizeof(dns_header);

            /* Get the time and build the display string */
            QDateTime pktTime;
            pktTime.setTime_t(tv_sec);
            QDateTime local(pktTime.toLocalTime());
            int qrrc = ntohs(pDNSHdr->qrrc);
            std::ostringstream sstr;
            sstr << ver;
            pktStr = local.toString().toUtf8().constData() + std::string(": IPv") + sstr.str() + ": ";
            for (int i = 0; i < qrrc; i++)
            {
                std::string name;
                for(int j = 0; j < 5 && *pData; j++)
                {
                    u_char nbytes = *pData++;
                    for (int k = 0; k < nbytes; k++, pData++)
                        name += *pData;
                    if (*pData)
                        name += '.';
                }
                pktStr += name;
                if ( i < qrrc - 1 )
                    pktStr += "/";
            }
        }
    }
    return ret;
}

}
