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
#include "pcap.h"
#include "pcapimpl.h"

namespace DNSView
{

PCapImpl::PCapImpl() : IFCapImpl(), pPCapH_(NULL), pDevsH_(NULL)
{}

PCapImpl::~PCapImpl() 
{}

int PCapImpl::doInit(const std::string &dev, std::string errmsg)
{
    char errbuf[PCAP_ERRBUF_SIZE];
#ifdef _HAS_PCAP_OPEN
    if ( ( pPCapH_ = pcap_open(dev.c_str(), 65535, 
            0, 1, NULL, errbuf ) ) == NULL )
#else
    if ( ( pPCapH_ = pcap_open_live(dev.c_str(), 65535, 
            0, 1, errbuf ) ) == NULL )
#endif
    {
        errmsg = errbuf;
        return -1;
    }
    return 0;
}

void PCapImpl::doShutDown()
{
    if (pPCapH_)
    {
        pcap_close(pPCapH_);
        pPCapH_ = NULL;
    }
}

std::map<std::string, std::string> PCapImpl::doGetDeviceList(std::string &errmsg)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    std::map<std::string, std::string> _nameMap;
#ifdef _HAS_PCAP_OPEN
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &pDevsH_, errbuf) == -1)
#else
    if (pcap_findalldevs(&pDevsH_, errbuf) == -1)
#endif
        errmsg = errbuf;
    else
    {
        for(pcap_if_t *d=pDevsH_; d; d=d->next)
            _nameMap.insert(std::map<std::string, std::string>::value_type( 
                (d->description ? d->description : d->name), d->name ) );
        pcap_freealldevs(pDevsH_);
    }
    pDevsH_ = NULL;
    return _nameMap;
}

int PCapImpl::doGetNextPkt(const u_char* &data, u_int &tv_sec)
{
    pcap_pkthdr *hdr;
    const u_char *pdata;
    int ret;
    if ( 1 == (ret = pcap_next_ex(pPCapH_, &hdr, &pdata) ) )
    {
        if ( hdr->caplen != hdr->len )
            return -1;
        data = pdata;
        tv_sec = hdr->ts.tv_sec + ( ( hdr->ts.tv_usec + 500000 ) / 1000000 );
        return hdr->caplen;
    }
    return ret;
}

}
