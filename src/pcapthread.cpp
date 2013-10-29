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
#include <QTimer>
#include <QThread>
#include <QElapsedTimer>

#include "pcapthread.h"
#include "pcapimpl.h"

namespace DNSView
{

/* QObject thread */
PCapThread::PCapThread(QObject *parent)
    : QObject(parent), spThread_(new QThread), spPCapImpl_(new PCapImpl)
{
    this->moveToThread(spThread_.data());
    
    /* Calls exec */
    spThread_->start();
}

PCapThread::~PCapThread()
{}

/* Called directly from the main thread */
void PCapThread::waitForThread()
{
    spThread_->wait();
}

void PCapThread::slotStart(const QString &devDesc)
{
    /* Start the poll timer, kBps update timer, and the elapsed timer */
    spTimer_ = QSharedPointer<QTimer>(new QTimer);
    spTimer_->setInterval(0);
    spkBpsTimer_ = QSharedPointer<QTimer>(new QTimer);
    spkBpsTimer_->setInterval(500);
    spElapsed_ = QSharedPointer<QElapsedTimer>(new QElapsedTimer);
    connect(spTimer_.data(), SIGNAL(timeout()), this, SLOT(slotPoll()) );
    connect(spkBpsTimer_.data(), SIGNAL(timeout()), this, SLOT(slotKbps()) );
    std::string errmsg;
    std::map<std::string, std::string>::iterator it;
    if ( devMap_.end() == ( it = devMap_.find( devDesc.toUtf8().constData() ) ) )
    {
        emit sigError("Device not found");
        emit sigDone();
    }   
    else if ( spPCapImpl_->init(it->second, errmsg) )
    {   
        emit sigError("Error initializing " + devDesc + " " + QString::fromStdString(errmsg) ); 
        emit sigDone();
    }
    else
    {
        spkBpsTimer_->start();
        spElapsed_->start();
        spTimer_->start();
    }
}

void PCapThread::slotKbps()
{
    /* Update the kBps, emit to the main thread */
    quint64 nbytes = spPCapImpl_->getNBytes();
    quint64 elapsed = spElapsed_->restart();
    double kBps = ( static_cast<double>( ( nbytes - prevBytes_ ) * 8) / 1024.L ) 
        / ( static_cast<double>(elapsed) / 1000.L );
    prevBytes_ = nbytes;
    emit sigkBps(kBps);
}

void PCapThread::slotStop()
{
    /* Stop the two timers and disconnect their signals */
    spTimer_->stop();
    spkBpsTimer_->stop();
    if ( !disconnect(spTimer_.data(), SIGNAL(timeout()), this, SLOT(slotPoll())) )
        emit sigError("Error Disconnecting timer slot");
    if (!disconnect(spkBpsTimer_.data(), SIGNAL(timeout()), this, SLOT(slotKbps())) )
        emit sigError("Error Disconnecting kBps slot");
    spPCapImpl_->shutDown();
    emit sigDone();
}

void PCapThread::slotQuit()
{
    spTimer_ = QSharedPointer<QTimer>(NULL);
    spkBpsTimer_ = QSharedPointer<QTimer>(NULL);
    spThread_->quit();
}

void PCapThread::slotPoll()
{
    /* Get the next DNS entry string */
    std::string pktStr;
    int ret = spPCapImpl_->getNextPacket(pktStr);
    if ( 0 > ret )
    {
        emit sigError("Error reading from interface");
        spTimer_->stop();
        emit sigDone();
    }
    else if ( 0 < ret && !pktStr.empty() )
    {
        QString qStr =  QString::fromStdString(pktStr);
        emit sigDataReady(qStr);
    }
}

/* Called directly from the main thread */
QStringList PCapThread::getDeviceList()
{
    QStringList qlist;
    devMap_.clear();
    std::string errmsg;
    spPCapImpl_->getDeviceList(std::inserter(devMap_, devMap_.begin()), errmsg);
    if (!errmsg.empty())
        emit sigError(QString::fromStdString(errmsg));
    else if (devMap_.empty())
        emit sigError("No devices found (are you root?)");
    else
        for (std::map<std::string, std::string>::iterator it = devMap_.begin(); it != devMap_.end(); ++it)
            qlist << QString::fromStdString(it->first);
    return qlist;
}

}