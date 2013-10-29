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
#include <QStringList>
#include <QStringListModel>
#include <QMessageBox>
#include <QCloseEvent>
#include <QTextStream>
#include <QFile>
#include <QFileDialog>
#include "listwindow.h"
#include "dnsviewer.h"
#include UI_INCLUDE
#include "pcapthread.h"

namespace DNSView
{

class NonEditableQStringListModel : public QStringListModel
{
public:
    explicit NonEditableQStringListModel(QObject *parent = 0) : QStringListModel(parent) {}
    ~NonEditableQStringListModel() {}

    Qt::ItemFlags flags(const QModelIndex &index) const
    {
        return QStringListModel::flags(index) & ~Qt::ItemIsEditable;
    }
};

ListWindow::ListWindow(QWidget *parent) :
    QMainWindow(parent),
    spUi_(new Ui::ListWindow),
    spPCapThread_(new PCapThread),
    spStringListModel_(new NonEditableQStringListModel)
{
    spUi_->setupUi(this);

    /* Set the view model and connect the signals/slots */
    spUi_->listView_->setModel(spStringListModel_.data());
    this->setWindowTitle(QApplication::translate("ListWindow", "DNSView " VERSION_MAJOR "." VERSION_MINOR, 0));
    connect(spPCapThread_.data(), SIGNAL(sigDataReady(const QString&)), this, SLOT(slotDataReady(const QString&)));
    connect(spPCapThread_.data(), SIGNAL(sigError(const QString&)), this, SLOT(slotError(const QString&)));
    connect(spPCapThread_.data(), SIGNAL(sigDone()), this, SLOT(slotDone()));
    connect(spUi_->actionQuit, SIGNAL(triggered()), this, SLOT(close()));
    connect(this, SIGNAL(sigQuit()), spPCapThread_.data(), SLOT(slotQuit()));
    connect(this, SIGNAL(sigStartPoll(const QString&)), spPCapThread_.data(), SLOT(slotStart(const QString&)));
    connect(this, SIGNAL(sigStopPoll()), spPCapThread_.data(), SLOT(slotStop()));
    connect(spPCapThread_.data(), SIGNAL(sigkBps(double)), this, SLOT(slotKbps(double)));
    connect(spUi_->startButton_, SIGNAL(clicked()), this, SLOT(slotOnStartClick()));
    connect(spUi_->stopButton_, SIGNAL(clicked()), this, SLOT(slotOnStopClick()));
    connect(spUi_->fileSelectButton_, SIGNAL(clicked()), this, SLOT(slotOnSaveFileClick()));
    
    /* Populate the device list */
    QStringList qlist(spPCapThread_->getDeviceList());
    spUi_->comboBox_->insertItems(0, qlist);

    /* Set the initial button state */
    spUi_->comboBox_->setEnabled(true);
    spUi_->startButton_->setEnabled(true);
    spUi_->stopButton_->setEnabled(false);

    setWindowIcon(QIcon(":/resources/net.png"));
}

ListWindow::~ListWindow()
{}

void ListWindow::closeEvent(QCloseEvent *event)
{
    /* Emit the quit signal and wait for the thread */
    emit sigQuit();
    qTStream_.flush();
    qTStream_.setDevice(NULL);
    spPCapThread_->waitForThread();
    if (event)
        event->accept();
}

void ListWindow::slotDone()
{
    /* Set the button state and close the file if any */
    spUi_->comboBox_->setEnabled(true);
    spUi_->startButton_->setEnabled(true);
    spUi_->stopButton_->setEnabled(false);
    spUi_->fileSaveEdit_->setEnabled(true);
    spUi_->fileSelectButton_->setEnabled(true);
    if ( qTStream_.device() )
    {
        qTStream_.flush();
        qTStream_.setDevice(NULL);
        qFile_.close();
    }
}

void ListWindow::slotDataReady(const QString &value)
{
    /* Insert the dns entry and log to file */
    spStringListModel_->insertRows(spStringListModel_->rowCount(), 1);
    spStringListModel_->setData(spStringListModel_->index(spStringListModel_->rowCount() - 1), value);
    if ( spUi_->autoScroll_->isChecked() )
        spUi_->listView_->scrollTo(spStringListModel_->index(spStringListModel_->rowCount() - 1));
    if ( qTStream_.device() )
        qTStream_ << value << endl;
}

void ListWindow::slotOnStartClick()
{
    /* Set the button state, clear the view, and open the file if one was given */
    spUi_->comboBox_->setEnabled(false);
    spUi_->startButton_->setEnabled(false);
    spUi_->stopButton_->setEnabled(true);
    spUi_->fileSaveEdit_->setEnabled(false);
    spUi_->fileSelectButton_->setEnabled(false);
    spStringListModel_->removeRows(0, spStringListModel_->rowCount() );
    if ( !spUi_->fileSaveEdit_->text().isEmpty() )
    {
        qFile_.setFileName(spUi_->fileSaveEdit_->text());
        if ( !qFile_.open(QFile::WriteOnly | QFile::Append) )
            slotError("Error opening file " + spUi_->fileSaveEdit_->text() );
        else
            qTStream_.setDevice(&qFile_);
    }
    emit sigStartPoll(spUi_->comboBox_->currentText() );
}

void ListWindow::slotKbps(double value)
{
    QString str = QString("%1").arg(value, 0, 'f', 2);
    spUi_->KbpsLabel_->setText(str);
}

void ListWindow::slotOnStopClick()
{
    emit sigStopPoll();
}

void ListWindow::slotOnSaveFileClick()
{
     QString saveName = QFileDialog::getSaveFileName(this, tr("Save File"), QString(), tr("All Files(*.*)"), 
         0, QFileDialog::DontConfirmOverwrite);
     spUi_->fileSaveEdit_->setText(saveName);
}

void ListWindow::slotError(const QString &value)
{
    QMessageBox::information(this, tr("DNSViewer"),
                                 tr("The following error occurred: %1.")
                                 .arg(value) );
}

}