#ifndef LISTWINDOW_H
#define LISTWINDOW_H

#include <QMainWindow>
#include <QSharedPointer>
#include <QFile>
#include <QTextStream>

;
namespace Ui {
class ListWindow;
}

namespace DNSView
{

class NonEditableQStringListModel;
class PCapThread;

class ListWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit ListWindow(QWidget *parent = 0);
    ~ListWindow();

protected:
    void closeEvent(QCloseEvent *event);

public slots:
    void slotDataReady(const QString &value);
    void slotError(const QString &value);
    void slotOnStartClick();
    void slotOnStopClick();
    void slotOnSaveFileClick();
    void slotDone();
    void slotKbps(double value);

signals:
    void sigStartPoll(const QString &dev);
    void sigStopPoll();
    void sigQuit();

private:
    QSharedPointer<Ui::ListWindow> spUi_;
    QSharedPointer<PCapThread> spPCapThread_;
    QSharedPointer<NonEditableQStringListModel> spStringListModel_;
    QFile qFile_;
    QTextStream qTStream_;
};

}

#endif // LISTWINDOW_H
