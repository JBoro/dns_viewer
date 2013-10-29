#include <map>
#include <QObject>
#include <QSharedPointer>
#include <QStringList>

class QThread;
class QTimer;
class QElapsedTimer;

namespace DNSView
{

class PCapImpl;

class PCapThread : public QObject
{
    Q_OBJECT

public:
    explicit PCapThread(QObject *parent = 0);
    virtual ~PCapThread();

    void waitForThread();

    QStringList getDeviceList();

public slots:
    void slotPoll();
    void slotStart(const QString &devDesc);
    void slotStop();
    void slotQuit();
    void slotKbps();

signals:
    void sigDataReady(const QString &value);
    void sigError(const QString &value);
    void sigDone();
    void sigkBps(double value);

private:
    QSharedPointer<QThread> spThread_;
    QSharedPointer<QTimer> spTimer_, spkBpsTimer_;
    QSharedPointer<PCapImpl> spPCapImpl_;
    QSharedPointer<QElapsedTimer> spElapsed_;
    std::map<std::string, std::string> devMap_;
    quint64 prevBytes_;
};

}
