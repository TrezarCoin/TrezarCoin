#ifndef TRAFFICGRAPHWIDGET_H
#define TRAFFICGRAPHWIDGET_H

#include <QWidget>
#include <QQueue>

class ClientModel;

QT_BEGIN_NAMESPACE
class QPaintEvent;
class QTimer;
QT_END_NAMESPACE

class TrafficGraphWidget : public QWidget
{
    Q_OBJECT

public:
    explicit TrafficGraphWidget(QWidget *parent = 0);
    void setClientModel(ClientModel *model);

protected:
    void paintEvent(QPaintEvent *);

public slots:
    void updateRates();
    void setGraphRange(int nMinutes);
    void clear();

private:
    void paintPath(QPainterPath &path, QQueue<float> &samples);

    QTimer *timer;
    float fMax;
    int nMinutes;
    QQueue<float> vSamplesIn;
    QQueue<float> vSamplesOut;
    quint64 nLastBytesRx;
    quint64 nLastBytesTx;
    ClientModel *clientModel;
};

#endif // TRAFFICGRAPHWIDGET_H
