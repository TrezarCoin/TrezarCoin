#include "trafficgraphwidget.h"
#include "clientmodel.h"

#include <QPainter>
#include <QColor>
#include <QTimer>

#include <cmath>

#define DESIRED_SAMPLES 600

#define XMARGIN 10
#define YMARGIN 10

TrafficGraphWidget::TrafficGraphWidget(QWidget *parent) :
    QWidget(parent),
    timer(0),
    fMax(0.0f),
    nMinutes(0),
    vSamplesIn(),
    vSamplesOut(),
    nLastBytesRx(0),
    nLastBytesTx(0),
    clientModel(0)
{
    timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), SLOT(updateRates()));
}

void TrafficGraphWidget::setClientModel(ClientModel *model) {
    clientModel = model;
    if(model) {
        nLastBytesRx = model->getTotalBytesRx();
        nLastBytesTx = model->getTotalBytesTx();
    }
}

void TrafficGraphWidget::paintPath(QPainterPath &path, QQueue<float> &samples) {
    int h = height() - YMARGIN * 2, w = width() - XMARGIN * 2;
    int sampleCount = samples.size(), x = XMARGIN + w, y, i;

    if(sampleCount > 0) {
        path.moveTo(x, YMARGIN + h);
        for(i = 0; i < sampleCount; ++i) {
            x = XMARGIN + w - w * i / DESIRED_SAMPLES;
            y = YMARGIN + h - (int)(h * samples.at(i) / fMax);
            path.lineTo(x, y);
        }
        path.lineTo(x, YMARGIN + h);
    }
}

void TrafficGraphWidget::paintEvent(QPaintEvent *) {
    int i, h, yy, base;
    float y, val;

    QPainter painter(this);
    painter.fillRect(rect(), Qt::black);

    if(fMax <= 0.0f) return;

    QColor axisCol(Qt::gray);
    h = height() - YMARGIN * 2;
    painter.setPen(axisCol);
    painter.drawLine(XMARGIN, YMARGIN + h, width() - XMARGIN, YMARGIN + h);

    // decide what order of magnitude we are
    base = floor(log10(fMax));
    val = pow(10.0f, base);

    const QString units = tr("Kb/s");
    // draw lines
    painter.setPen(axisCol);
    painter.drawText(XMARGIN, YMARGIN + h - h * val / fMax, QString("%1 %2").arg(val).arg(units));
    for(y = val; y < fMax; y += val) {
        yy = YMARGIN + h - h * y / fMax;
        painter.drawLine(XMARGIN, yy, width() - XMARGIN, yy);
    }
    // if we drew 3 or fewer lines, break them up at the next lower order of magnitude
    if(fMax / val <= 3.0f) {
        axisCol = axisCol.darker();
        val = pow(10.0f, base - 1);
        painter.setPen(axisCol);
        painter.drawText(XMARGIN, YMARGIN + h - h * val / fMax, QString("%1 %2").arg(val).arg(units));
        for(y = val, i = 1; y < fMax; y += val, i++) {
            // don't overwrite lines drawn above
            if(!(i % 10)) continue;
            yy = YMARGIN + h - h * y / fMax;
            painter.drawLine(XMARGIN, yy, width() - XMARGIN, yy);
        }
    }

    if(!vSamplesIn.empty()) {
        QPainterPath p;
        paintPath(p, vSamplesIn);
        painter.fillPath(p, QColor(0, 255, 0, 128));
        painter.setPen(Qt::green);
        painter.drawPath(p);
    }
    if(!vSamplesOut.empty()) {
        QPainterPath p;
        paintPath(p, vSamplesOut);
        painter.fillPath(p, QColor(255, 0, 0, 128));
        painter.setPen(Qt::red);
        painter.drawPath(p);
    }
}

void TrafficGraphWidget::updateRates() {

    if(!clientModel) return;

    quint64 bytesRx = clientModel->getTotalBytesRx();
    quint64 bytesTx = clientModel->getTotalBytesTx();
    float rateRx = (bytesRx - nLastBytesRx) / 1024.0f * 1000 / timer->interval();
    float rateTx = (bytesTx - nLastBytesTx) / 1024.0f * 1000 / timer->interval();

    vSamplesIn.push_front(rateRx);
    vSamplesOut.push_front(rateTx);
    nLastBytesRx = bytesRx;
    nLastBytesTx = bytesTx;

    while(vSamplesIn.size() > DESIRED_SAMPLES)
      vSamplesIn.pop_back();

    while(vSamplesOut.size() > DESIRED_SAMPLES)
      vSamplesOut.pop_back();

    float tmax = 0.0f;
    foreach(float f, vSamplesIn) {
        if(f > tmax) tmax = f;
    }
    foreach(float f, vSamplesOut) {
        if(f > tmax) tmax = f;
    }
    fMax = tmax;
    update();
}

void TrafficGraphWidget::setGraphRange(int nMinutes) {
    timer->stop();
    timer->setInterval(nMinutes * 60 * 1000 / DESIRED_SAMPLES);
    clear();
}

void TrafficGraphWidget::clear() {
    timer->stop();
    vSamplesOut.clear();
    vSamplesIn.clear();
    fMax = 0.0f;
    if(clientModel) {
        nLastBytesRx = clientModel->getTotalBytesRx();
        nLastBytesTx = clientModel->getTotalBytesTx();
    }
    timer->start();
}
