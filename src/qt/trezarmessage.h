#ifndef BITCOIN_QT_TREZARMESSAGE_H
#define BITCOIN_QT_TREZARMESSAGE_H

#include "amount.h"
#include "walletmodel.h"

#include <QWidget>
#include <QPushButton>
#include <QListView>
#include <QPainter>
#include <memory>
#include <QScrollBar>

class ClientModel;
class OptionsModel;
class WalletModel;
class PlatformStyle;
class TransactionFilterProxy;

namespace Ui {
    class TrezarMessage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE


class TrezarMessage : public QWidget
{
    Q_OBJECT

public:
    explicit TrezarMessage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~TrezarMessage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);


private:
    Ui::TrezarMessage *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    const PlatformStyle *platformStyle;
};

#endif // BITCOIN_QT_TrezarMessageG_H
