#ifndef BITCOIN_QT_STAKINGDIALOG_H
#define BITCOIN_QT_STAKINGDIALOG_H

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

class TxViewDelegate;
class TransactionFilterProxy;

namespace Ui {
    class StakingDialog;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

class StakingDialog : public QWidget
{
    Q_OBJECT

public:
    explicit StakingDialog(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~StakingDialog();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);

Q_SIGNALS:
    void transactionClicked(const QModelIndex &index);
    void show_txClicked();

public Q_SLOTS:

    void setStakingStatus(QString text, bool fStake);
    void setNetworkStats(QString blockheight, QString diffPoW, QString diffPoS);
    void updateStakeReportNow();
    void updateStakeReportbalanceChanged(qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64);
    void btn_Stake_OnClicked();
    void btn_Stake_OffClicked();
    void getColdStakingAddress();

private:
    Ui::StakingDialog *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    void updateStakeReport(bool fImmediate);
    qint64 nLastReportUpdate;

    TxViewDelegate *txdelegateStake;
    std::unique_ptr<TransactionFilterProxy> filterS;

    private Q_SLOTS:
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
};

#endif // BITCOIN_QT_STAKINGDIALOG_H
