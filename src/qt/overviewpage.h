// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_OVERVIEWPAGE_H
#define BITCOIN_QT_OVERVIEWPAGE_H

#include "amount.h"

#include <QWidget>
#include <QPushButton>
#include <QListView>
#include <QPainter>
#include <memory>
#include <QScrollBar>
#include <QStaticText>

class ClientModel;
class TransactionFilterProxy;
class TxViewDelegate;
class PlatformStyle;
class WalletModel;

namespace Ui {
    class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QModelIndex;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~OverviewPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);
    void showOutOfSyncWarning(bool fShow);

    public Q_SLOTS:
    void setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& stakingBalance, const CAmount& immatureBalance,
        const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance, const CAmount& coldStakingBalance);

    void showLockStaking(bool status);
    void setStakingStatus(QString text, bool fStake);
    void setNetworkStats(QString blockheight, QString diffPoW, QString diffPoS);
    void updateStakeReportNow();
    void updateStakeReportbalanceChanged(qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64);

Q_SIGNALS:
    void transactionClicked(const QModelIndex &index);
    void show_txClicked();
    

private:
    Ui::OverviewPage *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    CAmount currentBalance;
    CAmount currentUnconfirmedBalance;
    CAmount currentStakingBalance;
    CAmount currentColdStakingBalance;
    CAmount currentImmatureBalance;
    CAmount currentWatchOnlyBalance;
    CAmount currentWatchUnconfBalance;
    CAmount currentWatchImmatureBalance;
    QStaticText qsAmount;

    TxViewDelegate *txdelegate;
    std::unique_ptr<TransactionFilterProxy> filter;
    qint64 nLastReportUpdate;
    void updateStakeReport(bool fImmediate);

    private Q_SLOTS:
    void updateDisplayUnit();
    void handleTransactionClicked(const QModelIndex &index);
    void updateAlerts(const QString &warnings);
    void updateWatchOnlyLabels(bool showWatchOnly);
    void unlockWalletStaking();
    void show_txButtonClicked();
    void btn_copyClipboardClicked();
    void btn_showQRClicked();
};

#endif // BITCOIN_QT_OVERVIEWPAGE_H
