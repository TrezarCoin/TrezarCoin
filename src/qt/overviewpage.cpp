// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "overviewpage.h"
#include "ui_overviewpage.h"

#include "bitcoinunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactionfilterproxy.h"
#include "transactiontablemodel.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"
#include "walletframe.h"
#include "wallet/wallet.h"
#include "askpassphrasedialog.h"
#include "pubkey.h"
#include "util.h"
#include "base58.h"
#include"QScrollBar"
#include <QStaticText>

#include <QAbstractItemDelegate>
#include <QPainter>

#define DECORATION_SIZE 54
#define NUM_ITEMS 6

class TxViewDelegate : public QAbstractItemDelegate
{
    Q_OBJECT
public:
    TxViewDelegate(const PlatformStyle *platformStyle, QObject *parent = nullptr) :
        QAbstractItemDelegate(parent), unit(BitcoinUnits::BTC),
        platformStyle(platformStyle)
    {

    }

    inline void paint(QPainter *painter, const QStyleOptionViewItem &option,
        const QModelIndex &index) const
    {
        painter->save();

        //negative
        bool negValue = false;
        bool BoolLabel = false;
        //font
        QFont font = painter->font();
        font.setPixelSize(16);

        QIcon icon = qvariant_cast<QIcon>(index.data(TransactionTableModel::RawDecorationRole));
        QRect mainRect = option.rect;
        QRect decorationRect(mainRect.topLeft(), QSize(DECORATION_SIZE, DECORATION_SIZE));
        int xspace = DECORATION_SIZE + 8;
        int ypad = 6;
        int halfheight = (mainRect.height() - 2 * ypad) / 2;
        QRect amountRect(mainRect.left() + xspace, mainRect.top() + ypad, mainRect.width() - xspace, halfheight);
        QRect txHashRect(mainRect.left() + xspace, mainRect.top() + ypad + halfheight, mainRect.width() - xspace, halfheight);
        QRect addressRect(mainRect.left() + xspace, mainRect.top() + ypad + halfheight, mainRect.width() - xspace, halfheight);

        //Rects
        QRect middleRectLower(mainRect.right()/2 - 1.5 * xspace, mainRect.top() + ypad + halfheight, mainRect.width() - xspace, halfheight);
        QRect middleRectUpper(mainRect.right() / 2, mainRect.top() + ypad, mainRect.width() - xspace, halfheight);
        icon = platformStyle->SingleColorIcon(icon);
        icon.paint(painter, decorationRect);

        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        QString address = index.data(Qt::DisplayRole).toString();

        QString txHash = index.data(TransactionTableModel::TxHashRole).toString();
        QString txType = index.data(TransactionTableModel::TxType).toString();
        QString txFromTo = index.data(TransactionTableModel::TxTypeOverview).toString();

        qint64 amount = index.data(TransactionTableModel::AmountRole).toLongLong();
        QString amountText = BitcoinUnits::formatWithUnit(unit, amount, true, BitcoinUnits::separatorAlways);
        bool confirmed = index.data(TransactionTableModel::ConfirmedRole).toBool();
        QVariant value = index.data(Qt::ForegroundRole);
        QColor foreground = option.palette.color(QPalette::Text);
        if (value.canConvert<QBrush>())
        {
            QBrush brush = qvariant_cast<QBrush>(value);
            foreground = brush.color();
        }

        painter->setPen(foreground);
        QRect boundingRect;

        

        painter->drawText(addressRect, Qt::AlignLeft | Qt::AlignVCenter, GUIUtil::dateTimeStr(date));
        painter->drawText(middleRectLower, Qt::AlignLeft | Qt::AlignVCenter, address, &boundingRect);
        font.setPixelSize(12);
        painter->setFont(font);
        //painter->drawText(txHashRect, Qt::AlignRight | Qt::AlignVCenter, txHash);

        if (index.data(TransactionTableModel::WatchonlyRole).toBool())
        {
            QIcon iconWatchonly = qvariant_cast<QIcon>(index.data(TransactionTableModel::WatchonlyDecorationRole));
            QRect watchonlyRect(boundingRect.right() + 5, mainRect.top() + ypad + halfheight, 16, halfheight);
            iconWatchonly.paint(painter, watchonlyRect);
        }

        if (amount < 0)
        {
            negValue = true;
            foreground = COLOR_NEGATIVE;
        }
        else if (!confirmed)
        {
            foreground = COLOR_UNCONFIRMED;
        }
        else
        {
            foreground = COLOR_SUCCESS;
        }
        painter->setPen(foreground);
            
        if (!confirmed)
        {
            amountText = QString("[") + amountText + QString("]");
        }
        font.setPixelSize(16);
        painter->setFont(font);
        painter->drawText(amountRect, Qt::AlignRight | Qt::AlignVCenter, amountText);
        painter->setPen(COLOR_WHITE);
        painter->drawText(amountRect, Qt::AlignLeft | Qt::AlignVCenter, txType, &boundingRect);

        painter->restore();
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;
    const PlatformStyle *platformStyle;

};
#include "overviewpage.moc"

OverviewPage::OverviewPage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::OverviewPage),
    clientModel(0),
    walletModel(0),
    currentBalance(-1),
    currentUnconfirmedBalance(-1),
    currentStakingBalance(-1),
    currentColdStakingBalance(-1),
    currentImmatureBalance(-1),
    currentWatchOnlyBalance(-1),
    currentWatchUnconfBalance(-1),
    currentWatchImmatureBalance(-1),
    txdelegate(new TxViewDelegate(platformStyle, this))
{
    ui->setupUi(this);
    // use a SingleColorIcon for the "out of sync warning" icon
    QIcon icon = platformStyle->SingleColorIcon(":/icons/warning");
    icon.addPixmap(icon.pixmap(QSize(64, 64), QIcon::Normal), QIcon::Disabled); // also set the disabled icon because we are using a disabled QPushButton to work around missing HiDPI support of QLabel (https://bugreports.qt.io/browse/QTBUG-42503)
    //ui->labelWalletStatus->setIcon(icon);
    ui->stakeingDot->setIcon(QIcon(":/icons/reddot"));

    // Recent transactions
    ui->listTransactions->setItemDelegate(txdelegate);
    ui->listTransactions->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listTransactions->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listTransactions->setAttribute(Qt::WA_MacShowFocusRect, false);

    //SetAccountAddress
    CPubKey pubKey;
    pwalletMain->GetAccountPubkey(pubKey,"",false);
    ui->labelAddressAccount->setText(QString::fromStdString(CBitcoinAddress(pubKey.GetID()).ToString()));
    ui->labelAddressAccount->setTextInteractionFlags(Qt::TextSelectableByMouse);

    connect(ui->listTransactions, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));
    connect(ui->show_tx, SIGNAL(clicked()), this, SLOT(show_txButtonClicked()));
    //connect(ui->unlockStakingButton, SIGNAL(clicked()), this, SLOT(unlockWalletStaking()));
    connect(ui->btn_copyClipboard, SIGNAL(clicked()), this, SLOT(btn_copyClipboardClicked()));
    connect(ui->btn_showQR, SIGNAL(clicked()), this, SLOT(btn_showQRClicked()));

    // start with displaying the "out of sync" warnings
    showOutOfSyncWarning(true);
    updateStakeReportNow();
}

void OverviewPage::handleTransactionClicked(const QModelIndex &index)
{
    if (filter)
        Q_EMIT transactionClicked(filter->mapToSource(index));
}

void OverviewPage::btn_copyClipboardClicked()
{
    GUIUtil::setClipboard(ui->labelAddressAccount->text());
}

void OverviewPage::showLockStaking(bool status)
{
    //ui->unlockStakingButton->setVisible(status);
    //ui->unlockStakingButton->setIcon(QIcon(":/icons/lock_closed"));
}

void OverviewPage::btn_showQRClicked()
{
    QString address;
    QString label = "";

    address = ui->labelAddressAccount->text();


    SendCoinsRecipient info(address, label,
        0, "");
    ReceiveRequestDialog *dialog = new ReceiveRequestDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setInfo(info);
    dialog->show();
}


OverviewPage::~OverviewPage()
{
    delete ui;
}

void OverviewPage::setNetworkStats(QString blockheight, QString diffPoW, QString diffPoS)
{
    //ui->label_Blockheight->setText(blockheight);
    //ui->label_Blockheight->setStyleSheet("QLabel { color:#00ff00; }");
    //ui->label_DiffPoW->setText(diffPoW);
    //ui->label_DiffPoS->setText(diffPoS);
}


void OverviewPage::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& stakingBalance, const CAmount& immatureBalance, const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance, const CAmount& coldStakingBalance)
{
    int unit = walletModel->getOptionsModel()->getDisplayUnit();
    currentBalance = balance;
    currentUnconfirmedBalance = unconfirmedBalance;
    currentStakingBalance = stakingBalance;
    currentColdStakingBalance = coldStakingBalance;
    currentImmatureBalance = immatureBalance;
    currentWatchOnlyBalance = watchOnlyBalance;
    currentWatchUnconfBalance = watchUnconfBalance;
    currentWatchImmatureBalance = watchImmatureBalance;
    //ui->labelBalance->setText(BitcoinUnits::formatWithUnit(unit, balance, false, BitcoinUnits::separatorAlways));
    ui->labelUnconfirmed->setText(BitcoinUnits::format(unit, unconfirmedBalance, false, BitcoinUnits::separatorAlways));
    //ui->labelUnconfirmed->setStyleSheet("QLabel {font-size:16pt; color:#dceaed; }");
    //ui->labelStaking->setText(BitcoinUnits::formatWithUnit(unit, stakingBalance, false, BitcoinUnits::separatorAlways));
    //ui->labelImmature->setText(BitcoinUnits::formatWithUnit(unit, immatureBalance, false, BitcoinUnits::separatorAlways));
    ui->labelTotal->setText(BitcoinUnits::formatWithUnitGreen(unit,balance + unconfirmedBalance + stakingBalance, false, BitcoinUnits::separatorAlways));
    //ui->labelTotal->setText(BitcoinUnits::format(unit,balance + unconfirmedBalance + stakingBalance, false, BitcoinUnits::separatorAlways));
	//ui->labelTotal->setStyleSheet("QLabel {font-size:25pt; color:#dceaed; }");

    bool showStaking = stakingBalance != 0;

    //ui->labelStaking->setVisible(showStaking);
    //ui->labelStakingText->setVisible(showStaking);

    // only show immature (newly mined) balance if it's non-zero, so as not to complicate things
    // for the non-mining users
    bool showImmature = false;
    bool showWatchOnlyImmature = watchImmatureBalance != 0;

    // for symmetry reasons also show immature label when the watch-only one is shown
    //ui->labelImmature->setVisible(false);
    //ui->labelImmatureText->setVisible(false);
}

// show/hide watch-only labels
void OverviewPage::updateWatchOnlyLabels(bool showWatchOnly)
{

}

void OverviewPage::setStakingStatus(QString text, bool fStake)
{
    if (fStake) {
        ui->labelStakingStatus->setText(QString("ACTIVE"));
        ui->stakeingDot->setIcon(QIcon(":/icons/greendot"));
    }
    else {
        ui->labelStakingStatus->setText(QString("IDLE"));
        ui->stakeingDot->setIcon(QIcon(":/icons/reddot"));
    }
}

// Coin Control: button inputs -> show actual coin control dialog
void OverviewPage::show_txButtonClicked()
{
    Q_EMIT show_txClicked();
}

void OverviewPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if (model)
    {
        // Show warning if this is a prerelease version
        connect(model, SIGNAL(alertsChanged(QString)), this, SLOT(updateAlerts(QString)));
        updateAlerts(model->getStatusBarWarnings());
    }
}

void OverviewPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if (model && model->getOptionsModel())
    {
        // Set up transaction list
        filter.reset(new TransactionFilterProxy());
        filter->setSourceModel(model->getTransactionTableModel());
        filter->setLimit(NUM_ITEMS);
        filter->setDynamicSortFilter(true);
        filter->setSortRole(Qt::EditRole);
        filter->setShowInactive(false);
        filter->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        ui->listTransactions->setModel(filter.get());
        ui->listTransactions->setModelColumn(TransactionTableModel::ToAddress);

        // Keep up to date with wallet
        setBalance(model->getBalance(), model->getUnconfirmedBalance(), model->getStake(), model->getImmatureBalance(),
            model->getWatchBalance(), model->getWatchUnconfirmedBalance(), model->getWatchImmatureBalance(), model->getColdStakingBalance());
        connect(model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)), this, SLOT(setBalance(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)));
        connect(model, &WalletModel::balanceChanged, this, &OverviewPage::updateStakeReportbalanceChanged);

        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

        updateWatchOnlyLabels(model->haveWatchOnly());
        connect(model, SIGNAL(notifyWatchonlyChanged(bool)), this, SLOT(updateWatchOnlyLabels(bool)));
    }

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void OverviewPage::updateDisplayUnit()
{
    if (walletModel && walletModel->getOptionsModel())
    {
        if (currentBalance != -1)
            setBalance(currentBalance, currentUnconfirmedBalance, currentStakingBalance, currentImmatureBalance,
                currentWatchOnlyBalance, currentWatchUnconfBalance, currentWatchImmatureBalance, currentColdStakingBalance);

        // Update txdelegate->unit with the current unit
        txdelegate->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listTransactions->update();
    }
}

void OverviewPage::unlockWalletStaking()
{
    if (!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::UnlockStaking, this);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}

void OverviewPage::updateAlerts(const QString &warnings)
{
    this->ui->labelAlerts->setVisible(!warnings.isEmpty());
    this->ui->labelAlerts->setText(warnings);
}

void OverviewPage::showOutOfSyncWarning(bool fShow)
{
    ui->labelWalletStatus->setVisible(fShow);
}

using namespace boost;
using namespace std;

struct StakePeriodRange_T {
    int64_t Start;
    int64_t End;
    int64_t Total;
    int Count;
    string Name;
};

typedef vector<StakePeriodRange_T> vStakePeriodRange_T;

extern vStakePeriodRange_T PrepareRangeForStakeReport();
extern int GetsStakeSubTotal(vStakePeriodRange_T& aRange);

void OverviewPage::updateStakeReport(bool fImmediate = false)
{
    static vStakePeriodRange_T aRange;
    int nItemCounted = 0;

    if (fImmediate) nLastReportUpdate = 0;

    if (this->isHidden())
        return;

    int64_t nTook = GetTimeMillis();

    // Skip report recalc if not immediate or before 5 minutes from last
    if (GetTime() - nLastReportUpdate > 300)
    {

        aRange = PrepareRangeForStakeReport();

        // get subtotal calc
        nItemCounted = GetsStakeSubTotal(aRange);

        nLastReportUpdate = GetTime();

        nTook = GetTimeMillis() - nTook;

    }

    int64_t nTook2 = GetTimeMillis();

    int i = 30;

    int unit = walletModel->getOptionsModel()->getDisplayUnit();

    //ui->label24hStakingStats->setText(BitcoinUnits::formatWithUnit(unit, aRange[i++].Total, false, BitcoinUnits::separatorAlways));
    //ui->label7dStakingStats->setText(BitcoinUnits::formatWithUnit(unit, aRange[i++].Total, false, BitcoinUnits::separatorAlways));
    //ui->label30dStakingStats->setText(BitcoinUnits::formatWithUnit(unit, aRange[i++].Total, false, BitcoinUnits::separatorAlways));

}

void OverviewPage::updateStakeReportbalanceChanged(qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64)
{
    OverviewPage::updateStakeReportNow();
}

void OverviewPage::updateStakeReportNow()
{
    updateStakeReport(true);
}
