#include "stakingdialog.h"
#include "ui_stakingdialog.h"

#include "bitcoinunits.h"
#include "miner.h"
#include "bitcoingui.h"
#include "coldstakingwizard.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "main.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactionfilterproxy.h"
#include "transactiontablemodel.h"
#include "walletmodel.h"
#include "walletframe.h"
#include "askpassphrasedialog.h"
#include "util.h"

//TransactionList

#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "wallet/wallet.h"
#include "askpassphrasedialog.h"
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
        
    }

    inline QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
    {
        return QSize(DECORATION_SIZE, DECORATION_SIZE);
    }

    int unit;
    const PlatformStyle *platformStyle;

};

StakingDialog::StakingDialog(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::StakingDialog),
    clientModel(0),
    walletModel(0),
    txdelegateStake(new TxViewDelegate(platformStyle, this))
{
    ui->setupUi(this);
    if (GetStaking())
    {
        ui->btn_Stake_On->setStyleSheet("font-size:20px; height:35px; color: white; background-color:#1b2234;");
        ui->btn_Stake_Off->setStyleSheet("font-size:20px; height:35px; color: #6d7886;");
    }
    else
    {
        ui->btn_Stake_On->setStyleSheet(" font-size:20px; height:35px; color: #6d7886; ");
        ui->btn_Stake_Off->setStyleSheet("font-size:20px; height:35px; color: white; background-color:#1b2234; ");
    }
    // Recent transactions
    ui->listStakes->setItemDelegate(txdelegateStake);
    ui->listStakes->setIconSize(QSize(DECORATION_SIZE, DECORATION_SIZE));
    ui->listStakes->setMinimumHeight(NUM_ITEMS * (DECORATION_SIZE + 2));
    ui->listStakes->setAttribute(Qt::WA_MacShowFocusRect, false);

    updateStakeReportNow();
    connect(ui->listStakes, SIGNAL(clicked(QModelIndex)), this, SLOT(handleTransactionClicked(QModelIndex)));
    connect(ui->btn_Stake_On, SIGNAL(clicked()), this, SLOT(btn_Stake_OnClicked()));
    connect(ui->btn_Stake_Off, SIGNAL(clicked()), this, SLOT(btn_Stake_OffClicked()));

    connect(ui->pushButtonColdStaking, &QPushButton::clicked, this, &StakingDialog::getColdStakingAddress);
}

void StakingDialog::setClientModel(ClientModel *model)
{
    this->clientModel = model;
}

StakingDialog::~StakingDialog()
{
    delete ui;
}

void StakingDialog::getColdStakingAddress()
{
    {
        LOCK(cs_main);
        if (!IsColdStakingEnabled(chainActive.Tip(), Params().GetConsensus())) {
            QMessageBox::warning(this, tr("Action not available"),
                                 "<qt>Cold Staking is not active yet.</qt>");
            return;
        }
    }

    ColdStakingWizard wizard;
    wizard.exec();
}

void StakingDialog::setStakingStatus(QString text, bool fStake)
{
    if (fStake) {
        ui->labelStakingStatus->setText(QString("Staking"));
        ui->stakeingDot->setIcon(QIcon(":/icons/greendot"));
        ui->btn_Stake_Off->setStyleSheet("  font-size:20px; height:35px; color: #6d7886; ");
        ui->btn_Stake_On->setStyleSheet("  font-size:20px; height:35px; color: white; background-color:#1b2234; ");
        ui->estimatedStakeTimeLabel->setText(text);
    }
    else {
        ui->labelStakingStatus->setText(QString("Staking"));
        ui->stakeingDot->setIcon(QIcon(":/icons/reddot"));
        ui->btn_Stake_On->setStyleSheet("  font-size:20px; height:35px; color: #6d7886; ");
        ui->btn_Stake_Off->setStyleSheet(" font-size:20px; height:35px; color: white; background-color:#1b2234; ");
        ui->estimatedStakeTimeLabel->setText("Staking Idle.");
    }

}

void StakingDialog::handleTransactionClicked(const QModelIndex &index)
{
    if (filterS)
        Q_EMIT transactionClicked(filterS->mapToSource(index));
}

void StakingDialog::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if (model && model->getOptionsModel())
    {
        // Set up transaction list
        filterS.reset(new TransactionFilterProxy());
        filterS->setTypeFilter(4);
        filterS->setSourceModel(model->getTransactionTableModel());
        filterS->setLimit(NUM_ITEMS);
        filterS->setDynamicSortFilter(true);
        filterS->setSortRole(Qt::EditRole);
        filterS->setShowInactive(false);
        filterS->sort(TransactionTableModel::Date, Qt::DescendingOrder);

        ui->listStakes->setModel(filterS.get());
        ui->listStakes->setModelColumn(TransactionTableModel::ToAddress);
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
    }
}

void StakingDialog::updateDisplayUnit()
{
    if (walletModel && walletModel->getOptionsModel())
    {
        // Update txdelegate->unit with the current unit
        txdelegateStake->unit = walletModel->getOptionsModel()->getDisplayUnit();

        ui->listStakes->update();
        updateStakeReportNow();
    }
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


void StakingDialog::updateStakeReport(bool fImmediate = false)
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
    ui->listStakes->update();

    ui->labelColdStaking->setText(BitcoinUnits::formatWithUnit(unit, walletModel->getColdStakingBalance(), false, BitcoinUnits::separatorAlways));
    ui->label24hStakingStats->setText(BitcoinUnits::formatWithUnit(unit, aRange[i++].Total, false, BitcoinUnits::separatorAlways));
    ui->label7dStakingStats->setText(BitcoinUnits::formatWithUnit(unit, aRange[i++].Total, false, BitcoinUnits::separatorAlways));
    ui->label30dStakingStats->setText(BitcoinUnits::formatWithUnit(unit, aRange[i++].Total, false, BitcoinUnits::separatorAlways));
    ui->labelAllTimeStakingStats->setText(BitcoinUnits::formatWithUnit(unit, aRange[i++].Total, false, BitcoinUnits::separatorAlways));

}

void StakingDialog::updateStakeReportbalanceChanged(qint64, qint64, qint64, qint64, qint64, qint64, qint64, qint64)
{
    StakingDialog::updateStakeReportNow();
}

void StakingDialog::updateStakeReportNow()
{
    updateStakeReport(true);
}


void StakingDialog::btn_Stake_OnClicked()
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
    if(fWalletUnlockStakingOnly || walletModel->getEncryptionStatus() == WalletModel::Unlocked)
    {

        ui->btn_Stake_Off->setStyleSheet("  font-size:20px; height:35px; color: #6d7886; ");
        ui->btn_Stake_On->setStyleSheet("  font-size:20px; height:35px; color: white; background-color:#1b2234; ");
        ui->labelStakingStatus->setText(QString("Staking"));
        ui->stakeingDot->setIcon(QIcon(":/icons/greendot"));

    }
}

void StakingDialog::btn_Stake_OffClicked()
{
    ui->btn_Stake_On->setStyleSheet("  font-size:20px; height:35px; color: #6d7886; ");
    ui->btn_Stake_Off->setStyleSheet(" font-size:20px; height:35px; color: white; background-color:#1b2234; ");
    ui->labelStakingStatus->setText(QString("Staking"));
    ui->stakeingDot->setIcon(QIcon(":/icons/reddot"));
}

void StakingDialog::setNetworkStats(QString blockheight, QString diffPoW, QString diffPoS)
{
    ui->label_DiffPoW->setText(diffPoW);
    ui->label_DiffPoS->setText(diffPoS);
}



