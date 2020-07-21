// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "receivecoinsdialog.h"
#include "ui_receivecoinsdialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "receiverequestdialog.h"
#include "recentrequeststablemodel.h"
#include "walletmodel.h"
#include "base58.h"
#include "pubkey.h"
#include "wallet/wallet.h"

#include <QAction>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>
#include <QClipboard>

ReceiveCoinsDialog::ReceiveCoinsDialog(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ReceiveCoinsDialog),
    columnResizingFixer(0),
    model(0),
    platformStyle(platformStyle)
{
    ui->setupUi(this);

    // UI things

    ui->reqLabel->setPlaceholderText(tr("Enter Address Label"));
    ui->reqMessage->setPlaceholderText(tr("Enter a message up to 140 characters"));
    
    // context menu actions
    QAction *copyLabelAction = new QAction(tr("Copy label"), this);
    QAction *copyMessageAction = new QAction(tr("Copy message"), this);
    QAction *copyAmountAction = new QAction(tr("Copy amount"), this);

    // context menu
    contextMenu = new QMenu(this);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyMessageAction);
    contextMenu->addAction(copyAmountAction);

    //SetAccountAddress
    CPubKey pubKey;
    pwalletMain->GetAccountPubkey(pubKey, "", false);
    ui->labelAddressAccount->setText(QString::fromStdString(CBitcoinAddress(pubKey.GetID()).ToString()));

    // context menu signals
    //connect(ui->recentRequestsView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showMenu(QPoint)));
    connect(copyLabelAction, SIGNAL(triggered()), this, SLOT(copyLabel()));
    connect(copyMessageAction, SIGNAL(triggered()), this, SLOT(copyMessage()));
    connect(copyAmountAction, SIGNAL(triggered()), this, SLOT(copyAmount()));
    connect(ui->btnCopyAddressAccount, SIGNAL(clicked()), this, SLOT(btn_copyClipboardClicked()));

    connect(ui->labelCopyAddress, SIGNAL(clicked()), this, SLOT(on_labelCopyAddress_clicked()));

    connect(ui->clearButton, SIGNAL(clicked()), this, SLOT(clear()));
}

void ReceiveCoinsDialog::setModel(WalletModel *model)
{
    this->model = model;

    //SetBalance
    setBalance(model->getBalance(), model->getUnconfirmedBalance(), model->getStake(), model->getImmatureBalance(),
        model->getWatchBalance(), model->getWatchUnconfirmedBalance(), model->getWatchImmatureBalance(), model->getColdStakingBalance());
    connect(model, SIGNAL(balanceChanged(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)), this, SLOT(setBalance(CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount, CAmount)));
    connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
    updateDisplayUnit();

    if(model && model->getOptionsModel())
    {
        model->getRecentRequestsTableModel()->sort(RecentRequestsTableModel::Date, Qt::DescendingOrder);
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
        updateDisplayUnit();

        QTableView* tableView = ui->recentRequestsView;

        tableView->verticalHeader()->hide();
        tableView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        tableView->setModel(model->getRecentRequestsTableModel());
        tableView->setAlternatingRowColors(true);
        tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
        tableView->setSelectionMode(QAbstractItemView::ContiguousSelection);
        tableView->setColumnWidth(RecentRequestsTableModel::Date, DATE_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Label, LABEL_COLUMN_WIDTH);
        tableView->setColumnWidth(RecentRequestsTableModel::Amount, AMOUNT_MINIMUM_COLUMN_WIDTH);

        connect(tableView->selectionModel(),
            SIGNAL(selectionChanged(QItemSelection, QItemSelection)), this,
            SLOT(recentRequestsView_selectionChanged(QItemSelection, QItemSelection)));
        // Last 2 columns are set by the columnResizingFixer, when the table geometry is ready.
        columnResizingFixer = new GUIUtil::TableViewLastColumnResizingFixer(tableView, AMOUNT_MINIMUM_COLUMN_WIDTH, DATE_COLUMN_WIDTH, this);
    }
}

ReceiveCoinsDialog::~ReceiveCoinsDialog()
{
    delete ui;
}

void ReceiveCoinsDialog::clear()
{
    ui->reqAmount->clear();
    ui->reqLabel->setText("");
    ui->reqMessage->setText("");
    updateDisplayUnit();
}

void ReceiveCoinsDialog::reject()
{
    clear();
}

void ReceiveCoinsDialog::btn_copyClipboardClicked()
{
    GUIUtil::setClipboard(ui->labelAddressAccount->text());
}

void ReceiveCoinsDialog::accept()
{
    clear();
}

void ReceiveCoinsDialog::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        ui->reqAmount->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
        ui->label_tzc->setText(BitcoinUnits::unitGreen(model->getOptionsModel()->getDisplayUnit()));
        setBalance(model->getBalance(), 0, 0, 0, 0, 0, 0, 0);
    }
}

void ReceiveCoinsDialog::on_receiveButton_clicked()
{
    if(!model || !model->getOptionsModel() || !model->getAddressTableModel() || !model->getRecentRequestsTableModel())
        return;

    QString address;
    QString label = ui->reqLabel->text();

    /* Generate new receiving address */
    address = model->getAddressTableModel()->addRow(AddressTableModel::Receive, label, "");
    
        
    SendCoinsRecipient info(address, label,
    ui->reqAmount->value(), ui->reqMessage->text());
    ReceiveRequestDialog *dialog = new ReceiveRequestDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModel(model->getOptionsModel());
    dialog->setInfo(info);
    dialog->show();
    clear();

    /* Store request for later reference */
    model->getRecentRequestsTableModel()->addNewRequest(info);
}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void ReceiveCoinsDialog::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    columnResizingFixer->stretchColumnWidth(RecentRequestsTableModel::Message);
}

void ReceiveCoinsDialog::keyPressEvent(QKeyEvent *event)
{
    if (event->key() == Qt::Key_Return)
    {
        // press return -> submit form
        if (ui->reqLabel->hasFocus() || ui->reqAmount->hasFocus() || ui->reqMessage->hasFocus())
        {
            event->ignore();
            on_receiveButton_clicked();
            return;
        }
    }

    this->QDialog::keyPressEvent(event);
}

void ReceiveCoinsDialog::on_recentRequestsView_doubleClicked(const QModelIndex &index)
{
    const RecentRequestsTableModel *submodel = model->getRecentRequestsTableModel();
    ReceiveRequestDialog *dialog = new ReceiveRequestDialog(this);
    dialog->setModel(model->getOptionsModel());
    dialog->setInfo(submodel->entry(index.row()).recipient);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->show();
}

void ReceiveCoinsDialog::recentRequestsView_selectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
{
    // Enable Show/Remove buttons only if anything is selected.
    bool enable = !ui->recentRequestsView->selectionModel()->selectedRows().isEmpty();
    //ui->showRequestButton->setEnabled(enable);
    //ui->removeRequestButton->setEnabled(enable);
}

void ReceiveCoinsDialog::on_labelCopyAddress_clicked()
{
    // Paste text from clipboard into label field
    ui->reqLabel->setText(QApplication::clipboard()->text());
}

// copy column of selected row to clipboard
void ReceiveCoinsDialog::copyColumnToClipboard(int column)
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return;
    // correct for selection mode ContiguousSelection
    QModelIndex firstIndex = selection.at(0);
    GUIUtil::setClipboard(model->getRecentRequestsTableModel()->data(firstIndex.child(firstIndex.row(), column), Qt::EditRole).toString());
}

// context menu
void ReceiveCoinsDialog::showMenu(const QPoint &point)
{
    if(!model || !model->getRecentRequestsTableModel() || !ui->recentRequestsView->selectionModel())
        return;
    QModelIndexList selection = ui->recentRequestsView->selectionModel()->selectedRows();
    if(selection.empty())
        return;
    contextMenu->exec(QCursor::pos());
}

// context menu action: copy labelta
void ReceiveCoinsDialog::copyLabel()
{
    copyColumnToClipboard(RecentRequestsTableModel::Label);
}

// context menu action: copy message
void ReceiveCoinsDialog::copyMessage()
{
    copyColumnToClipboard(RecentRequestsTableModel::Message);
}

// context menu action: copy amount
void ReceiveCoinsDialog::copyAmount()
{
    copyColumnToClipboard(RecentRequestsTableModel::Amount);
}

void ReceiveCoinsDialog::on_receiveQR_clicked()
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

// display balance
void ReceiveCoinsDialog::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& stakingBalance, const CAmount& immatureBalance,
    const CAmount& watchBalance, const CAmount& watchUnconfirmedBalance, const CAmount& watchImmatureBalance, const CAmount& coldStakingBalance)
{
    Q_UNUSED(unconfirmedBalance);
    Q_UNUSED(immatureBalance);
    Q_UNUSED(watchBalance);
    Q_UNUSED(watchUnconfirmedBalance);
    Q_UNUSED(watchImmatureBalance);
    Q_UNUSED(coldStakingBalance);

    if (model && model->getOptionsModel())
    {
        ui->labelBalance->setText(BitcoinUnits::formatWithUnitGreen(0, balance) + (model->getOptionsModel()->getDisplayUnit() != 0 ? (" (" + BitcoinUnits::formatWithUnitGreen(model->getOptionsModel()->getDisplayUnit(), balance) + ")") : ""));
    }
}

