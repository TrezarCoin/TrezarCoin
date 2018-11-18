// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "easysplitentry.h"
#include "ui_easysplitentry.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "walletmodel.h"

#include <QApplication>
#include <QClipboard>

EasySplitEntry::EasySplitEntry(const PlatformStyle *platformStyle, QWidget *parent) :
    QStackedWidget(parent),
    ui(new Ui::EasySplitEntry),
    model(0),
    platformStyle(platformStyle)
{
    ui->setupUi(this);

    ui->addressBookButton->setIcon(platformStyle->SingleColorIcon(":/icons/address-book"));
    //ui->pasteButton->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
    ui->deleteButton->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));
    ui->deleteButton_is->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));
    ui->deleteButton_s->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));

    setCurrentWidget(ui->SendCoins);

    if (platformStyle->getUseExtraSpacing())
        ui->payToEasySplitLayout->setSpacing(4);
#if QT_VERSION >= 0x040700
    //ui->addAsLabel->setPlaceholderText(tr("Enter a label for this address to add it to your address book"));
#endif

    // normal bitcoin address field
    GUIUtil::setupAddressWidget(ui->payToEasySplit, this);
    // just a label for displaying bitcoin address(es)
    ui->payToEasySplit_is->setFont(GUIUtil::fixedPitchFont());

    // Connect signals
    connect(ui->payAmountEasySplit, SIGNAL(valueChanged()), this, SIGNAL(payAmountChanged()));
    connect(ui->checkboxSubtractFeeFromAmount, SIGNAL(toggled(bool)), this, SIGNAL(subtractFeeFromAmountChanged()));
    connect(ui->deleteButton, SIGNAL(clicked()), this, SLOT(deleteClicked()));
    connect(ui->deleteButton_is, SIGNAL(clicked()), this, SLOT(deleteClicked()));
    connect(ui->deleteButton_s, SIGNAL(clicked()), this, SLOT(deleteClicked()));
}

EasySplitEntry::~EasySplitEntry()
{
    delete ui;
}

void EasySplitEntry::on_pasteButton_clicked()
{
    // Paste text from clipboard into recipient field
    ui->payToEasySplit->setText(QApplication::clipboard()->text());
}

void EasySplitEntry::on_addressBookButton_clicked()
{
    if(!model)
        return;
    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::EasySplitTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        ui->payToEasySplit->setText(dlg.getReturnValue());
        ui->payAmountEasySplit->setFocus();
        ui->listWidgetEasySplit->clear();
        ui->listWidgetEasySplit->addItems(dlg.getEasySplitList());
        //easySplitList.append(dlg.getEasySplitList());
    }
}

void EasySplitEntry::on_payToEasySplit_textChanged(const QString &address)
{
    updateLabel(address);
}

void EasySplitEntry::setModel(WalletModel *model)
{
    this->model = model;

    if (model && model->getOptionsModel())
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

    clear();
}

void EasySplitEntry::clear()
{
    // clear UI elements for normal payment
    ui->payToEasySplit->clear();
    //ui->addAsLabel->clear();
    ui->payAmountEasySplit->clear();
    ui->checkboxSubtractFeeFromAmount->setCheckState(Qt::Unchecked);
    ui->messageTextLabel->clear();
    ui->messageTextLabel->hide();
    ui->messageLabel->hide();
    // clear UI elements for unauthenticated payment request
    ui->payToEasySplit_is->clear();
    ui->memoTextLabel_is->clear();
    ui->payAmountEasySplit_is->clear();
    // clear UI elements for authenticated payment request
    ui->payToEasySplit_s->clear();
    ui->memoTextLabel_s->clear();
    ui->payAmountEasySplit_s->clear();

    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void EasySplitEntry::deleteClicked()
{
    Q_EMIT removeEntry(this);
}

bool EasySplitEntry::validate()
{
    if (!model)
        return false;

    // Check input validity
    bool retval = true;

    // Skip checks for payment request
    if (recipient.paymentRequest.IsInitialized())
        return retval;

    if (!model->validateAddress(ui->payToEasySplit->text()))
    {
        ui->payToEasySplit->setValid(false);
        retval = false;
    }

    if (!ui->payAmountEasySplit->validate())
    {
        retval = false;
    }

    // Sending a zero amount is invalid
    if (ui->payAmountEasySplit->value(0) <= 0)
    {
        ui->payAmountEasySplit->setValid(false);
        retval = false;
    }

    // Reject dust outputs:
    if (retval && GUIUtil::isDust(ui->payToEasySplit->text(), ui->payAmountEasySplit->value())) {
        ui->payAmountEasySplit->setValid(false);
        retval = false;
    }

    return retval;
}

void EasySplitEntry::getValueRecipients(QList<SendCoinsRecipient> &qLRecipients)
{
    for (int i = 0; i < ui->listWidgetEasySplit->count(); i++) {
        SendCoinsRecipient recipient;
        recipient.address = ui->listWidgetEasySplit->item(i)->text();
        recipient.amount = ui->payAmountEasySplit->value();
        qLRecipients.append(recipient);   
    }
}

SendCoinsRecipient EasySplitEntry::getValue()
{
    recipientCounter = 0;
    for (int i = 0; i < ui->listWidgetEasySplit->count(); i++) {
        recipientCounter++;
    }

    // Payment request
    if (recipient.paymentRequest.IsInitialized())
        return recipient;

    // Normal payment
    recipient.address = ui->payToEasySplit->text();
    //recipient.label = ui->addAsLabel->text();
    if(recipientCounter>=1) recipient.amount = ui->payAmountEasySplit->value() * recipientCounter;
    else recipient.amount = ui->payAmountEasySplit->value();
    recipient.message = ui->messageTextLabel->text();
    recipient.fSubtractFeeFromAmount = (ui->checkboxSubtractFeeFromAmount->checkState() == Qt::Checked);

    return recipient;
}

QWidget *EasySplitEntry::setupTabChain(QWidget *prev)
{
    QWidget::setTabOrder(prev, ui->payToEasySplit);
    //QWidget::setTabOrder(ui->payToEasySplit, ui->addAsLabel);
    //QWidget *w = ui->payAmountEasySplit->setupTabChain(ui->addAsLabel);
    //QWidget::setTabOrder(w, ui->checkboxSubtractFeeFromAmount);
    QWidget::setTabOrder(ui->checkboxSubtractFeeFromAmount, ui->addressBookButton);
    //QWidget::setTabOrder(ui->addressBookButton, ui->pasteButton);
    //QWidget::setTabOrder(ui->pasteButton, ui->deleteButton);
    return ui->deleteButton;
}

void EasySplitEntry::setValue(const SendCoinsRecipient &value)
{
    recipient = value;

    if (recipient.paymentRequest.IsInitialized()) // payment request
    {
        if (recipient.authenticatedMerchant.isEmpty()) // unauthenticated
        {
            ui->payToEasySplit_is->setText(recipient.address);
            ui->memoTextLabel_is->setText(recipient.message);
            ui->payAmountEasySplit_is->setValue(recipient.amount);
            ui->payAmountEasySplit_is->setReadOnly(true);
            setCurrentWidget(ui->SendCoins_UnauthenticatedPaymentRequest);
        }
        else // authenticated
        {
            ui->payToEasySplit_s->setText(recipient.authenticatedMerchant);
            ui->memoTextLabel_s->setText(recipient.message);
            ui->payAmountEasySplit_s->setValue(recipient.amount);
            ui->payAmountEasySplit_s->setReadOnly(true);
            setCurrentWidget(ui->SendCoins_AuthenticatedPaymentRequest);
        }
    }
    else // normal payment
    {
        // message
        ui->messageTextLabel->setText(recipient.message);
        ui->messageTextLabel->setVisible(!recipient.message.isEmpty());
        ui->messageLabel->setVisible(!recipient.message.isEmpty());

        //ui->addAsLabel->clear();
        ui->payToEasySplit->setText(recipient.address); // this may set a label from addressbook
        //if (!recipient.label.isEmpty()) // if a label had been set from the addressbook, don't overwrite with an empty label
            //ui->addAsLabel->setText(recipient.label);
        ui->payAmountEasySplit->setValue(recipient.amount);
    }
}

void EasySplitEntry::setAddress(const QString &address)
{
    ui->payToEasySplit->setText(address);
    ui->payAmountEasySplit->setFocus();
}

bool EasySplitEntry::isClear()
{
    return ui->payToEasySplit->text().isEmpty() && ui->payToEasySplit_is->text().isEmpty() && ui->payToEasySplit_s->text().isEmpty();
}

void EasySplitEntry::setFocus()
{
    ui->payToEasySplit->setFocus();
}

void EasySplitEntry::updateDisplayUnit()
{
    if(model && model->getOptionsModel())
    {
        // Update payAmountEasySplit with the current unit
        ui->payAmountEasySplit->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
        ui->payAmountEasySplit_is->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
        ui->payAmountEasySplit_s->setDisplayUnit(model->getOptionsModel()->getDisplayUnit());
    }
}

bool EasySplitEntry::updateLabel(const QString &address)
{
    if(!model)
        return false;

    // Fill in label from address book, if address has an associated label
    QString associatedLabel = model->getAddressTableModel()->labelForAddress(address);
    if(!associatedLabel.isEmpty())
    {
        //ui->addAsLabel->setText(associatedLabel);
        return true;
    }

    return false;
}
