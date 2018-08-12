#include "easysplitentry.h"
#include "ui_easysplitentry.h"
#include "guiutil.h"
#include "bitcoinunits.h"
#include "addressbookpage.h"
#include "walletmodel.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"

#include <QApplication>
#include <QClipboard>

EasySplitEntry::EasySplitEntry(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::EasySplitEntry),
    model(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC
    ui->payToEasySplitLayout->setSpacing(4);
#endif
#if QT_VERSION >= 0x040700
    /* Do not move this to the XML file, Qt before 4.7 will choke on it */
    ui->payToEasySplit->setPlaceholderText(tr("Enter an Trezarcoin address (e.g. TninUHdJX1yfXoWLPcgf4NxWttZmyXixNR)"));
#endif
    setFocusPolicy(Qt::TabFocus);
    setFocusProxy(ui->payToEasySplit);

    GUIUtil::setupAddressWidget(ui->payToEasySplit, this);
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
    AddressBookPage dlg(AddressBookPage::ForSending, AddressBookPage::EasySplitTab, this);
    dlg.setModel(model->getAddressTableModel());
    if(dlg.exec())
    {
        ui->payToEasySplit->setText("Your Coins will be split on the Addresses below");
        ui->payAmountEasySplit->setFocus();
        ui->listWidgetEasySplit->clear();
        ui->listWidgetEasySplit->addItems(dlg.getEasySplitList());

    }
}

void EasySplitEntry::on_payToEasySplit_textChanged(const QString &address)
{
    if(!model)
        return;
    // Fill in label from address book, if address has an associated label
    QString associatedLabel = model->getAddressTableModel()->labelForAddress(address);
}

void EasySplitEntry::setModel(WalletModel *model)
{
    this->model = model;

    if(model && model->getOptionsModel())
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));

    connect(ui->payAmountEasySplit, SIGNAL(textChanged()), this, SIGNAL(payAmountEasySplitChanged()));

    clear();
}

void EasySplitEntry::setRemoveEnabled(bool enabled)
{
}

void EasySplitEntry::clear()
{
    ui->payToEasySplit->clear();
    ui->payAmountEasySplit->clear();
    ui->payToEasySplit->setFocus();
    // update the display unit, to not use the default ("BTC")
    updateDisplayUnit();
}

void EasySplitEntry::on_deleteButton_clicked()
{
    emit removeEntry(this);
}

bool EasySplitEntry::validate()
{
    // Check input validity
    bool retval = true;

    if(!ui->payAmountEasySplit->validate())
    {
        retval = false;
    }
    else
    {
        if(ui->payAmountEasySplit->value() <= 0)
        {
            // Cannot send 0 coins or less
            ui->payAmountEasySplit->setValid(false);
            retval = false;
        }
    }

    if(!ui->payToEasySplit->hasAcceptableInput() ||
       (model && !model->validateAddress(ui->payToEasySplit->text())))
    {
        ui->payToEasySplit->setValid(false);
        retval = false;
    }

    return retval;
}

void EasySplitEntry::getValueRecipients(QList<SendCoinsRecipient> &qLRecipients)
{
    for (int i = 0; i < ui->listWidgetEasySplit->count();i++) {

        SendCoinsRecipient rv;

        rv.address = ui->listWidgetEasySplit->item(i)->text();
        rv.amount = ui->payAmountEasySplit->value();
        qLRecipients.append(rv);
    }
}

SendCoinsRecipient EasySplitEntry::getValue()
{
    SendCoinsRecipient rv;

    rv.address = ui->payToEasySplit->text();
    rv.amount = ui->payAmountEasySplit->value();

    return rv;
}

QWidget *EasySplitEntry::setupTabChain(QWidget *prev)
{
    QWidget *tab;

    QWidget::setTabOrder(prev, ui->payToEasySplit);
    QWidget::setTabOrder(ui->payToEasySplit, ui->addressBookButton);
    QWidget::setTabOrder(ui->addressBookButton, ui->pasteButton);
    return tab;
}

void EasySplitEntry::setValue(const SendCoinsRecipient &value)
{
    ui->payToEasySplit->setText(value.address);
    ui->payAmountEasySplit->setValue(value.amount);
}

bool EasySplitEntry::isClear()
{
    return ui->payToEasySplit->text().isEmpty();
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
    }
}
