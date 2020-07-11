#include "trezarmessage.h"
#include "ui_trezarmessage.h"

#include "bitcoinunits.h"
#include "miner.h"
#include "bitcoingui.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "transactionfilterproxy.h"
#include "transactiontablemodel.h"
#include "walletmodel.h"
#include "walletframe.h"
#include "askpassphrasedialog.h"
#include "util.h"
#include "platformstyle.h"

// Add Contact
#include "addcontactdialog.h"

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

TrezarMessage::TrezarMessage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::TrezarMessage),
    clientModel(0),
    walletModel(0),
    model(0),
    platformStyle(platformStyle)
{
    ui->setupUi(this);
    connect(ui->pushButtonAddContact, SIGNAL(clicked()), this, SLOT(addContactButtonClicked()));
}

void TrezarMessage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
}

TrezarMessage::~TrezarMessage()
{
    delete ui;
}

void TrezarMessage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
}

void TrezarMessage::setModel(WalletModel *model)
{
    this->model = model;
}

// Add Contact: opens Contact Dialog to add Contacts for TrezarMessage
void TrezarMessage::addContactButtonClicked()
{
    AddContactDialog dlg(platformStyle);
    dlg.setModel(model);
    dlg.exec();
}


