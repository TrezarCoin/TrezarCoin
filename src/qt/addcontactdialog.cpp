// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "addcontactdialog.h"
#include "ui_addcontactdialog.h"

#include "base58.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "qvalidatedlineedit.h"
#include "smessage.h"
#include "trezarmessage.h"
#include "walletmodel.h"

#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QDialogButtonBox>

AddContactDialog::AddContactDialog(const PlatformStyle *platformStyle, TrezarMessage* trezarMessage, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AddContactDialog),
    model(0),
    trezarMessage(trezarMessage),
    platformStyle(platformStyle)
{
    ui->setupUi(this);

    textChanged();

    GUIUtil::setupAddressWidget(ui->input_Address, this);

    connect(ui->input_Alias, &QLineEdit::textChanged, this, &AddContactDialog::textChanged);
    connect(ui->input_Address, &QValidatedLineEdit::textChanged, this, &AddContactDialog::textChanged);
    connect(ui->input_Pubkey, &QLineEdit::textChanged, this, &AddContactDialog::textChanged);

    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &AddContactDialog::accept);
    connect(ui->buttonBox, &QDialogButtonBox::rejected, this, &AddContactDialog::reject);
}

void AddContactDialog::setModel(WalletModel *model)
{
    this->model = model;
}

AddContactDialog::~AddContactDialog()
{
    delete ui;
}

void AddContactDialog::accept()
{
    std::string address = ui->input_Address->text().toStdString();
    std::string pubkey = ui->input_Pubkey->text().toStdString();

    int rv = SecureMsgAddAddress(address, pubkey);

    if (rv != 0 && rv != 4) { // 4 = alias already in DB, we'll just be updating the alias then
        std::string error;
        switch (rv)
        {
        case 2:
            error = "Pubkey is invalid.";
            break;
        case 3:
            error = "Pubkey does not match address.";
            break;
        case 5:
            error = "Address is invalid.";
            break;
        }

        QMessageBox::critical(this, tr("Error"),
            tr("%1").arg(QString::fromStdString(error)));

        return; // Return without closing
    } else {
        std::string alias = ui->input_Alias->text().toStdString();

        CKeyID hashKey;

        if (!CBitcoinAddress(address).GetKeyID(hashKey))
        {
            QMessageBox::critical(this, tr("Error"),
                tr("GetKeyID failed."));
            return;
        }

        if (!SecureMsgInsertAlias(hashKey, alias)) {
            QMessageBox::critical(this, tr("Error"),
                tr("Alias creation failed."));
        }

        // Let TrezarMessage know about the new or updated entry
        trezarMessage->addEntry(QString::fromStdString(address), QString::fromStdString(alias));
    }

    QDialog::accept();
}

void AddContactDialog::reject()
{
    clearFields();
    QDialog::reject();
}

void AddContactDialog::textChanged()
{
    // Validate input, set Ok button to enabled when acceptable
    bool acceptable = false;
    bool addressValid = false;
    bool pubKeyValid = false;
    bool addressMatchPubKey = false;

    if (!ui->input_Pubkey->text().isEmpty()) {
        std::string publicKey = ui->input_Pubkey->text().toStdString();

        std::vector<uint8_t> vchTest;
        DecodeBase58(publicKey, vchTest);
        CPubKey pubKey(vchTest);

        CPubKey pubKeyT(pubKey);
        if (pubKeyT.IsValid()) {
            pubKeyValid = true;
        }

        if (model->validateAddress(ui->input_Address->text())) {
            addressValid = true;

            std::string address = ui->input_Address->text().toStdString();
            CBitcoinAddress coinAddress(address);
            CKeyID keyIDT = pubKeyT.GetID();
            CBitcoinAddress addressT(keyIDT);

            if (addressT.ToString() == address) {
                addressMatchPubKey = true;
            }
        }
    }

    acceptable = !ui->input_Alias->text().isEmpty() && addressValid && pubKeyValid && addressMatchPubKey;
    if (acceptable) {
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(acceptable);
        ui->buttonBox->button(QDialogButtonBox::Ok)->setStyleSheet("background:#2d374f;"); 
    }
    else
    {
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
        ui->buttonBox->button(QDialogButtonBox::Ok)->setStyleSheet("background:#808080;");
    }
}


static void clearQLineEdit(QLineEdit* edit)
{
    edit->clear();
}

void AddContactDialog::clearFields()
{
    clearQLineEdit(ui->input_Alias);
    clearQLineEdit(ui->input_Address);
    clearQLineEdit(ui->input_Pubkey);
}
