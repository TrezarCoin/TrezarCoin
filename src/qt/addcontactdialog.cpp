// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "addcontactdialog.h"
#include "ui_addcontactdialog.h"
#include "platformstyle.h"

#include "guiconstants.h"
#include "walletmodel.h"

#include <QKeyEvent>
#include <QMessageBox>
#include <QPushButton>


AddContactDialog::AddContactDialog(const PlatformStyle *platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::AddContactDialog),
    model(0),
    platformStyle(platformStyle)
{
    ui->setupUi(this);

    textChanged();
    connect(ui->input_Alias, SIGNAL(textChanged(QString)), this, SLOT(textChanged()));
    connect(ui->input_Address, SIGNAL(textChanged(QString)), this, SLOT(textChanged()));
    connect(ui->input_Pubkey, SIGNAL(textChanged(QString)), this, SLOT(textChanged()));

    connect(ui->buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
    connect(ui->buttonBox, SIGNAL(rejected()), this, SLOT(reject()));

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
    //TODO LOGIC TO ADD THE CONTACT TO THE LIST VIEW
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
    acceptable = !ui->input_Alias->text().isEmpty() && !ui->input_Address->text().isEmpty() && !ui->input_Pubkey->text().isEmpty();
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(acceptable);
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