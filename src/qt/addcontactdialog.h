// Copyright (c) 2011-2015 The Bitcoin Core developers
// Copyright (c) 2017-2020 Trezarcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_ADDCONTACTDIALOG_H
#define BITCOIN_QT_ADDCONTACTDIALOG_H

#include <QDialog>

class PlatformStyle;
class TrezarMessage;
class WalletModel;

namespace Ui {
    class AddContactDialog;
}

/** Multifunctional dialog to add Contacts to TrezarMessage.
 */
class AddContactDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AddContactDialog(const PlatformStyle *platformStyle, TrezarMessage *trezarMessage, QWidget *parent = 0);
    ~AddContactDialog();

    void setModel(WalletModel *model);
    void accept();
    void reject();

private:
    Ui::AddContactDialog *ui;
    WalletModel *model;
    TrezarMessage *trezarMessage;
    const PlatformStyle *platformStyle;

private Q_SLOTS:
    void textChanged();
    void clearFields();
};

#endif // BITCOIN_QT_ADDCONTACTDIALOG_H
