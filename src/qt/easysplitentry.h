// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_EASYSPLITENTRY_H
#define BITCOIN_QT_EASYSPLITENTRY_H

#include "walletmodel.h"

#include <QStackedWidget>
#include <QFrame>
#include <QStringList>
#include <QAbstractListModel>
#include <QStringListModel>
#include <QListWidget>

class WalletModel;
class PlatformStyle;
class SendCoinsRecipient;
class EasySplitDialog;

namespace Ui {
    class EasySplitEntry;
}

QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
class QStringList;
QT_END_NAMESPACE

/**
 * A single entry in the dialog for sending bitcoins.
 * Stacked widget, with different UIs for payment requests
 * with a strong payee identity.
 */
class EasySplitEntry : public QStackedWidget
{
    Q_OBJECT

public:
    explicit EasySplitEntry(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~EasySplitEntry();

    void setModel(WalletModel *model);
    bool validate();
    SendCoinsRecipient getValue();
    void getValueRecipients(QList<SendCoinsRecipient> &qLRecipients);
    QStringListModel easyModel;

    /** Return whether the entry is still empty and unedited */
    bool isClear();

    void setValue(const SendCoinsRecipient &value);
    void setAddress(const QString &address);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases
     *  (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

    void setFocus();

public Q_SLOTS:
    void clear();

Q_SIGNALS:
    void removeEntry(EasySplitEntry *entry);
    void payAmountChanged();
    void subtractFeeFromAmountChanged();

private Q_SLOTS:
    void deleteClicked();
    void on_payToEasySplit_textChanged(const QString &address);
    void on_addressBookButton_clicked();
    void on_pasteButton_clicked();
    void updateDisplayUnit();

private:
    SendCoinsRecipient recipient;
    Ui::EasySplitEntry *ui;
    WalletModel *model;
    const PlatformStyle *platformStyle;
    int recipientCounter;

    bool updateLabel(const QString &address);
};

#endif // BITCOIN_QT_SENDCOINSENTRY_H
