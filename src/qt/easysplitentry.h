#ifndef EASYSPLITENTRY_H
#define EASYSPLITENTRY_H

#include <QFrame>
#include <QStringList>
#include <QAbstractListModel>
#include <QStringListModel>
#include <QListWidget>

namespace Ui {
    class EasySplitEntry;
}
class WalletModel;
class SendCoinsRecipient;
class EasySplitDialog;

QT_BEGIN_NAMESPACE
class QTableView;
class QItemSelection;
class QSortFilterProxyModel;
class QMenu;
class QModelIndex;
class QStringList;
QT_END_NAMESPACE

/** A single entry in the dialog for sending bitcoins. */
class EasySplitEntry : public QFrame
{
    Q_OBJECT

public:
    explicit EasySplitEntry(QWidget *parent = 0);
    ~EasySplitEntry();

    void setModel(WalletModel *model);
    bool validate();
    SendCoinsRecipient getValue();
    void getValueRecipients(QList<SendCoinsRecipient> &qLRecipients);
    QStringListModel easyModel;

    /** Return whether the entry is still empty and unedited */
    bool isClear();

    void setValue(const SendCoinsRecipient &value);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

    void setFocus();

public slots:
    void setRemoveEnabled(bool enabled);
    void clear();

signals:
    void removeEntry(EasySplitEntry *entry);
    void payAmountEasySplitChanged();

private slots:
    void on_deleteButton_clicked();
    void on_payToEasySplit_textChanged(const QString &address);
    void on_addressBookButton_clicked();
    void on_pasteButton_clicked();
    void updateDisplayUnit();
    
private:
    Ui::EasySplitEntry *ui;
    WalletModel *model;
};

#endif // EasySplitENTRY_H
