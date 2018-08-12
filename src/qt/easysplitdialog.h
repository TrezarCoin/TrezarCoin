#ifndef EASYSPLITDIALOG_H
#define EASYSPLITDIALOG_H

#include <QDialog>
#include <QString>

namespace Ui {
    class EasySplitDialog;
}
class WalletModel;
class EasySplitEntry;
class SendCoinsRecipient;

QT_BEGIN_NAMESPACE
class QUrl;
QT_END_NAMESPACE

/** Dialog for sending bitcoins */
class EasySplitDialog : public QDialog
{
    Q_OBJECT

public:
    explicit EasySplitDialog(QWidget *parent = 0);
    ~EasySplitDialog();

    void setModel(WalletModel *model);

    /** Set up the tab chain manually, as Qt messes up the tab chain by default in some cases (issue https://bugreports.qt-project.org/browse/QTBUG-10907).
     */
    QWidget *setupTabChain(QWidget *prev);

    void pasteEntry(const SendCoinsRecipient &rv);
    bool handleURI(const QString &uri);

public slots:
    void clear();
    void reject();
    void accept();
    EasySplitEntry *addEntry();
    void updateRemoveEnabled();
    void setBalance(qint64 balance, qint64 stake, qint64 unconfirmed, qint64 immature);

private:
    Ui::EasySplitDialog *ui;
    WalletModel *model;
    bool fNewRecipientAllowed;

private slots:
    void on_sendButton_clicked();
    void removeEntry(EasySplitEntry* entry);
    void updateDisplayUnit();
    void coinControlFeatureChanged(bool);
    void coinControlButtonClicked();
    void coinControlChangeChecked(int);
    void coinControlChangeEdited(const QString &);
    void coinControlUpdateLabels();
    void coinControlClipboardQuantity();
    void coinControlClipboardAmount();
    void coinControlClipboardFee();
    void coinControlClipboardAfterFee();
    void coinControlClipboardBytes();
    void coinControlClipboardPriority();
    void coinControlClipboardLowOutput();
    void coinControlClipboardChange();
};

#endif // EASYSPLITDIALOG_H
