#ifndef BITCOIN_QT_TREZARMESSAGE_H
#define BITCOIN_QT_TREZARMESSAGE_H

#include <set>

#include <QStyledItemDelegate>
#include <QWidget>

struct Message;
struct MessageCmp;
class WalletModel;
class PlatformStyle;
class QVBoxLayout;

namespace Ui {
    class TrezarMessage;
}

class TrezarMessage : public QWidget
{
    Q_OBJECT

public:
    explicit TrezarMessage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~TrezarMessage();

    void setWalletModel(WalletModel *walletModel);
    void addEntry(QString address, QString alias);

private:
    // Front page address used as QSettings key
    std::string settingsAddress;

    // Address used as sending address
    std::string sendingAddress;
    std::string sendingPubKey;

    // Maintain set of removed addresses
    QList<QVariant> blockedAddresses;

    // Keep track of whether there are unread messages
    bool unreadMessages{false};

    Ui::TrezarMessage *ui;
    WalletModel *walletModel;
    const PlatformStyle *platformStyle;

    void addMessagesToConversation(std::set<Message, MessageCmp>& messages);
    void checkForNewMessages();
    void checkMessages(std::set<Message, MessageCmp>& messages, bool unread = false);
    void deleteConversation(std::string addrFrom);
    void displayContactInfo();
    void setSendingAddress();
    void populateUserList();

Q_SIGNALS:
    //! Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style);

protected :
    void showEvent(QShowEvent* event);

private Q_SLOTS:
    void editUserListItem();
    void populateConversation();
    void renameAlias(QWidget *editor);
    void userListContextMenu(const QPoint& pos);

    // Buttons
    void on_choose_address_clicked();
    void on_add_contact_clicked();
    void on_get_address_clicked();
    void on_send_button_clicked();
    void on_clear_conversation_clicked();
    void on_remove_contact_clicked();
};

class UserAliasDelegate : public QStyledItemDelegate
{
Q_OBJECT
public:
    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;
    QSize sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const override;
};

#endif // BITCOIN_QT_TrezarMessageG_H
