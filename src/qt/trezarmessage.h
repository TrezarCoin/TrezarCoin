#ifndef BITCOIN_QT_TREZARMESSAGE_H
#define BITCOIN_QT_TREZARMESSAGE_H

#include <set>

#include <QWidget>

class ClientModel;
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
    void setModel(WalletModel *model);
    void addEntry(QString address, QString alias);

private:
    std::string sendingAddress;
    std::string sendingPubKey;
    Ui::TrezarMessage *ui;
    ClientModel *clientModel;
    WalletModel *walletModel;
    const PlatformStyle *platformStyle;

    void populateUserList();
    void getMessages(std::set<Message, MessageCmp>& messages, bool unread = false);
    void addMessagesToConversation(std::set<Message, MessageCmp>& messages);

protected :
    void showEvent(QShowEvent* event);

private Q_SLOTS:
    void addContactButtonClicked();
    void addSendButtonClicked();
    void checkForNewMessages();
    void populateConversation();
    void showLocalAddress();
};

#endif // BITCOIN_QT_TrezarMessageG_H
