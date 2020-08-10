#include "trezarmessage.h"
#include "ui_trezarmessage.h"

#include "addcontactdialog.h"
#include "clientmodel.h"
#include "platformstyle.h"
#include "wallet/wallet.h"
#include "walletmodel.h"
#include "util.h"
#include "utiltime.h"

#include <QLabel>
#include <QLineEdit>
#include <QListWidgetItem>
#include <QMessageBox>
#include <QPushButton>
#include <QScrollArea>
#include <QThread>
#include <QTimer>
#include <QVBoxLayout>

struct Message {
    int64_t time;
    std::string from;
    std::string to;
    std::string text;
};

struct MessageCmp {
    bool operator()(const Message& lhs, const Message& rhs) const {
        return lhs.time < rhs.time;
    }
};

static bool firstRun = true;

TrezarMessage::TrezarMessage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::TrezarMessage),
    clientModel(0),
    walletModel(0),
    platformStyle(platformStyle)
{
    ui->setupUi(this);

    populateUserList();

    connect(ui->pushButtonAddContact, &QPushButton::clicked, this, &TrezarMessage::addContactButtonClicked);
    connect(ui->pushButtonGetAddress, &QPushButton::clicked, this, &TrezarMessage::showLocalAddress);
    connect(ui->send_button, &QPushButton::clicked, this, &TrezarMessage::addSendButtonClicked);
    connect(ui->input_text, &QLineEdit::returnPressed, ui->send_button, &QPushButton::click);
    connect(ui->user_list, &QListWidget::itemClicked, this, &TrezarMessage::populateConversation);

    // Check new messages every second
    auto *timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &TrezarMessage::checkForNewMessages);
    timer->start(1000);

    ui->user_list->setStyleSheet("QListWidget { background: #232c41; color: #000; font-size: 20px; padding: 2px; border-radius:10px; }"
                                 "QListWidget::item { border-bottom: 1px solid #b9dbe8; color: #b9dbe8; } "
                                 "QListWidget::item:selected { background: #95bcf2; color: #000; } "
                                 "QToolTip { background: #fff; color: #000; }");

    ui->message_widget->setStyleSheet("QScrollBar { margin: 0; width:10px; background: #10131a; border-radius: 4px; }"
                                      "QScrollBar::add-line:vertical { height: 0px; }"
                                      "QScrollBar::sub-line:vertical { height: 0px; }"
                                      "QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { height: 0px; }"
                                      "QScrollBar::handle { border: 0px; background: #384157; border-radius: 4px; }"
                                      "QMenu::item { color: gray; }");
}

TrezarMessage::~TrezarMessage()
{
    delete ui;
}

void TrezarMessage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
}

void TrezarMessage::showLocalAddress()
{
    QDialog* popup = new QDialog();
    auto verticalLayout = new QVBoxLayout(popup);
    QString str = QString("Address:\n%1\n\nPublic Key:\n%2").arg(QString::fromStdString(sendingAddress)).arg(QString::fromStdString(sendingPubKey));
    QLabel* address = new QLabel(str);
    address->setTextInteractionFlags(Qt::TextSelectableByMouse);
    verticalLayout->addWidget(address);
    popup->exec();
}

// Add Contact: opens Contact Dialog to add Contacts for TrezarMessage
void TrezarMessage::addContactButtonClicked()
{
    AddContactDialog dlg(platformStyle, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void TrezarMessage::addSendButtonClicked()
{
    std::string message = ui->input_text->text().toStdString();

    if (!message.empty()) {
        QList<QListWidgetItem *> items = ui->user_list->selectedItems();

        if (items.count() != 1) {
            return;
        }

        std::string addrTo = items.at(0)->data(Qt::ToolTipRole).toString().toStdString();

        std::string sError;
        if (SecureMsgSend(sendingAddress, addrTo, message, sError) != 0) {
            QMessageBox::critical(this, tr("Error"),
                tr("%1").arg(QString::fromStdString(sError)));

            return;
        }

        // Add message to conversation
        std::set<Message, MessageCmp> messages;
        messages.insert({GetTime(), sendingAddress, addrTo, message});
        addMessagesToConversation(messages);

        ui->input_text->clear();
    }
}

void TrezarMessage::showEvent(QShowEvent* event)
{
    // Need to unlock to read and encrypt messages
    if (!fWalletUnlockStakingOnly) {
        fWalletUnlockStakingOnly = true;
        WalletModel::UnlockContext ctx(walletModel->requestUnlock());
        if (!ctx.isValid())
        {
            this->close();
            return;
        }
    }

    if (firstRun) {
        firstRun = false;

        // Get the same address shown on the front page
        CPubKey pubKey;
        pwalletMain->GetAccountPubkey(pubKey, "", false);
        sendingAddress = CBitcoinAddress(pubKey.GetID()).ToString();

        // Add wallet addresses to secure messaging
        SecureMsgAddWalletAddress(sendingAddress);

        // Get matching pubkey
        SecureMsgGetLocalPublicKey(sendingAddress, sendingPubKey);
    }

    // Scan buckets for messages
    SecureMsgScanBuckets();

    QWidget::showEvent(event);
}

void TrezarMessage::populateConversation()
{
    ui->message_widget->clear();

    std::set<Message, MessageCmp> messages;
    getMessages(messages);

    if (messages.size()) {
        addMessagesToConversation(messages);
    }
}

void TrezarMessage::checkForNewMessages()
{
    std::set<Message, MessageCmp> messages;
    getMessages(messages, true);

    if (messages.size()) {
        addMessagesToConversation(messages);
    }
}

void TrezarMessage::getMessages(std::set<Message, MessageCmp>& messages, bool unread)
{
    QList<QListWidgetItem *> items = ui->user_list->selectedItems();

    if (items.count() != 1) {
        return;
    }

    std::string addrFrom = items.at(0)->data(Qt::ToolTipRole).toString().toStdString();

    {
        LOCK(cs_smsgDB);
        SecMsgDB secureMsgDB;

        if (!secureMsgDB.Open("cr+")) {
            return;
        }

        unsigned char chKey[18];
        SecMsgStored smsgStored;
        MessageData msg;

        secureMsgDB.TxnBegin();

        // Incoming mail
        std::string sPrefix("im");
        leveldb::Iterator* it = secureMsgDB.pdb->NewIterator(leveldb::ReadOptions());
        while (secureMsgDB.NextSmesg(it, sPrefix, chKey, smsgStored))
        {
            if (unread && !(smsgStored.status & SMSG_MASK_UNREAD)) {
                continue;
            }

            uint32_t nPayload = smsgStored.vchMessage.size() - SMSG_HDR_LEN;
            SecureMsgDecrypt(false, smsgStored.sAddrTo, &smsgStored.vchMessage[0], &smsgStored.vchMessage[SMSG_HDR_LEN], nPayload, msg);

            if (msg.sFromAddress == addrFrom && smsgStored.sAddrTo == sendingAddress) {
                messages.insert({smsgStored.timeReceived, msg.sFromAddress, smsgStored.sAddrTo, std::string((char*)&msg.vchMessage[0])});
            }

            // Mark as read
            smsgStored.status &= ~SMSG_MASK_UNREAD;
            secureMsgDB.WriteSmesg(chKey, smsgStored);
        }
        delete it;

        secureMsgDB.TxnCommit();

        // Outgoing mail
        // For unread we are only checking incoming mail to add to an existing conversatio,
        // we already know what we are sending without checking the outbox.
        if (!unread) {
            sPrefix = "sm";
            it = secureMsgDB.pdb->NewIterator(leveldb::ReadOptions());
            while (secureMsgDB.NextSmesg(it, sPrefix, chKey, smsgStored))
            {
                uint32_t nPayload = smsgStored.vchMessage.size() - SMSG_HDR_LEN;
                SecureMsgDecrypt(false, smsgStored.sAddrOutbox, &smsgStored.vchMessage[0], &smsgStored.vchMessage[SMSG_HDR_LEN], nPayload, msg);

                if (msg.sFromAddress == sendingAddress && smsgStored.sAddrTo == addrFrom) {
                    messages.insert({smsgStored.timeReceived, msg.sFromAddress, smsgStored.sAddrTo, std::string((char*)&msg.vchMessage[0])});
                }
            }
            delete it;
        }
    }
}

void TrezarMessage::addMessagesToConversation(std::set<Message, MessageCmp>& messages)
{
    for (auto& msg : messages) {
        auto* message_widget = new QWidget();
        auto* message_layout = new QVBoxLayout(message_widget);
        auto* message_text = new QLabel(QString::fromStdString(msg.text));
        message_text->setWordWrap(true);

        std::string time = DateTimeStrFormat("%d %B %Y %H:%M", msg.time);
        auto* message_time = new QLabel(QString::fromStdString(time));
        message_time->setAlignment(Qt::AlignRight);
        message_time->setStyleSheet("QLabel { color : #bdbdbd; }");

        message_layout->addWidget(message_text);
        message_layout->addWidget(message_time);
        message_layout->setSizeConstraint( QLayout::SetFixedSize );
        message_widget->setLayout(message_layout);

        if (sendingAddress == msg.to) {
            message_widget->setStyleSheet("QWidget { background: #fff; border-radius: 5px; }"
                                          "QMenu::item { color: gray; background: white; }"
                                          "QMenu::item:selected { color: white; background: gray; }");
        } else {
            message_widget->setStyleSheet("QWidget { background: #effdde; border-radius: 5px; }"
                                          "QMenu::item { color: gray; background: white; }"
                                          "QMenu::item:selected { color: white; background: gray; }");
        }

        auto* item = new QListWidgetItem();
        item->setSizeHint( message_widget->sizeHint() );
        ui->message_widget->addItem(item);
        ui->message_widget->setItemWidget(item, message_widget);
    }

    if (messages.size()) {
        ui->message_widget->scrollToBottom();
    }
}

void TrezarMessage::populateUserList()
{
    std::map<std::string, std::string> aliases;
    if (!SecureMsgGetAllAliases(aliases)) {
        QMessageBox::critical(this, tr("Error"),
            tr("Failed to populate user list."));
        return;
    }

    for (auto pair : aliases)
    {
        QListWidgetItem* item = new QListWidgetItem(ui->user_list);
        item->setText(QString::fromStdString(pair.second));
        item->setData(Qt::ToolTipRole, QString::fromStdString(pair.first));
        item->setSizeHint(QSize(item->sizeHint().width(), 35));
    }
}

void TrezarMessage::addEntry(QString address, QString alias)
{
    bool found = false;
    for (int i = 0; i < ui->user_list->count(); ++i) {
        QListWidgetItem* item = ui->user_list->item(i);

        if (item->data(Qt::ToolTipRole) == address) {
            item->setText(alias);
            found = true;
        }
    }

    if (!found) {
        QListWidgetItem* item = new QListWidgetItem(ui->user_list);
        item->setText(alias);
        item->setData(Qt::ToolTipRole, address);
        item->setSizeHint(QSize(item->sizeHint().width(), 35));
    }
}
