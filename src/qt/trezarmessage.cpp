#include "trezarmessage.h"
#include "ui_trezarmessage.h"

#include "addcontactdialog.h"
#include "addressbookpage.h"
#include "platformstyle.h"
#include "wallet/wallet.h"
#include "walletmodel.h"
#include "util.h"
#include "utiltime.h"

#include <iomanip>

#include <QCheckBox>
#include <QLabel>
#include <QLineEdit>
#include <QListWidgetItem>
#include <QMenu>
#include <QMessageBox>
#include <QPainter>
#include <QPainterPath>
#include <QPushButton>
#include <QScrollArea>
#include <QSettings>
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

TrezarMessage::TrezarMessage(const PlatformStyle *platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::TrezarMessage),
    walletModel(0),
    platformStyle(platformStyle)
{
    ui->setupUi(this);

    QSettings settings;

    // Hidden option to remove cleared aliases
    if (GetBoolArg("-clearaliases", false)) {
        settings.remove("SecureMessageGUIRemovedAddresses");
    } else {
        // Get removed addresses before populating user list
        blockedAddresses = settings.value("SecureMessageGUIRemovedAddresses").value<QList<QVariant>>();
    }

    // Set address to send messages from
    setSendingAddress();

    // Populate list of users
    populateUserList();

    // Set delegate for user_list for bespoke drawing
    ui->user_list->setItemDelegate(new UserAliasDelegate());

    connect(ui->input_text, &QLineEdit::returnPressed, ui->send_button, &QPushButton::click);
    connect(ui->user_list, &QListWidget::itemClicked, this, &TrezarMessage::populateConversation);
    connect(ui->user_list->itemDelegate(), &QAbstractItemDelegate::commitData, this, &TrezarMessage::renameAlias);
    connect(ui->user_list, &QListWidget::customContextMenuRequested, this, &TrezarMessage::userListContextMenu);

    // Style
    ui->message_widget->setStyleSheet("QListWidget { background: gray; }");
    ui->conversation_controls_widget->setStyleSheet("background-color: lightgray;");
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

    // Check new messages every second
    auto *timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &TrezarMessage::checkForNewMessages);
    timer->start(1000);
}

TrezarMessage::~TrezarMessage()
{
    delete ui;
}

void TrezarMessage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
}

void TrezarMessage::on_get_address_clicked()
{
    QDialog* popup = new QDialog();
    auto verticalLayout = new QVBoxLayout(popup);
    QString str = QString("Address:\n%1\n\nPublic Key:\n%2").arg(QString::fromStdString(sendingAddress)).arg(QString::fromStdString(sendingPubKey));
    QLabel* address = new QLabel(str);
    address->setTextInteractionFlags(Qt::TextSelectableByMouse);
    verticalLayout->addWidget(address);
    popup->exec();
}

void TrezarMessage::displayContactInfo()
{
    QList<QListWidgetItem *> items = ui->user_list->selectedItems();

    if (items.count() != 1) {
        return;
    }

    QDialog* popup = new QDialog();
    popup->setWindowTitle("Contact Information");
    auto verticalLayout = new QVBoxLayout(popup);
    std::string contact(items[0]->data(Qt::ToolTipRole).toString().toStdString());
    std::string publicKey;

    if (SecureMsgGetLocalPublicKey(contact, publicKey) != 0) {
        CBitcoinAddress coinAddress(contact);
        CKeyID keyID;
        if (!coinAddress.GetKeyID(keyID)) {
            return;
        }

        CPubKey cpkFromDB;
        if (SecureMsgGetStoredKey(keyID, cpkFromDB) != 0) {
            return;
        }

        if (!cpkFromDB.IsValid() || !cpkFromDB.IsCompressed()) {
            return;
        }

        publicKey = EncodeBase58(cpkFromDB.begin(), cpkFromDB.end());
    }

    QString str = QString("Address:\n%1\n\nPublic Key:\n%2").arg(QString::fromStdString(contact)).arg(QString::fromStdString(publicKey));
    QLabel* address = new QLabel(str);
    address->setTextInteractionFlags(Qt::TextSelectableByMouse);
    verticalLayout->addWidget(address);
    popup->exec();
}

// Add Contact: opens Contact Dialog to add Contacts for TrezarMessage
void TrezarMessage::on_add_contact_clicked()
{
    AddContactDialog dlg(platformStyle, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void TrezarMessage::on_send_button_clicked()
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

void TrezarMessage::on_choose_address_clicked()
{
    if(!walletModel || !walletModel->getAddressTableModel())
        return;

    AddressBookPage dlg(platformStyle, AddressBookPage::ForSelection, AddressBookPage::ReceivingTab, nullptr);
    dlg.setModel(walletModel->getAddressTableModel());
    if(dlg.exec())
    {
        QString address{dlg.getReturnValue()};
        std::string sendingAddressTemp{address.toStdString()};
        std::string sendingPubKeyTemp;

        if (CBitcoinAddress{sendingAddressTemp}.IsValid() && SecureMsgGetLocalPublicKey(sendingAddressTemp, sendingPubKeyTemp) == 0) {
            sendingAddress = sendingAddressTemp;
            sendingPubKey = sendingPubKeyTemp;

            QSettings settings;
            settings.setValue(QString::fromStdString(settingsAddress), QString::fromStdString(sendingAddress));

            // Repopulate conversation with new sending address
            populateConversation();
        }
    }
}

void TrezarMessage::deleteConversation(std::string addrFrom)
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

    // Delete incoming messages
    std::string sPrefix("im");
    leveldb::Iterator* it = secureMsgDB.pdb->NewIterator(leveldb::ReadOptions());
    while (secureMsgDB.NextSmesg(it, sPrefix, chKey, smsgStored))
    {
        uint32_t nPayload = smsgStored.vchMessage.size() - SMSG_HDR_LEN;
        if (SecureMsgDecrypt(false, smsgStored.sAddrTo, &smsgStored.vchMessage[0], &smsgStored.vchMessage[SMSG_HDR_LEN], nPayload, msg) != 0) {
            continue;
        }

        if (msg.sFromAddress == addrFrom && smsgStored.sAddrTo == sendingAddress) {
            secureMsgDB.EraseSmesg(chKey);
        }
    }
    delete it;

    // Delete outgoing messages
    sPrefix = "sm";
    it = secureMsgDB.pdb->NewIterator(leveldb::ReadOptions());
    while (secureMsgDB.NextSmesg(it, sPrefix, chKey, smsgStored))
    {
        uint32_t nPayload = smsgStored.vchMessage.size() - SMSG_HDR_LEN;
        if (SecureMsgDecrypt(false, smsgStored.sAddrOutbox, &smsgStored.vchMessage[0], &smsgStored.vchMessage[SMSG_HDR_LEN], nPayload, msg) != 0) {
            continue;
        }

        if (msg.sFromAddress == sendingAddress && smsgStored.sAddrTo == addrFrom) {
            secureMsgDB.EraseSmesg(chKey);
        }
    }
    delete it;

    secureMsgDB.TxnCommit();
}

void TrezarMessage::on_remove_contact_clicked()
{
    QList<QListWidgetItem *> items = ui->user_list->selectedItems();

    if (items.count() != 1) {
        return;
    }

    QCheckBox *cb = new QCheckBox("Permanently delete messages");
    QMessageBox msgBox(QMessageBox::Question, "Confirm Action", "Are you sure you want to remove this contact?", QMessageBox::Yes | QMessageBox::No, this);
    msgBox.setDefaultButton(QMessageBox::No);
    msgBox.setIcon(QMessageBox::Question);
    msgBox.setCheckBox(cb);

    bool delete_messages = false;

    QObject::connect(cb, &QCheckBox::stateChanged, [&](int state){
        if (static_cast<Qt::CheckState>(state) == Qt::CheckState::Checked) {
            delete_messages = true;
        }
    });

    int reply = msgBox.exec();

    if (reply != QMessageBox::Yes) {
        return;
    }

    QString addrFrom = items[0]->data(Qt::ToolTipRole).toString();

    if (delete_messages) {
        deleteConversation(addrFrom.toStdString());
    }

    // Update removed addresses
    blockedAddresses.push_back(addrFrom);
    QSettings settings;
    settings.setValue("SecureMessageGUIRemovedAddresses", QVariant::fromValue(blockedAddresses));

    delete ui->user_list->takeItem(ui->user_list->row(items[0]));

    populateConversation();
}

void TrezarMessage::on_clear_conversation_clicked()
{
    QList<QListWidgetItem *> items = ui->user_list->selectedItems();

    if (items.count() != 1) {
        return;
    }

    QMessageBox::StandardButton reply = QMessageBox::question(this, "Confirm Action", "Are you sure you want to delete this conversation?");

    if (reply == QMessageBox::No) {
        return;
    }

    std::string addrFrom = items.at(0)->data(Qt::ToolTipRole).toString().toStdString();

    deleteConversation(addrFrom);

    populateConversation();
}

void TrezarMessage::setSendingAddress()
{
    // Get the same address shown on the front page
    CPubKey pubKey;
    pwalletMain->GetAccountPubkey(pubKey, "", false);
    sendingAddress = CBitcoinAddress(pubKey.GetID()).ToString();
    settingsAddress = sendingAddress;

    // Add wallet addresses to secure messaging
    SecureMsgAddWalletAddress(sendingAddress);

    // Get matching pubkey
    SecureMsgGetLocalPublicKey(sendingAddress, sendingPubKey);

    QSettings settings;
    bool add_to_settings = true;
    if (settings.contains(QString::fromStdString(sendingAddress))) {
        std::string sendingAddressTemp = settings.value(QString::fromStdString(settingsAddress)).toString().toStdString();
        std::string sendingPubKeyTemp;

        if (SecureMsgGetLocalPublicKey(sendingAddressTemp, sendingPubKeyTemp) == 0) {
            sendingAddress = sendingAddressTemp;
            sendingPubKey = sendingPubKeyTemp;

            add_to_settings = false;
        }
    }

    if (add_to_settings) {
        settings.setValue(QString::fromStdString(settingsAddress), QString::fromStdString(sendingAddress));
    }

    // Scan buckets for messages
    SecureMsgScanBuckets();
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

    ui->conversation_controls_widget->hide();

    QWidget::showEvent(event);
}

void TrezarMessage::populateConversation()
{
    ui->message_widget->clear();

    if (ui->user_list->selectedItems().count() == 1) {
        ui->conversation_controls_widget->show();

        std::set<Message, MessageCmp> messages;
        checkMessages(messages);

        if (messages.size()) {
            addMessagesToConversation(messages);
        }
    } else {
        ui->conversation_controls_widget->hide();
    }
}

void TrezarMessage::renameAlias(QWidget *editor)
{
    QList<QListWidgetItem *> items = ui->user_list->selectedItems();

    if (items.count() != 1) {
        return;
    }

    std::string alias = reinterpret_cast<QLineEdit*>(editor)->text().toStdString();
    std::string address = items[0]->data(Qt::ToolTipRole).toString().toStdString();

    CKeyID hashKey;

    if (!CBitcoinAddress(address).GetKeyID(hashKey))
    {
        QMessageBox::critical(this, tr("Error"),
                              tr("Failed to save new name."));
        return;
    }

    if (!SecureMsgInsertAlias(hashKey, alias)) {
        QMessageBox::critical(this, tr("Error"),
                              tr("Failed to save new name."));
    }
}

void TrezarMessage::userListContextMenu(const QPoint& pos)
{
    QList<QListWidgetItem *> items = ui->user_list->selectedItems();

    if (items.count() != 1) {
        return;
    }

    populateConversation();

    QPoint global_pos = ui->user_list->mapToGlobal(pos);

    QMenu user_list_menu;
    user_list_menu.addAction("Clear Conversation",  this, &TrezarMessage::on_clear_conversation_clicked);
    user_list_menu.addAction("Contact Information",  this, &TrezarMessage::displayContactInfo);
    user_list_menu.addAction("Remove Contact",  this, &TrezarMessage::on_remove_contact_clicked);
    user_list_menu.addAction("Rename", this, &TrezarMessage::editUserListItem);
    user_list_menu.exec(global_pos);
}

void TrezarMessage::editUserListItem()
{
    QList<QListWidgetItem *> items = ui->user_list->selectedItems();

    if (items.count() != 1) {
        return;
    }

    ui->user_list->editItem(items[0]);
}

void TrezarMessage::checkForNewMessages()
{
    std::set<Message, MessageCmp> messages;
    checkMessages(messages, true);

    if (messages.size()) {
        addMessagesToConversation(messages);
    }
}

void TrezarMessage::checkMessages(std::set<Message, MessageCmp>& messages, bool unread)
{
    std::map<std::string, std::string> aliases;
    if (!SecureMsgGetAllAliases(aliases)) {
        return;
    }

    QList<QListWidgetItem *> items = ui->user_list->selectedItems();
    std::string addrFrom;
    if (items.count() == 1) {
        addrFrom = items[0]->data(Qt::ToolTipRole).toString().toStdString();
    }

    // Find messages from unknown users
    {
        LOCK(cs_smsgDB);
        SecMsgDB secureMsgDB;

        if (!secureMsgDB.Open("cr+")) {
            return;
        }

        unsigned char chKey[18];
        SecMsgStored smsgStored;
        MessageData msg;

        // Keep track of whether we have unread messages
        bool localUnread{false};

        // Count unread addresses per address
        std::map<std::string, int> unreadCount;

        secureMsgDB.TxnBegin();

        // Incoming mail
        std::string sPrefix("im");
        leveldb::Iterator* it = secureMsgDB.pdb->NewIterator(leveldb::ReadOptions());
        while (secureMsgDB.NextSmesg(it, sPrefix, chKey, smsgStored))
        {
            // Check if we only want unread mail
            if (unread && !(smsgStored.status & SMSG_MASK_UNREAD)) {
                continue;
            }

            uint32_t nPayload = smsgStored.vchMessage.size() - SMSG_HDR_LEN;
            if (SecureMsgDecrypt(false, smsgStored.sAddrTo, &smsgStored.vchMessage[0], &smsgStored.vchMessage[SMSG_HDR_LEN], nPayload, msg) != 0) {
                continue;
            }

            // Make sure address is not removed user, has to be manually added.
            if (blockedAddresses.contains(QString::fromStdString(msg.sFromAddress))) {
                continue;
            }

            // New message alert if new message not from current conversation but to our sending address
            if (msg.sFromAddress != addrFrom && smsgStored.sAddrTo == sendingAddress && smsgStored.status & SMSG_MASK_UNREAD) {
                // Alert user of new message
                localUnread = true;
                if (!this->unreadMessages) {
                    this->unreadMessages = true;
                    Q_EMIT message(tr("New Messages"), tr("You have new messages."), CClientUIInterface::MSG_INFORMATION);
                }

                // Keep count of new messages
                ++unreadCount[msg.sFromAddress];
            }

            // If message from unknown alias add new alias contact
            if (smsgStored.sAddrTo == sendingAddress && aliases.count(msg.sFromAddress) == 0) {
                CBitcoinAddress coinAddress{msg.sFromAddress};

                if (!coinAddress.IsValid()) {
                    continue;
                }

                CKeyID keyID;
                if (!coinAddress.GetKeyID(keyID)) {
                    continue;
                }

                std::string new_user{"New Contact"};
                if (!SecureMsgInsertAlias(keyID, new_user)) {
                    continue;
                }

                QListWidgetItem* item = new QListWidgetItem(ui->user_list);
                item->setText(QString::fromStdString(new_user));
                item->setData(Qt::ToolTipRole, QString::fromStdString(msg.sFromAddress));
                item->setSizeHint(QSize(item->sizeHint().width(), 35));
                item->setFlags(item->flags() | Qt::ItemIsEditable);
            }
            else if (!addrFrom.empty() && msg.sFromAddress == addrFrom && smsgStored.sAddrTo == sendingAddress) { // Add to open conversation
                messages.insert({smsgStored.timeReceived, msg.sFromAddress, smsgStored.sAddrTo, std::string((char*)&msg.vchMessage[0])});

                // Mark as read
                if (smsgStored.status & SMSG_MASK_UNREAD) {
                    smsgStored.status &= ~SMSG_MASK_UNREAD;
                    secureMsgDB.WriteSmesg(chKey, smsgStored);
                }
            }
        }
        delete it;

        secureMsgDB.TxnCommit();

        // Reset unread status if no unread messages were found
        if (this->unreadMessages && !localUnread) {
            this->unreadMessages = false;
        } else {
            // store num of unread messages for use in delegate
            for(int i = 0; i < ui->user_list->count(); ++i)
            {
                ui->user_list->item(i)->setData(Qt::UserRole, unreadCount[ui->user_list->item(i)->data(Qt::ToolTipRole).toString().toStdString()]);
            }
        }

        // Outgoing mail
        // For unread we are only checking incoming mail to add to an existing conversation,
        // we already know what we are sending without checking the outbox.
        if (!addrFrom.empty() && !unread) {
            sPrefix = "sm";
            it = secureMsgDB.pdb->NewIterator(leveldb::ReadOptions());
            while (secureMsgDB.NextSmesg(it, sPrefix, chKey, smsgStored))
            {
                uint32_t nPayload = smsgStored.vchMessage.size() - SMSG_HDR_LEN;
                if (SecureMsgDecrypt(false, smsgStored.sAddrOutbox, &smsgStored.vchMessage[0], &smsgStored.vchMessage[SMSG_HDR_LEN], nPayload, msg) != 0) {
                    continue;
                }

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

        // Set time text std::string time = DateTimeStrFormat("%d %B %Y %H:%M", msg.time);
        const time_t time = msg.time;
        std::stringstream timeString;
        timeString << std::put_time(localtime(&time), "%d %b %Y %H:%M");
        auto* message_time = new QLabel(QString::fromStdString(timeString.str()));
        message_time->setAlignment(Qt::AlignRight);
        QFont small_font{message_time->font()};
        small_font.setPointSize(8);
        message_time->setFont(small_font);

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
        if (blockedAddresses.contains(QString::fromStdString(pair.first))) {
            continue;
        }

        QListWidgetItem* item = new QListWidgetItem(ui->user_list);
        item->setText(QString::fromStdString(pair.second));
        item->setData(Qt::ToolTipRole, QString::fromStdString(pair.first));
        item->setSizeHint(QSize(item->sizeHint().width(), 35));
        item->setFlags(item->flags() | Qt::ItemIsEditable);
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
        item->setFlags(item->flags() | Qt::ItemIsEditable);

        // Contact manually added, removed from removed contacts if present
        if (blockedAddresses.contains(address)) {
            blockedAddresses.removeAll(address);

            QSettings settings;
            settings.setValue("SecureMessageGUIRemovedAddresses", QVariant::fromValue(blockedAddresses));
        }
    }
}

void UserAliasDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    auto pen = painter->pen();
    auto font = painter->font();
    QString alias{index.data(Qt::DisplayRole).toString()};
    int newMessageCount{index.data(Qt::UserRole).toInt()};
    QRect newMessageRect;
    QString newMessageCountString;
    QFontMetrics fm(font);
    int pixelsWide = fm.width(alias);
    int newMessageIconWidth{0};

    // Set new message variables if new messafe present
    if (newMessageCount > 0) {
        if (newMessageCount > 999) {
            newMessageCountString = QString("999+");
        } else {
            newMessageCountString = QString::number(newMessageCount);
        }

        newMessageIconWidth = fm.width(newMessageCountString) + 10;
        newMessageRect = QRect(option.rect.width() - newMessageIconWidth - 5, option.rect.y() + 5, newMessageIconWidth, 25);
    }

    // Elide alias if too long
    int newMessageSpacing{15};
    if (newMessageCount > 0 && pixelsWide > option.rect.width() - newMessageIconWidth - newMessageSpacing) // With new message icon
    {
        alias = fm.elidedText(alias, Qt::ElideRight, option.rect.width() - newMessageIconWidth - newMessageSpacing);
    }
    else if (pixelsWide > option.rect.width() - newMessageSpacing) // Without new message icon
    {
        alias = fm.elidedText(alias, Qt::ElideRight, option.rect.width() - newMessageSpacing);
    }

    // Set antialiasing
    painter->setRenderHint(QPainter::Antialiasing);

    // If item selected change background colour and pen colour
    if (option.state & QStyle::State_Selected) {
        painter->setPen(Qt::white);
        painter->fillRect(option.rect, QColor("#419fd9"));
    }

    // Write alias
    painter->drawText(option.rect.x() + 5, option.rect.y(), option.rect.width(), option.rect.height(), Qt::AlignVCenter|Qt::AlignLeft, alias);

    // Draw new message icon if new messages are present
    if (newMessageCount > 0) {
        QPainterPath path;
        path.addRoundedRect(newMessageRect, 8, 8);
        painter->fillPath(path, Qt::darkGray);

        painter->setPen(Qt::white);
        auto bold = painter->font();
        bold.setBold(true);
        painter->setFont(bold);
        painter->drawText(newMessageRect, Qt::AlignCenter, newMessageCountString);
    }

    // Restore original pen for drawing of next item
    painter->setPen(pen);
    painter->setFont(font);
}

QSize UserAliasDelegate::sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const
{
    return QStyledItemDelegate::sizeHint(option, index);
}
