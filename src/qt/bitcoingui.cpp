// Copyright (c) 2011-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "bitcoingui.h"

#include "bitcoinunits.h"
#include "clientmodel.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "miner.h"
#include "net.h"
#include "networkstyle.h"
#include "notificator.h"
#include "openuridialog.h"
#include "optionsdialog.h"
#include "optionsmodel.h"
#include "platformstyle.h"
#include "rpcconsole.h"
#include "rpc/server.h"
#include "utilitydialog.h"
#include "walletmodel.h"
#include "wallet/rpcwallet.h"

#ifdef ENABLE_WALLET
#include "walletframe.h"
#include "walletmodel.h"
#include "walletview.h"
#include "wallet/wallet.h"
#endif // ENABLE_WALLET

#ifdef Q_OS_MAC
#include "macdockiconhandler.h"
#endif

#include "chainparams.h"
#include "init.h"
#include "miner.h"
#include "ui_interface.h"
#include "util.h"

#include <iostream>

#include <QAction>
#include <QApplication>
#include <QDateTime>
#include <QDesktopWidget>
#include <QDir>
#include <QDragEnterEvent>
#include <QFileDialog>
#include <QInputDialog>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QMimeData>
#include <QProgressBar>
#include <QProgressDialog>
#include <QPushButton>
#include <QSettings>
#include <QShortcut>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStyle>
#include <QTimer>
#include <QToolBar>
#include <QVBoxLayout>
#include <QWidget>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QUrl>
#include <QUrlQuery>
#include <QVariant>
#include <QJsonValue>
#include <QJsonDocument>
#include <QJsonObject>
#include <QVariantMap>
#include <QJsonArray>

#if QT_VERSION < 0x050000
#include <QTextDocument>
#include <QUrl>
#else
#include <QUrlQuery>
#endif

const std::string BitcoinGUI::DEFAULT_UIPLATFORM =
#if defined(Q_OS_MAC)
        "macosx"
#elif defined(Q_OS_WIN)
        "windows"
#else
        "other"
#endif
        ;

const QString BitcoinGUI::DEFAULT_WALLET = "~Default";

BitcoinGUI::BitcoinGUI(const PlatformStyle *platformStyle, const NetworkStyle *networkStyle, QWidget *parent) :
    QMainWindow(parent),
    clientModel(0),
    walletFrame(0),
    unitDisplayControl(0),
    labelEncryptionIcon(0),
    labelStakeMining(0),
    labelConnectionsIcon(0),
    labelBlocksIcon(0),
    labelStakingIcon(0),
    labelPrice(0),
    progressBarLabel(0),
    progressBar(0),
    progressDialog(0),
    appMenuBar(0),
    overviewAction(0),
    historyAction(0),
    quitAction(0),
    sendCoinsAction(0),
    sendCoinsMenuAction(0),
    usedSendingAddressesAction(0),
    usedReceivingAddressesAction(0),
    signMessageAction(0),
    verifyMessageAction(0),
    aboutAction(0),
    receiveCoinsAction(0),
    receiveCoinsMenuAction(0),
    toggleHideAction(0),
    encryptWalletAction(0),
    backupWalletAction(0),
    changePassphraseAction(0),
    aboutQtAction(0),
    openRPCConsoleAction(0),
    openAction(0),
    showHelpMessageAction(0),
    trayIcon(0),
    trayIconMenu(0),
    notificator(0),
    rpcConsole(0),
    helpMessageDialog(0),
    prevBlocks(0),
    spinnerFrame(0),
    unlockWalletAction(0),
    lockWalletAction(0),
    toggleStakingAction(0),
    easysplitAction(0),
    exportWalletAction(0),
    importWalletAction(0),
    stakingAction(0),
    emptyAction(0),
    quitMenuAction(0),
    settingsMenuAction(0),
    optionPageAction(0),
    trezarMessageAction(0),
    platformStyle(platformStyle)
{
    /* Open CSS when configured */
    this->setStyleSheet(GUIUtil::loadStyleSheet());

    GUIUtil::restoreWindowGeometry("nWindow", QSize(840, 600), this);
    QString windowTitle = tr(PACKAGE_NAME) + " - ";
#ifdef ENABLE_WALLET
    /* if compiled with wallet support, -disablewallet can still disable the wallet */
    enableWallet = !GetBoolArg("-disablewallet", false);
#else
    enableWallet = false;
#endif // ENABLE_WALLET
    if(enableWallet)
    {
        windowTitle += tr("Wallet");
    } else {
        windowTitle += tr("Node");
    }
    windowTitle += " " + networkStyle->getTitleAddText();
#ifndef Q_OS_MAC
    QApplication::setWindowIcon(networkStyle->getTrayAndWindowIcon());
    setWindowIcon(networkStyle->getTrayAndWindowIcon());
#else
    /*High DPI Displays can cause some issues fors scaling. AA_DisableHighDpiScaling attribute turns off all scaling. 
    This attribute should be removed if scaleing is needed. note:ui settings must support scaling correctly*/
    QApplication::setAttribute(Qt::AA_DisableHighDpiScaling);
    MacDockIconHandler::instance()->setIcon(networkStyle->getAppIcon());
#endif
    setWindowTitle(windowTitle);

#if defined(Q_OS_MAC) && QT_VERSION < 0x050000
    // This property is not implemented in Qt 5. Setting it has no effect.
    // A replacement API (QtMacUnifiedToolBar) is available in QtMacExtras.
    setUnifiedTitleAndToolBarOnMac(true);
#endif

    rpcConsole = new RPCConsole(platformStyle, 0);
    helpMessageDialog = new HelpMessageDialog(this, false);
#ifdef ENABLE_WALLET
    if(enableWallet)
    {
        /** Create wallet frame and make it the central widget */
        walletFrame = new WalletFrame(platformStyle, this);
        setCentralWidget(walletFrame);
    } else
#endif // ENABLE_WALLET
    {
        /* When compiled without wallet or -disablewallet is provided,
         * the central widget is the rpc console.
         */
        setCentralWidget(rpcConsole);
    }

    // Accept D&D of URIs
    setAcceptDrops(true);

    // Create actions for the toolbar, menu bar and tray/dock icon
    // Needs walletFrame to be initialized
    createActions();

    // Create application menu bar
    createMenuBar();

    // Create the toolbars
    createToolBars();

    // Create system tray icon and notification
    createTrayIcon(networkStyle);

    // Create status bar
    statusBar();

    // Disable size grip because it looks ugly and nobody needs it
    statusBar()->setSizeGripEnabled(false);

    // Status bar notification icons
    QFrame *frameBlocks = new QFrame();
    frameBlocks->setContentsMargins(0,0,0,0);
    frameBlocks->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    QHBoxLayout *frameBlocksLayout = new QHBoxLayout(frameBlocks);
    frameBlocksLayout->setContentsMargins(3,0,3,0);
    frameBlocksLayout->setSpacing(3);
    unitDisplayControl = new UnitDisplayStatusBarControl(platformStyle);
    labelEncryptionIcon = new QLabel();
    labelStakeMining = new QLabel();
    labelStakingIcon = new QLabel();
    labelPrice = new QLabel();
    labelConnectionsIcon = new QLabel();
    labelBlocksIcon = new QLabel();
    if(enableWallet)
    {
        frameBlocksLayout->addStretch();
        frameBlocksLayout->addWidget(labelStakingIcon);
        frameBlocksLayout->addStretch();
        frameBlocksLayout->addWidget(labelPrice);
        frameBlocksLayout->addStretch();
        frameBlocksLayout->addWidget(unitDisplayControl);
        frameBlocksLayout->addStretch();
        frameBlocksLayout->addWidget(labelEncryptionIcon);
        frameBlocksLayout->addStretch();
        frameBlocksLayout->addWidget(labelStakeMining);
    }
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelConnectionsIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelBlocksIcon);
    frameBlocksLayout->addStretch();

    if (GetBoolArg("-stakegen", true))
    {
        QTimer *timerStakingIcon = new QTimer(labelStakingIcon);
        connect(timerStakingIcon, SIGNAL(timeout()), this, SLOT(updateStakingStatus()));
        timerStakingIcon->start(60 * 1000);
        updateStakingStatus();
    }
    else
    {
        walletFrame->setStakingStatus(tr("Staking is turned off."),false);
    }

    // Progress bar and label for blocks download 
    placeholderLabel = new QLabel();
    placeholderLabel->setPixmap(platformStyle->SingleColorIcon(":/icons/spacer").pixmap(145, 40));
    placeholderLabel->setAlignment(Qt::AlignCenter);


    progressBarLabel = new QLabel();
    progressBarLabel->setVisible(false);
    progressBar = new GUIUtil::ProgressBar();
    progressBar->setAlignment(Qt::AlignCenter);
    progressBar->setVisible(false);
    progressBarIcon = new QLabel();
    progressBarIcon->setPixmap(platformStyle->SingleColorIcon(":/icons/sync_globe").pixmap(24, 24));

    // Override style sheet for progress bar for styles that have a segmented progress bar,
    // as they make the text unreadable (workaround for issue #1071)
    // See https://qt-project.org/doc/qt-4.8/gallery.html
    //QString curStyle = QApplication::style()->metaObject()->className();
    //if(curStyle == "QWindowsStyle" || curStyle == "QWindowsXPStyle")
    //{
    progressBar->setStyleSheet("QProgressBar { background-color: #1b2234; border: transparent; border-radius: 10px; padding: 1px; text-align: center; } QProgressBar::chunk { background: #39df7b; border-radius: 4px; margin: 4px; }");
    //}
    

    statusBar()->addWidget(progressBarIcon);
    statusBar()->addWidget(progressBarLabel);
    statusBar()->addWidget(placeholderLabel);
    statusBar()->addWidget(progressBar);
    statusBar()->addPermanentWidget(frameBlocks);
    

    // Install event filter to be able to catch status tip events (QEvent::StatusTip)
    this->installEventFilter(this);

    // Initially wallet actions should be disabled
    setWalletActionsEnabled(false);

    // Subscribe to notifications from core
    subscribeToCoreSignals();
}

BitcoinGUI::~BitcoinGUI()
{
    // Unsubscribe from notifications from core
    unsubscribeFromCoreSignals();

    GUIUtil::saveWindowGeometry("nWindow", this);
    if(trayIcon) // Hide tray icon, as deleting will let it linger until quit (on Ubuntu)
        trayIcon->hide();
#ifdef Q_OS_MAC
    delete appMenuBar;
    MacDockIconHandler::cleanup();
#endif

    delete rpcConsole;
}


void BitcoinGUI::createActions()
{

    QActionGroup *tabGroup = new QActionGroup(this);

    emptyAction = new QAction(platformStyle->SingleColorIcon(":/icons/spacerBlock"), tr(""), this);
    emptyAction->setCheckable(false);
    emptyAction->setEnabled(false);
    tabGroup->addAction(emptyAction);

    overviewAction = new QAction(platformStyle->SingleColorIcon(":/icons/overview_green"), tr("&Overview"), this);
    overviewAction->setStatusTip(tr("Show general overview of wallet"));
    overviewAction->setToolTip(overviewAction->statusTip());
    overviewAction->setCheckable(true);
    overviewAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_1));
    tabGroup->addAction(overviewAction);

    sendCoinsAction = new QAction(platformStyle->SingleColorIcon(":/icons/send"), tr("&Send"), this);
    sendCoinsAction->setStatusTip(tr("Send coins to a Trezarcoin address"));
    sendCoinsAction->setToolTip(sendCoinsAction->statusTip());
    sendCoinsAction->setCheckable(true);
    sendCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_2));
    tabGroup->addAction(sendCoinsAction);

    sendCoinsMenuAction = new QAction(platformStyle->SingleColorIcon(":/icons/send_menu"), sendCoinsAction->text(), this);
    sendCoinsMenuAction->setStatusTip(sendCoinsAction->statusTip());
    sendCoinsMenuAction->setToolTip(sendCoinsMenuAction->statusTip());

    receiveCoinsAction = new QAction(platformStyle->SingleColorIcon(":/icons/receive"), tr("&Receive"), this);
    receiveCoinsAction->setStatusTip(tr("Request payments (generates QR codes and trezarcoin: URIs)"));
    receiveCoinsAction->setToolTip(receiveCoinsAction->statusTip());
    receiveCoinsAction->setCheckable(true);
    receiveCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_3));
    tabGroup->addAction(receiveCoinsAction);

    receiveCoinsMenuAction = new QAction(platformStyle->SingleColorIcon(":/icons/receive_menu"), receiveCoinsAction->text(), this);
    receiveCoinsMenuAction->setStatusTip(receiveCoinsAction->statusTip());
    receiveCoinsMenuAction->setToolTip(receiveCoinsMenuAction->statusTip());

    toggleStakingAction = new QAction(platformStyle->TextColorIcon(":/icons/staking_off_menu"), tr("Toggle &Staking"), this);
    toggleStakingAction->setStatusTip(tr("Toggle Staking"));

    historyAction = new QAction(platformStyle->SingleColorIcon(":/icons/history"), tr("&Transactions"), this);
    historyAction->setStatusTip(tr("Browse transaction history"));
    historyAction->setToolTip(historyAction->statusTip());
    historyAction->setCheckable(true);
    historyAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_4));
    tabGroup->addAction(historyAction);

#ifdef ENABLE_WALLET
#ifdef ENABLE_SMESSAGE
    trezarMessageAction = new QAction(platformStyle->SingleColorIcon(":/icons/send"), tr("&Message"), this);
    trezarMessageAction->setStatusTip(tr("Send Messages"));
    trezarMessageAction->setToolTip(trezarMessageAction->statusTip());
    trezarMessageAction->setCheckable(true);
    historyAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_5));
    tabGroup->addAction(trezarMessageAction);
#endif // ENABLE_SMESSAGE
#endif // ENABLE_WALLET

    easysplitAction = new QAction(platformStyle->TextColorIcon(":/icons/send_menu"), tr("&EasySplit"), this);
    easysplitAction->setStatusTip(tr("Split your Coins easily"));
    easysplitAction->setToolTip(easysplitAction->statusTip());
    easysplitAction->setCheckable(true);
    tabGroup->addAction(easysplitAction);

    stakingAction = new QAction(platformStyle->SingleColorIcon(":/icons/staking_off"), tr("&Staking"), this);
    stakingAction->setStatusTip(tr("Show staking stats"));
    stakingAction->setToolTip(stakingAction->statusTip());
    stakingAction->setCheckable(true);
    tabGroup->addAction(stakingAction);

    optionPageAction = new QAction(platformStyle->SingleColorIcon(":/icons/settings"), tr("&Settings"), this);
    optionPageAction->setStatusTip(tr("Show Settings"));
    optionPageAction->setToolTip(optionPageAction->statusTip());
    optionPageAction->setCheckable(true);
    tabGroup->addAction(optionPageAction);

    settingsMenuAction = new QAction(platformStyle->TextColorIcon(":/icons/settings_menu"), optionPageAction->text(), this);
    settingsMenuAction->setStatusTip(optionPageAction->statusTip());
    settingsMenuAction->setToolTip(settingsMenuAction->statusTip());

    

#ifdef ENABLE_WALLET
    // These showNormalIfMinimized are needed because Send Coins and Receive Coins
    // can be triggered from the tray menu, and need to show the GUI to be useful.
    connect(overviewAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(overviewAction, SIGNAL(triggered()), this, SLOT(gotoOverviewPage()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(gotoSendCoinsPage()));
    connect(sendCoinsMenuAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sendCoinsMenuAction, SIGNAL(triggered()), this, SLOT(gotoSendCoinsPage()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(gotoReceiveCoinsPage()));
    connect(receiveCoinsMenuAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(receiveCoinsMenuAction, SIGNAL(triggered()), this, SLOT(gotoReceiveCoinsPage()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(gotoHistoryPage()));
    connect(toggleStakingAction, SIGNAL(triggered()), this, SLOT(toggleStaking()));
    connect(easysplitAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(easysplitAction, SIGNAL(triggered()), this, SLOT(gotoEasySplitPage()));
    connect(stakingAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(stakingAction, SIGNAL(triggered()), this, SLOT(gotoStakingPage()));

#ifdef ENABLE_SMESSAGE
    connect(trezarMessageAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(trezarMessageAction, SIGNAL(triggered()), this, SLOT(gotoTrezarMessage()));
#endif // ENABLE_SMESSAGE

    connect(optionPageAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(optionPageAction, SIGNAL(triggered()), this, SLOT(gotoSettingsPage()));
    connect(settingsMenuAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(settingsMenuAction, SIGNAL(triggered()), this, SLOT(gotoSettingsPage()));

#endif // ENABLE_WALLET

    quitAction = new QAction(platformStyle->SingleColorIcon(":/icons/logout"), tr("&Logout"), this);
    quitAction->setStatusTip(tr("Quit application"));
    quitAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Q));
    quitAction->setMenuRole(QAction::QuitRole);
    quitMenuAction = new QAction(platformStyle->TextColorIcon(":/icons/logout_menu"), quitAction->text(), this);
    quitMenuAction->setStatusTip(quitAction->statusTip());
    quitMenuAction->setToolTip(quitMenuAction->statusTip());
    quitMenuAction->setMenuRole(QAction::QuitRole);
    aboutAction = new QAction(platformStyle->TextColorIcon(":/icons/about"), tr("&About %1").arg(tr(PACKAGE_NAME)), this);
    aboutAction->setStatusTip(tr("Show information about %1").arg(tr(PACKAGE_NAME)));
    aboutAction->setMenuRole(QAction::AboutRole);
    aboutAction->setEnabled(false);
    aboutQtAction = new QAction(platformStyle->TextColorIcon(":/icons/about_qt"), tr("About &Qt"), this);
    aboutQtAction->setStatusTip(tr("Show information about Qt"));
    aboutQtAction->setMenuRole(QAction::AboutQtRole);
    toggleHideAction = new QAction(platformStyle->TextColorIcon(":/icons/about"), tr("&Show / Hide"), this);
    toggleHideAction->setStatusTip(tr("Show or hide the main Window"));

    encryptWalletAction = new QAction(platformStyle->TextColorIcon(":/icons/lock_closed"), tr("&Encrypt Wallet..."), this);
    encryptWalletAction->setStatusTip(tr("Encrypt the private keys that belong to your wallet"));
    encryptWalletAction->setCheckable(true);
    unlockWalletAction = new QAction(tr("&Unlock Wallet for Staking..."), this);
    unlockWalletAction->setToolTip(tr("Unlock wallet for Staking"));
    backupWalletAction = new QAction(platformStyle->TextColorIcon(":/icons/filesave"), tr("&Backup Wallet..."), this);
    backupWalletAction->setStatusTip(tr("Backup wallet to another location"));
    changePassphraseAction = new QAction(platformStyle->TextColorIcon(":/icons/key"), tr("&Change Passphrase..."), this);
    changePassphraseAction->setStatusTip(tr("Change the passphrase used for wallet encryption"));
    signMessageAction = new QAction(platformStyle->TextColorIcon(":/icons/edit"), tr("Sign &message..."), this);
    signMessageAction->setStatusTip(tr("Sign messages with your Trezarcoin addresses to prove you own them"));

    verifyMessageAction = new QAction(platformStyle->TextColorIcon(":/icons/verify"), tr("&Verify message..."), this);
    verifyMessageAction->setStatusTip(tr("Verify messages to ensure they were signed with specified Trezarcoin addresses"));

    //Export PrivKeys
    exportWalletAction = new QAction(platformStyle->TextColorIcon(":/icons/key_export"), tr("&Export keys"), this);
    exportWalletAction->setStatusTip(tr("Export your PrivateKeys and PublicKeys into a Textfile."));

    //Import PrivKeys
    importWalletAction = new QAction(platformStyle->TextColorIcon(":/icons/key_import"), tr("&Import keys"), this);
    importWalletAction->setStatusTip(tr("Import your PrivateKeys and PublicKeys from a Textfile."));

    openRPCConsoleAction = new QAction(platformStyle->TextColorIcon(":/icons/debugwindow"), tr("&Debug window"), this);
    openRPCConsoleAction->setStatusTip(tr("Open debugging and diagnostic console"));
    // initially disable the debug window menu item
    openRPCConsoleAction->setEnabled(false);

    usedSendingAddressesAction = new QAction(platformStyle->TextColorIcon(":/icons/address-book"), tr("&Sending addresses..."), this);
    usedSendingAddressesAction->setStatusTip(tr("Show the list of used sending addresses and labels"));
    usedReceivingAddressesAction = new QAction(platformStyle->TextColorIcon(":/icons/address-book"), tr("&Receiving addresses..."), this);
    usedReceivingAddressesAction->setStatusTip(tr("Show the list of used receiving addresses and labels"));

    openAction = new QAction(platformStyle->TextColorIcon(":/icons/open"), tr("Open &URI..."), this);
    openAction->setStatusTip(tr("Open a trezarcoin: URI or payment request"));

    showHelpMessageAction = new QAction(platformStyle->TextColorIcon(":/icons/info"), tr("&Command-line options"), this);
    showHelpMessageAction->setMenuRole(QAction::NoRole);
    showHelpMessageAction->setStatusTip(tr("Show the %1 help message to get a list with possible Trezarcoin command-line options").arg(tr(PACKAGE_NAME)));

    connect(quitAction, SIGNAL(triggered()), qApp, SLOT(quit()));
    connect(quitMenuAction, SIGNAL(triggered()), qApp, SLOT(quit()));
    connect(aboutAction, SIGNAL(triggered()), this, SLOT(aboutClicked()));
    connect(aboutQtAction, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
    connect(toggleHideAction, SIGNAL(triggered()), this, SLOT(toggleHidden()));
    connect(showHelpMessageAction, SIGNAL(triggered()), this, SLOT(showHelpMessageClicked()));
    connect(openRPCConsoleAction, SIGNAL(triggered()), this, SLOT(showDebugWindow()));
    // prevents an open debug window from becoming stuck/unusable on client shutdown
    connect(quitAction, SIGNAL(triggered()), rpcConsole, SLOT(hide()));
    connect(quitMenuAction, SIGNAL(triggered()), rpcConsole, SLOT(hide()));

#ifdef ENABLE_WALLET
    if(walletFrame)
    {
        connect(encryptWalletAction, SIGNAL(triggered(bool)), walletFrame, SLOT(encryptWallet(bool)));
        connect(unlockWalletAction, SIGNAL(triggered()), walletFrame, SLOT(unlockWalletStaking()));
        connect(backupWalletAction, SIGNAL(triggered()), walletFrame, SLOT(backupWallet()));
        connect(changePassphraseAction, SIGNAL(triggered()), walletFrame, SLOT(changePassphrase()));
        connect(signMessageAction, SIGNAL(triggered()), this, SLOT(gotoSignMessageTab()));
        connect(verifyMessageAction, SIGNAL(triggered()), this, SLOT(gotoVerifyMessageTab()));
        connect(usedSendingAddressesAction, SIGNAL(triggered()), walletFrame, SLOT(usedSendingAddresses()));
        connect(usedReceivingAddressesAction, SIGNAL(triggered()), walletFrame, SLOT(usedReceivingAddresses()));
        connect(openAction, SIGNAL(triggered()), this, SLOT(openClicked()));
        connect(exportWalletAction, SIGNAL(triggered()), walletFrame, SLOT(exportWallet()));
        connect(importWalletAction, SIGNAL(triggered()), walletFrame, SLOT(importWallet()));
    }
#endif // ENABLE_WALLET

    new QShortcut(QKeySequence(Qt::CTRL + Qt::SHIFT + Qt::Key_C), this, SLOT(showDebugWindowActivateConsole()));
    new QShortcut(QKeySequence(Qt::CTRL + Qt::SHIFT + Qt::Key_D), this, SLOT(showDebugWindow()));
}

void BitcoinGUI::createMenuBar()
{
#ifdef Q_OS_MAC
    // Create a decoupled menu bar on Mac which stays even if the window is closed
    appMenuBar = new QMenuBar();
#else
    // Get the main window's menu bar on other platforms
    appMenuBar = menuBar();
#endif

    // Configure the menuse
    QMenu *file = appMenuBar->addMenu(tr("&File"));
    if(walletFrame)
    {
        file->addAction(openAction);
        file->addAction(backupWalletAction);
        file->addAction(signMessageAction);
        file->addAction(verifyMessageAction);
        file->addSeparator();
        file->addAction(usedSendingAddressesAction);
        file->addAction(usedReceivingAddressesAction);
        file->addSeparator();
        file->addAction(exportWalletAction);
        file->addAction(importWalletAction);
    }
    file->addAction(quitMenuAction);

    QMenu *settings = appMenuBar->addMenu(tr("&Settings"));
    if(walletFrame)
    {
        settings->addAction(encryptWalletAction);
        settings->addAction(unlockWalletAction);
        settings->addAction(changePassphraseAction);
        settings->addSeparator();
    }
    settings->addAction(settingsMenuAction);

    QMenu *pos = appMenuBar->addMenu(tr("&PoS"));
    if (walletFrame)
    {
        pos->addAction(toggleStakingAction);
        pos->addAction(easysplitAction);
    }

    QMenu *help = appMenuBar->addMenu(tr("&Help"));
    if(walletFrame)
    {
        help->addAction(openRPCConsoleAction);
    }
    help->addAction(showHelpMessageAction);
    help->addSeparator();
    help->addAction(aboutAction);
    help->addAction(aboutQtAction);

}

void BitcoinGUI::createToolBars()
{
    if(walletFrame)
    {
        QToolBar *toolbar = addToolBar(tr("Tabs toolbar"));
        QLabel* syncLabel = new QLabel();
        QLabel* emptyLabel = new QLabel();
        toolbar->setIconSize(QSize(80, 80));
        syncLabel->setPixmap(platformStyle->SingleColorIcon(":/icons/tzc_green_space").pixmap(108, 180));
        syncLabel->setAlignment(Qt::AlignCenter);
        QWidget* spacer = new QWidget();
        spacer->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
        addToolBar(Qt::LeftToolBarArea, toolbar);
        toolbar->addWidget(syncLabel);
        toolbar->setMovable(false);
        toolbar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        toolbar->addAction(emptyAction);
        toolbar->addAction(overviewAction);
        toolbar->addAction(sendCoinsAction);
        toolbar->addAction(receiveCoinsAction);
        toolbar->addAction(stakingAction);
        toolbar->addAction(historyAction);
#ifdef ENABLE_WALLET
#ifdef ENABLE_SMESSAGE
        toolbar->addAction(trezarMessageAction);
#endif // ENABLE_SMESSAGE
#endif // ENABLE_WALLET
        toolbar->addAction(optionPageAction);
        toolbar->addAction(quitAction);
        overviewAction->setChecked(true);
    }
}

void BitcoinGUI::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if(clientModel)
    {
        // Create system tray menu (or setup the dock menu) that late to prevent users from calling actions,
        // while the client has not yet fully loaded
        createTrayIconMenu();

        // Keep up to date with client
        setNumConnections(clientModel->getNumConnections());
        connect(clientModel, SIGNAL(numConnectionsChanged(int)), this, SLOT(setNumConnections(int)));

        setNumBlocks(clientModel->getNumBlocks(), clientModel->getLastBlockDate(), clientModel->getVerificationProgress(NULL), false);
        connect(clientModel, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)), this, SLOT(setNumBlocks(int,QDateTime,double,bool)));

        // Receive and report messages from client model
        connect(clientModel, SIGNAL(message(QString,QString,unsigned int)), this, SLOT(message(QString,QString,unsigned int)));

        // Show progress dialog
        connect(clientModel, SIGNAL(showProgress(QString,int)), this, SLOT(showProgress(QString,int)));

        rpcConsole->setClientModel(clientModel);
#ifdef ENABLE_WALLET
        if(walletFrame)
        {
            walletFrame->setClientModel(clientModel);
        }
#endif // ENABLE_WALLET
        unitDisplayControl->setOptionsModel(clientModel->getOptionsModel());
        
        OptionsModel* optionsModel = clientModel->getOptionsModel();
        if(optionsModel)
        {
            // be aware of the tray icon disable state change reported by the OptionsModel object.
            connect(optionsModel,SIGNAL(hideTrayIconChanged(bool)),this,SLOT(setTrayIconVisible(bool)));
        
            // initialize the disable state of the tray icon with the current value in the model.
            setTrayIconVisible(optionsModel->getHideTrayIcon());
        }
    } else {
        // Disable possibility to show main window via action
        toggleHideAction->setEnabled(false);
        if(trayIconMenu)
        {
            // Disable context menu on tray icon
            trayIconMenu->clear();
        }
        // Propagate cleared model to child objects
        rpcConsole->setClientModel(nullptr);
#ifdef ENABLE_WALLET
        if (walletFrame)
        {
            walletFrame->setClientModel(nullptr);
        }
#endif // ENABLE_WALLET
        unitDisplayControl->setOptionsModel(nullptr);
    }
}

#ifdef ENABLE_WALLET
bool BitcoinGUI::addWallet(const QString& name, WalletModel *walletModel)
{
    if(!walletFrame)
        return false;
    setWalletActionsEnabled(true);
    return walletFrame->addWallet(name, walletModel);
}

bool BitcoinGUI::setCurrentWallet(const QString& name)
{
    if(!walletFrame)
        return false;
    return walletFrame->setCurrentWallet(name);
}

void BitcoinGUI::removeAllWallets()
{
    if(!walletFrame)
        return;
    setWalletActionsEnabled(false);
    walletFrame->removeAllWallets();
}
#endif // ENABLE_WALLET

void BitcoinGUI::setWalletActionsEnabled(bool enabled)
{
    overviewAction->setEnabled(enabled);
    sendCoinsAction->setEnabled(enabled);
    sendCoinsMenuAction->setEnabled(enabled);
    receiveCoinsAction->setEnabled(enabled);
    receiveCoinsMenuAction->setEnabled(enabled);
    historyAction->setEnabled(enabled);
    easysplitAction->setEnabled(enabled);
    encryptWalletAction->setEnabled(enabled);
    backupWalletAction->setEnabled(enabled);
    changePassphraseAction->setEnabled(enabled);
    signMessageAction->setEnabled(enabled);
    verifyMessageAction->setEnabled(enabled);
    usedSendingAddressesAction->setEnabled(enabled);
    usedReceivingAddressesAction->setEnabled(enabled);
    openAction->setEnabled(enabled);
    exportWalletAction->setEnabled(enabled);
    importWalletAction->setEnabled(enabled);
    stakingAction->setEnabled(enabled);
    optionPageAction->setEnabled(enabled);
#ifdef ENABLE_WALLET
#ifdef ENABLE_SMESSAGE
    trezarMessageAction->setEnabled(enabled);
#endif // ENABLE_SMESSAGE
#endif // ENABLE_WALLET
}

void BitcoinGUI::createTrayIcon(const NetworkStyle *networkStyle)
{
#ifndef Q_OS_MAC
    trayIcon = new QSystemTrayIcon(this);
    QString toolTip = tr("%1 client").arg(tr(PACKAGE_NAME)) + " " + networkStyle->getTitleAddText();
    trayIcon->setToolTip(toolTip);
    trayIcon->setIcon(networkStyle->getTrayAndWindowIcon());
    trayIcon->hide();
#endif

    notificator = new Notificator(QApplication::applicationName(), trayIcon, this);
}

void BitcoinGUI::createTrayIconMenu()
{
#ifndef Q_OS_MAC
    // return if trayIcon is unset (only on non-Mac OSes)
    if (!trayIcon)
        return;

    trayIconMenu = new QMenu(this);
    trayIcon->setContextMenu(trayIconMenu);

    connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
            this, SLOT(trayIconActivated(QSystemTrayIcon::ActivationReason)));
#else
    // Note: On Mac, the dock icon is used to provide the tray's functionality.
    MacDockIconHandler *dockIconHandler = MacDockIconHandler::instance();
    dockIconHandler->setMainWindow((QMainWindow *)this);
    trayIconMenu = dockIconHandler->dockMenu();
#endif

    // Configuration of the tray icon (or dock icon) icon menu
    trayIconMenu->addAction(toggleHideAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(sendCoinsMenuAction);
    trayIconMenu->addAction(receiveCoinsMenuAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(signMessageAction);
    trayIconMenu->addAction(verifyMessageAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(optionPageAction);
    trayIconMenu->addAction(openRPCConsoleAction);
#ifndef Q_OS_MAC // This is built-in on Mac
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(quitAction);
#endif
}

#ifndef Q_OS_MAC
void BitcoinGUI::trayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if(reason == QSystemTrayIcon::Trigger)
    {
        // Click on system tray icon triggers show/hide of the main window
        toggleHidden();
    }
}
#endif


void BitcoinGUI::aboutClicked()
{
    if(!clientModel)
        return;

    HelpMessageDialog dlg(this, true);
    dlg.exec();
}

bool BitcoinGUI::getStakingStatus(double nEstimateTime, uint64_t nWeight, QString &stakeText, QString &stakeTime)
{
    stakeText = tr("Staking disabled");
    stakeTime = tr("Calculating time..");
    bool staking = false;

    if (GetStaking()) {
        LOCK(cs_vNodes);
        if (vNodes.empty()) {
            stakeText = tr("Not staking - Wallet offline");
        } else if (IsInitialBlockDownload()) {
            stakeText = tr("Not staking - Wallet syncing");
        } else if(pwalletMain->IsLocked()) {
            stakeText = tr("Not staking - Wallet locked");
        } else {
            if (!nWeight) {
                stakeText = tr("Not staking - Immature coins");
            } else if (nEstimateTime != 0) {
                staking = true;
                if ((nEstimateTime / 60) > 24) {
                    nEstimateTime /= 60 * 24;
                    stakeText = tr("Estimated Stake Time: %1 day(s)").arg(nEstimateTime);
                    stakeTime = tr("%1 day(s)").arg(nEstimateTime);
                } else if ((nEstimateTime / 60.00) < 0) {
                    stakeText = tr("Estimated Stake Time: %1 minute(s)").arg(nEstimateTime);
                    stakeTime = tr("%1 minute(s)").arg(nEstimateTime);
                } else {
                    nEstimateTime /= 60.00;
                    stakeText = tr("Estimated Stake Time: %1 hour(s)").arg(nEstimateTime);
                    stakeTime = tr("%1 hour(s)").arg(nEstimateTime);
                }
            } else {
                staking = true;
                stakeText = tr("You are staking");
            }
        }
    }

    return staking;
}

void BitcoinGUI::showDebugWindow()
{
    rpcConsole->showNormal();
    rpcConsole->show();
    rpcConsole->raise();
    rpcConsole->activateWindow();
}

void BitcoinGUI::showDebugWindowActivateConsole()
{
    rpcConsole->setTabFocus(RPCConsole::TAB_CONSOLE);
    showDebugWindow();
}

void BitcoinGUI::showHelpMessageClicked()
{
    helpMessageDialog->show();
}

#ifdef ENABLE_WALLET
void BitcoinGUI::openClicked()
{
    OpenURIDialog dlg(this);
    if(dlg.exec())
    {
        Q_EMIT receivedURI(dlg.getURI());
    }
}

void BitcoinGUI::gotoOverviewPage()
{
    overviewAction->setChecked(true);
    overviewAction->setIcon(QIcon(":/icons/overview_green"));
    sendCoinsAction->setIcon(QIcon(":/icons/send"));
    receiveCoinsAction->setIcon(QIcon(":/icons/receive"));
    stakingAction->setIcon(QIcon(":/icons/staking_off"));
    historyAction->setIcon(QIcon(":/icons/history"));
    optionPageAction->setIcon(QIcon(":/icons/settings"));

#ifdef ENABLE_WALLET
#ifdef ENABLE_SMESSAGE
    trezarMessageAction->setIcon(QIcon(":/icons/send"));
#endif // ENABLE_SMESSAGE
#endif // ENABLE_WALLET

    if (walletFrame) walletFrame->gotoOverviewPage();
}

void BitcoinGUI::gotoHistoryPage()
{
    historyAction->setChecked(true);
    historyAction->setIcon(QIcon(":/icons/history_green"));
    overviewAction->setIcon(QIcon(":/icons/overview"));
    sendCoinsAction->setIcon(QIcon(":/icons/send"));
    receiveCoinsAction->setIcon(QIcon(":/icons/receive"));
    stakingAction->setIcon(QIcon(":/icons/staking_off"));
    optionPageAction->setIcon(QIcon(":/icons/settings"));

#ifdef ENABLE_WALLET
#ifdef ENABLE_SMESSAGE
    trezarMessageAction->setIcon(QIcon(":/icons/send"));
#endif // ENABLE_SMESSAGE
#endif // ENABLE_WALLET

    if (walletFrame) walletFrame->gotoHistoryPage();
}

void BitcoinGUI::gotoEasySplitPage()
{
    if (walletFrame) walletFrame->gotoEasySplitPage();
}

void BitcoinGUI::gotoReceiveCoinsPage()
{
    receiveCoinsAction->setChecked(true);
    receiveCoinsAction->setIcon(QIcon(":/icons/receive_green"));
    overviewAction->setIcon(QIcon(":/icons/overview"));
    sendCoinsAction->setIcon(QIcon(":/icons/send"));
    stakingAction->setIcon(QIcon(":/icons/staking_off"));
    historyAction->setIcon(QIcon(":/icons/history"));
    optionPageAction->setIcon(QIcon(":/icons/settings"));

#ifdef ENABLE_WALLET
#ifdef ENABLE_SMESSAGE
    trezarMessageAction->setIcon(QIcon(":/icons/send"));
#endif // ENABLE_SMESSAGE
#endif // ENABLE_WALLET

    if (walletFrame) walletFrame->gotoReceiveCoinsPage();
}

void BitcoinGUI::gotoSendCoinsPage(QString addr)
{
    sendCoinsAction->setChecked(true);
    sendCoinsAction->setIcon(QIcon(":/icons/send_green"));
    overviewAction->setIcon(QIcon(":/icons/overview"));
    receiveCoinsAction->setIcon(QIcon(":/icons/receive"));
    stakingAction->setIcon(QIcon(":/icons/staking_off"));
    historyAction->setIcon(QIcon(":/icons/history"));
    optionPageAction->setIcon(QIcon(":/icons/settings"));

#ifdef ENABLE_WALLET
#ifdef ENABLE_SMESSAGE
    trezarMessageAction->setIcon(QIcon(":/icons/send"));
#endif // ENABLE_SMESSAGE
#endif // ENABLE_WALLET

    if (walletFrame) walletFrame->gotoSendCoinsPage(addr);
}

void BitcoinGUI::gotoSignMessageTab(QString addr)
{
    if (walletFrame) walletFrame->gotoSignMessageTab(addr);
}

void BitcoinGUI::gotoVerifyMessageTab(QString addr)
{
    if (walletFrame) walletFrame->gotoVerifyMessageTab(addr);
}

void BitcoinGUI::gotoStakingPage()
{
    stakingAction->setChecked(true);
    stakingAction->setIcon(QIcon(":/icons/staking_on"));
    overviewAction->setIcon(QIcon(":/icons/overview"));
    sendCoinsAction->setIcon(QIcon(":/icons/send"));
    receiveCoinsAction->setIcon(QIcon(":/icons/receive"));
    historyAction->setIcon(QIcon(":/icons/history"));
    optionPageAction->setIcon(QIcon(":/icons/settings"));

#ifdef ENABLE_WALLET
#ifdef ENABLE_SMESSAGE
    trezarMessageAction->setIcon(QIcon(":/icons/send"));
#endif // ENABLE_SMESSAGE
#endif // ENABLE_WALLET

    if (walletFrame) walletFrame->gotoStakingPage();
}

void BitcoinGUI::gotoTrezarMessage()
{
    trezarMessageAction->setChecked(true);
    stakingAction->setIcon(QIcon(":/icons/staking_off"));
    overviewAction->setIcon(QIcon(":/icons/overview"));
    sendCoinsAction->setIcon(QIcon(":/icons/send"));
    receiveCoinsAction->setIcon(QIcon(":/icons/receive"));
    historyAction->setIcon(QIcon(":/icons/history"));
    optionPageAction->setIcon(QIcon(":/icons/settings"));

#ifdef ENABLE_WALLET
#ifdef ENABLE_SMESSAGE
    trezarMessageAction->setIcon(QIcon(":/icons/send"));
#endif // ENABLE_SMESSAGE
#endif // ENABLE_WALLET

    if (walletFrame) walletFrame->gotoTrezarMessage();
}

void BitcoinGUI::gotoSettingsPage()
{
    optionPageAction->setChecked(true);
    optionPageAction->setIcon(QIcon(":/icons/settings_green"));
    overviewAction->setIcon(QIcon(":/icons/overview"));
    sendCoinsAction->setIcon(QIcon(":/icons/send"));
    receiveCoinsAction->setIcon(QIcon(":/icons/receive"));
    stakingAction->setIcon(QIcon(":/icons/staking_off"));
    historyAction->setIcon(QIcon(":/icons/history"));

#ifdef ENABLE_WALLET
#ifdef ENABLE_SMESSAGE
    trezarMessageAction->setIcon(QIcon(":/icons/send"));
#endif // ENABLE_SMESSAGE
#endif // ENABLE_WALLET

    if (walletFrame) walletFrame->gotoSettingsPage();
}
#endif // ENABLE_WALLET

void BitcoinGUI::setNumConnections(int count)
{
    QString icon;
    switch(count)
    {
    case 0: icon = ":/icons/connect_0"; break;
    case 1: case 2: case 3: icon = ":/icons/connect_1"; break;
    case 4: case 5: case 6: icon = ":/icons/connect_2"; break;
    case 7: case 8: case 9: icon = ":/icons/connect_3"; break;
    default: icon = ":/icons/connect_4"; break;
    }
    labelConnectionsIcon->setPixmap(platformStyle->TextColorIcon(icon).pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
    labelConnectionsIcon->setToolTip(tr("%n active connection(s) to Trezarcoin network", "", count));
}

void BitcoinGUI::setNumBlocks(int count, const QDateTime& blockDate, double nVerificationProgress, bool header)
{
    if(!clientModel)
        return;

    // Prevent orphan statusbar messages (e.g. hover Quit in main menu, wait until chain-sync starts -> garbelled text)
    //statusBar()->clearMessage();

    // Acquire current block source
    enum BlockSource blockSource = clientModel->getBlockSource();
    switch (blockSource) {
        case BLOCK_SOURCE_NETWORK:
            if (header) {
                return;
            }
            progressBarLabel->setText(tr("Synchronizing with network..."));
            break;
        case BLOCK_SOURCE_DISK:
            if (header) {
                progressBarLabel->setText(tr("Indexing blocks on disk..."));
            } else {
                progressBarLabel->setText(tr("Processing blocks on disk..."));
            }
            break;
        case BLOCK_SOURCE_REINDEX:
            progressBarLabel->setText(tr("Reindexing blocks on disk..."));
            break;
        case BLOCK_SOURCE_NONE:
            if (header) {
                return;
            }
            // Case: not Importing, not Reindexing and no network connection
            progressBarLabel->setText(tr("No block source available..."));
            break;
    }

    QString tooltip;

    QDateTime currentDate = QDateTime::currentDateTime();
    qint64 secs = blockDate.secsTo(currentDate);

    tooltip = tr("Processed %n block(s) of transaction history.", "", count);

    // Set icon state: spinning if catching up, tick otherwise
    if(secs < 90*60)
    {
        tooltip = tr("Up to date") + QString(".<br>") + tooltip;
        labelBlocksIcon->setPixmap(platformStyle->TextColorIcon(":/icons/synced").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));

        tooltip += QString("<br>") + tr("The current PoW difficulty is %1").arg(GetDifficulty());
        tooltip += QString("<br>") + tr("The current PoS difficulty is %1").arg(GetDifficulty(GetLastBlockIndex(chainActive.Tip(), true)));
        
        bheight = QString::number(count);


#ifdef ENABLE_WALLET
        if(walletFrame)
            walletFrame->showOutOfSyncWarning(false);
#endif // ENABLE_WALLET

        progressBarIcon->setVisible(false);
        progressBarLabel->setVisible(false);
        progressBar->setVisible(false);
        

    }
    else
    {
        // Represent time from last generated block in human readable text
        QString timeBehindText;
        const int HOUR_IN_SECONDS = 60*60;
        const int DAY_IN_SECONDS = 24*60*60;
        const int WEEK_IN_SECONDS = 7*24*60*60;
        const int YEAR_IN_SECONDS = 31556952; // Average length of year in Gregorian calendar
        if(secs < 2*DAY_IN_SECONDS)
        {
            timeBehindText = tr("%n hour(s)","",secs/HOUR_IN_SECONDS);
        }
        else if(secs < 2*WEEK_IN_SECONDS)
        {
            timeBehindText = tr("%n day(s)","",secs/DAY_IN_SECONDS);
        }
        else if(secs < YEAR_IN_SECONDS)
        {
            timeBehindText = tr("%n week(s)","",secs/WEEK_IN_SECONDS);
        }
        else
        {
            qint64 years = secs / YEAR_IN_SECONDS;
            qint64 remainder = secs % YEAR_IN_SECONDS;
            timeBehindText = tr("%1 and %2").arg(tr("%n year(s)", "", years)).arg(tr("%n week(s)","", remainder/WEEK_IN_SECONDS));
        }

        progressBarIcon->setVisible(true);
        progressBarLabel->setVisible(true);
        progressBar->setFormat(tr("%1 behind").arg(timeBehindText));
        progressBar->setMaximum(1000000000);
        progressBar->setValue(nVerificationProgress * 1000000000.0 + 0.5);
        progressBar->setVisible(true);
        

        tooltip = tr("Catching up...") + QString("<br>") + tooltip;
        if(count != prevBlocks)
        {
            labelBlocksIcon->setPixmap(platformStyle->TextColorIcon(QString(
                ":/movies/spinner-%1").arg(spinnerFrame, 3, 10, QChar('0')))
                .pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
            spinnerFrame = (spinnerFrame + 1) % SPINNER_FRAMES;
        }
        prevBlocks = count;

#ifdef ENABLE_WALLET
        if(walletFrame)
            walletFrame->showOutOfSyncWarning(true);
#endif // ENABLE_WALLET

        tooltip += QString("<br>");
        tooltip += tr("Last received block was generated %1 ago.").arg(timeBehindText);
        tooltip += QString("<br>");
        tooltip += tr("Transactions after this will not yet be visible.");
    }

    // Don't word-wrap this (fixed-width) tooltip
    tooltip = QString("<nobr>") + tooltip + QString("</nobr>");

    labelBlocksIcon->setToolTip(tooltip);
    progressBarLabel->setToolTip(tooltip);
    progressBar->setToolTip(tooltip);
}

void BitcoinGUI::message(const QString &title, const QString &message, unsigned int style, bool *ret)
{
    QString strTitle = tr("Trezarcoin"); // default title
    // Default to information icon
    int nMBoxIcon = QMessageBox::Information;
    int nNotifyIcon = Notificator::Information;

    QString msgType;

    // Prefer supplied title over style based title
    if (!title.isEmpty()) {
        msgType = title;
    }
    else {
        switch (style) {
        case CClientUIInterface::MSG_ERROR:
            msgType = tr("Error");
            break;
        case CClientUIInterface::MSG_WARNING:
            msgType = tr("Warning");
            break;
        case CClientUIInterface::MSG_INFORMATION:
            msgType = tr("Information");
            break;
        default:
            break;
        }
    }
    // Append title to "Bitcoin - "
    if (!msgType.isEmpty())
        strTitle += " - " + msgType;

    // Check for error/warning icon
    if (style & CClientUIInterface::ICON_ERROR) {
        nMBoxIcon = QMessageBox::Critical;
        nNotifyIcon = Notificator::Critical;
    }
    else if (style & CClientUIInterface::ICON_WARNING) {
        nMBoxIcon = QMessageBox::Warning;
        nNotifyIcon = Notificator::Warning;
    }

    // Display message
    if (style & CClientUIInterface::MODAL) {
        // Check for buttons, use OK as default, if none was supplied
        QMessageBox::StandardButton buttons;
        if (!(buttons = (QMessageBox::StandardButton)(style & CClientUIInterface::BTN_MASK)))
            buttons = QMessageBox::Ok;

        showNormalIfMinimized();
        QMessageBox mBox((QMessageBox::Icon)nMBoxIcon, strTitle, message, buttons, this);
        int r = mBox.exec();
        if (ret != NULL)
            *ret = r == QMessageBox::Ok;
    }
    else
        notificator->notify((Notificator::Class)nNotifyIcon, strTitle, message);
}

void BitcoinGUI::changeEvent(QEvent *e)
{
    QMainWindow::changeEvent(e);
#ifndef Q_OS_MAC // Ignored on Mac
    if(e->type() == QEvent::WindowStateChange)
    {
        if(clientModel && clientModel->getOptionsModel() && clientModel->getOptionsModel()->getMinimizeToTray())
        {
            QWindowStateChangeEvent *wsevt = static_cast<QWindowStateChangeEvent*>(e);
            if(!(wsevt->oldState() & Qt::WindowMinimized) && isMinimized())
            {
                QTimer::singleShot(0, this, SLOT(hide()));
                e->ignore();
            }
        }
    }
#endif
}

void BitcoinGUI::closeEvent(QCloseEvent *event)
{
#ifndef Q_OS_MAC // Ignored on Mac
    if(clientModel && clientModel->getOptionsModel())
    {
        if(!clientModel->getOptionsModel()->getMinimizeOnClose())
        {
            // close rpcConsole in case it was open to make some space for the shutdown window
            rpcConsole->close();

            QApplication::quit();
        }
        else
        {
            QMainWindow::showMinimized();
            event->ignore();
        }
    }
#else
    QMainWindow::closeEvent(event);
#endif
}

void BitcoinGUI::showEvent(QShowEvent *event)
{
    // enable the debug window when the main window shows up
    openRPCConsoleAction->setEnabled(true);
    aboutAction->setEnabled(true);
}

#ifdef ENABLE_WALLET
void BitcoinGUI::incomingTransaction(const QString& date, int unit, const CAmount& amount, const QString& type, const QString& address, const QString& label)
{
    // On new transaction, make an info balloon
    QString msg = tr("Date: %1\n").arg(date) +
                  tr("Amount: %1\n").arg(BitcoinUnits::formatWithUnit(unit, amount, true)) +
                  tr("Type: %1\n").arg(type);
    if (!label.isEmpty())
        msg += tr("Label: %1\n").arg(label);
    else if (!address.isEmpty())
        msg += tr("Address: %1\n").arg(address);
    message((amount)<0 ? tr("Sent transaction") : tr("Incoming transaction"),
             msg, CClientUIInterface::MSG_INFORMATION);
}
#endif // ENABLE_WALLET

void BitcoinGUI::dragEnterEvent(QDragEnterEvent *event)
{
    // Accept only URIs
    if(event->mimeData()->hasUrls())
        event->acceptProposedAction();
}

void BitcoinGUI::dropEvent(QDropEvent *event)
{
    if(event->mimeData()->hasUrls())
    {
        Q_FOREACH(const QUrl &uri, event->mimeData()->urls())
        {
            Q_EMIT receivedURI(uri.toString());
        }
    }
    event->acceptProposedAction();
}

bool BitcoinGUI::eventFilter(QObject *object, QEvent *event)
{
    // Catch status tip events
    if (event->type() == QEvent::StatusTip)
    {
        // Prevent adding text from setStatusTip(), if we currently use the status bar for displaying other stuff
        if (progressBarLabel->isVisible() || progressBar->isVisible())
            return true;
    }
    return QMainWindow::eventFilter(object, event);
}

#ifdef ENABLE_WALLET
bool BitcoinGUI::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    // URI has to be valid
    if (walletFrame && walletFrame->handlePaymentRequest(recipient))
    {
        showNormalIfMinimized();
        gotoSendCoinsPage();
        return true;
    }
    return false;
}

void BitcoinGUI::setEncryptionStatus(int status)
{
    if(fWalletUnlockStakingOnly)
    {
        labelEncryptionIcon->setPixmap(platformStyle->TextColorIcon(":/icons/lock_closed").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>unlocked for staking only</b>"));
        changePassphraseAction->setEnabled(false);
        unlockWalletAction->setVisible(false);
        encryptWalletAction->setEnabled(false);
        if(walletFrame)
            walletFrame->showLockStaking(false);
    }
    else
    {
        switch (status)
        {
        case WalletModel::Unencrypted:
            labelEncryptionIcon->hide();
            encryptWalletAction->setChecked(false);
            changePassphraseAction->setEnabled(false);
            encryptWalletAction->setEnabled(true);
            unlockWalletAction->setVisible(false);
            if (walletFrame)
                walletFrame->showLockStaking(false);
            break;
        case WalletModel::Unlocked:
            labelEncryptionIcon->show();
            labelEncryptionIcon->setPixmap(platformStyle->TextColorIcon(":/icons/lock_open").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
            labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>unlocked</b>"));
            unlockWalletAction->setVisible(false);
            encryptWalletAction->setChecked(true);
            changePassphraseAction->setEnabled(true);
            encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
            if (walletFrame)
                walletFrame->showLockStaking(false);
            break;
        case WalletModel::Locked:
            labelEncryptionIcon->show();
            labelEncryptionIcon->setPixmap(platformStyle->SingleColorIcon(":/icons/lock_closed").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
            labelEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>locked</b>"));
            encryptWalletAction->setChecked(true);
            changePassphraseAction->setEnabled(true);
            unlockWalletAction->setVisible(true);
            encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
            if (walletFrame)
                walletFrame->showLockStaking(true);
            break;
        }
    }
    updateStakingStatus();
}
#endif // ENABLE_WALLET

void BitcoinGUI::showNormalIfMinimized(bool fToggleHidden)
{
    if(!clientModel)
        return;

    // activateWindow() (sometimes) helps with keyboard focus on Windows
    if (isHidden())
    {
        show();
        activateWindow();
    }
    else if (isMinimized())
    {
        showNormal();
        activateWindow();
    }
    else if (GUIUtil::isObscured(this))
    {
        raise();
        activateWindow();
    }
    else if(fToggleHidden)
        hide();
}

void BitcoinGUI::toggleHidden()
{
    showNormalIfMinimized(true);
}

void BitcoinGUI::detectShutdown()
{
    if (ShutdownRequested())
    {
        if(rpcConsole)
            rpcConsole->hide();
        qApp->quit();
    }
}

void BitcoinGUI::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0)
    {
        progressDialog = new QProgressDialog(title, "", 0, 100);
        progressDialog->setWindowModality(Qt::ApplicationModal);
        progressDialog->setMinimumDuration(0);
        progressDialog->setCancelButton(0);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
    }
    else if (nProgress == 100)
    {
        if (progressDialog)
        {
            progressDialog->close();
            progressDialog->deleteLater();
        }
    }
    else if (progressDialog)
        progressDialog->setValue(nProgress);
}

void BitcoinGUI::setTrayIconVisible(bool fHideTrayIcon)
{
    if (trayIcon)
    {
        trayIcon->setVisible(!fHideTrayIcon);
    }
}

static bool ThreadSafeMessageBox(BitcoinGUI *gui, const std::string& message, const std::string& caption, unsigned int style)
{
    bool modal = (style & CClientUIInterface::MODAL);
    // The SECURE flag has no effect in the Qt GUI.
    // bool secure = (style & CClientUIInterface::SECURE);
    style &= ~CClientUIInterface::SECURE;
    bool ret = false;
    // In case of modal message, use blocking connection to wait for user to click a button
    QMetaObject::invokeMethod(gui, "message",
                               modal ? GUIUtil::blockingGUIThreadConnection() : Qt::QueuedConnection,
                               Q_ARG(QString, QString::fromStdString(caption)),
                               Q_ARG(QString, QString::fromStdString(message)),
                               Q_ARG(unsigned int, style),
                               Q_ARG(bool*, &ret));
    return ret;
}

void BitcoinGUI::subscribeToCoreSignals()
{
    // Connect signals to client
    uiInterface.ThreadSafeMessageBox.connect(boost::bind(ThreadSafeMessageBox, this, _1, _2, _3));
    uiInterface.ThreadSafeQuestion.connect(boost::bind(ThreadSafeMessageBox, this, _1, _3, _4));
}

void BitcoinGUI::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    uiInterface.ThreadSafeMessageBox.disconnect(boost::bind(ThreadSafeMessageBox, this, _1, _2, _3));
    uiInterface.ThreadSafeQuestion.disconnect(boost::bind(ThreadSafeMessageBox, this, _1, _3, _4));
}

UnitDisplayStatusBarControl::UnitDisplayStatusBarControl(const PlatformStyle *platformStyle) :
    optionsModel(0),
    menu(0)
{
    createContextMenu();
    setToolTip(tr("Unit to show amounts in. Click to select another unit."));
    QList<BitcoinUnits::Unit> units = BitcoinUnits::availableUnits();
    int max_width = 0;
    const QFontMetrics fm(font());
    Q_FOREACH (const BitcoinUnits::Unit unit, units)
    {
        max_width = qMax(max_width, fm.width(BitcoinUnits::name(unit)));
    }
    setMinimumSize(max_width, 0);
    setAlignment(Qt::AlignRight | Qt::AlignVCenter);
    setStyleSheet(QString("QLabel { color : %1 }").arg(platformStyle->SingleColor().name()));
}

/** So that it responds to button clicks */
void UnitDisplayStatusBarControl::mousePressEvent(QMouseEvent *event)
{
    onDisplayUnitsClicked(event->pos());
}

/** Creates context menu, its actions, and wires up all the relevant signals for mouse events. */
void UnitDisplayStatusBarControl::createContextMenu()
{
    menu = new QMenu(this);
    Q_FOREACH(BitcoinUnits::Unit u, BitcoinUnits::availableUnits())
    {
        QAction *menuAction = new QAction(QString(BitcoinUnits::name(u)), this);
        menuAction->setData(QVariant(u));
        menu->addAction(menuAction);
    }
    connect(menu,SIGNAL(triggered(QAction*)),this,SLOT(onMenuSelection(QAction*)));
}

/** Lets the control know about the Options Model (and its signals) */
void UnitDisplayStatusBarControl::setOptionsModel(OptionsModel *optionsModel)
{
    if (optionsModel)
    {
        this->optionsModel = optionsModel;

        // be aware of a display unit change reported by the OptionsModel object.
        connect(optionsModel,SIGNAL(displayUnitChanged(int)),this,SLOT(updateDisplayUnit(int)));

        // initialize the display units label with the current value in the model.
        updateDisplayUnit(optionsModel->getDisplayUnit());
    }
}

/** When Display Units are changed on OptionsModel it will refresh the display text of the control on the status bar */
void UnitDisplayStatusBarControl::updateDisplayUnit(int newUnits)
{
    setText(BitcoinUnits::name(newUnits));
}

/** Shows context menu with Display Unit options by the mouse coordinates */
void UnitDisplayStatusBarControl::onDisplayUnitsClicked(const QPoint& point)
{
    QPoint globalPos = mapToGlobal(point);
    menu->exec(globalPos);
}

/** Tells underlying optionsModel to update its current display unit. */
void UnitDisplayStatusBarControl::onMenuSelection(QAction* action)
{
    if (action)
    {
        optionsModel->setDisplayUnit(action->data());
    }
}

void BitcoinGUI::toggleStaking()
{
    SetStaking(!GetStaking());
    updateStakingStatus();
    Q_EMIT message(tr("Staking"), GetStaking() ? tr("Staking has been enabled") : tr("Staking has been disabled"),
                   CClientUIInterface::MSG_INFORMATION);
}

#ifdef ENABLE_WALLET
void BitcoinGUI::updateStakingStatus()
{
    if (!pwalletMain)
        return;

    TRY_LOCK(cs_main, lockMain);
    if (!lockMain)
        return;

    TRY_LOCK(pwalletMain->cs_wallet, lockWallet);
    if (!lockWallet)
        return;

    uint64_t nWeight = pwalletMain->GetStakeWeight();

    bool staking = nLastCoinStakeSearchInterval && nWeight;
    double nNetworkWeight = GetPoSKernelPS();
    double nEstimateTime = 0;

    if (staking && nWeight != 0 && nNetworkWeight != 0)
        nEstimateTime = nNetworkWeight / nWeight * 3.00;
    
    QString stakeText;
    QString stakeTime;
    bool fStakeIcon = getStakingStatus(nEstimateTime, nWeight, stakeText, stakeTime);

    /* Don't wrap words */
    if (fStakeIcon)
    {
        stakeText += QString("<br>");
        if (!IsColdStakingEnabled(chainActive.Tip(), Params().GetConsensus())) {
            stakeText += tr("Staking enabled for %1 inputs with weight %2 coin days") \
                .arg(nMinWeightInputs + nAvgWeightInputs + nMaxWeightInputs).arg(nWeight);
            stakeText += QString("<br>");
            stakeText += tr("Inputs: %1 min. age, %2 avg. age, %3 max. age") \
                .arg(nMinWeightInputs).arg(nAvgWeightInputs).arg(nMaxWeightInputs);
        } else {
            stakeText += tr("Staking enabled with weight %1") \
                .arg(nWeight);
        }
    }

    stakeText = QString("<nobr>") + stakeText + QString("</nobr>");

    labelStakeMining->setToolTip(stakeText);

    if(walletFrame) {
        walletFrame->setStakingStatus(stakeTime,fStakeIcon);
        if (!GetStaking())
            walletFrame->showLockStaking(false);
    }

    if (fStakeIcon)
    {
        labelStakeMining->setPixmap(QIcon(":/icons/staking_on_menu").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
        toggleStakingAction->setIcon(QIcon(":/icons/staking_on_menu"));
    }   
    else
    {
        labelStakeMining->setPixmap(QIcon(":/icons/staking_off_menu").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
        toggleStakingAction->setIcon(QIcon(":/icons/staking_off_menu"));
    }

    //Update NetworkInfo
    QString diffPoW = QString("%1 PoW").arg(GetDifficulty());
    QString diffPoS = QString("%1 PoS").arg(GetDifficulty(GetLastBlockIndex(chainActive.Tip(), true)));

    if (walletFrame) {
        walletFrame->setNetworkStats(bheight, diffPoW, diffPoS);
    }
}
#endif
