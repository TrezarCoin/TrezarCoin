/*
 * Qt4 bitcoin GUI.
 *
 * W.J. van der Laan 2011-2012
 * The Bitcoin Developers 2011-2012
 */
#include "bitcoingui.h"
#include "transactiontablemodel.h"
#include "addressbookpage.h"
#include "sendcoinsdialog.h"
#include "signverifymessagedialog.h"
#include "optionsdialog.h"
#include "aboutdialog.h"
#include "clientmodel.h"
#include "walletmodel.h"
#include "editaddressdialog.h"
#include "optionsmodel.h"
#include "transactiondescdialog.h"
#include "addresstablemodel.h"
#include "transactionview.h"
#include "overviewpage.h"
#include "bitcoinunits.h"
#include "guiconstants.h"
#include "askpassphrasedialog.h"
#include "notificator.h"
#include "guiutil.h"
#include "rpcconsole.h"
#include "blockexplorer.h"

#ifdef Q_OS_MAC
#include "macdockiconhandler.h"
#endif

#include "util.h"

#include <QApplication>
#include <QMainWindow>
#include <QMenuBar>
#include <QMenu>
#include <QIcon>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QToolBar>
#include <QStatusBar>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QLocale>
#include <QMessageBox>
#include <QProgressBar>
#include <QStackedWidget>
#include <QDateTime>
#include <QFileDialog>
#include <QTimer>
#include <QDragEnterEvent>
#include <QStyle>

#if (QT_VERSION < 0x050000)
#include <QUrl>
#include <QDesktopServices>
#else
#include <QMimeData>
#include <QStandardPaths>
#endif

#include <iostream>

BitcoinGUI::BitcoinGUI(QWidget *parent):
    QMainWindow(parent),
    clientModel(0),
    walletModel(0),
    lockWalletToggleAction(0),
    encryptWalletAction(0),
    changePassphraseAction(0),
    aboutQtAction(0),
    trayIcon(0),
    notificator(0),
    rpcConsole(0),
    prevBlocks(0),
    spinnerFrame(0)
{
    setWindowTitle(tr("Orbitcoin") + " - " + tr("Wallet"));
#ifndef Q_OS_MAC
    qApp->setWindowIcon(QIcon(":icons/orbitcoin"));
    setWindowIcon(QIcon(":icons/orbitcoin"));
#else
    setUnifiedTitleAndToolBarOnMac(true);
    QApplication::setAttribute(Qt::AA_DontShowIconsInMenus);
#endif

    int nQtStyle = GetArg("-qtstyle", 0);
    if(nQtStyle < 0) nQtStyle = 0;

    if(!nQtStyle) {
        resize(850, 575);
        qApp->setStyleSheet("QToolBar QToolButton { text-align: left; \
          padding-left: 0px; padding-right: 0px; padding-top: 3px; padding-bottom: 3px; }");
    } else if(nQtStyle == 1) {
        resize(1000, 525);
        qApp->setStyleSheet("QToolBar QToolButton { text-align: center; width: 100%; \
          padding-left: 5px; padding-right: 5px; padding-top: 2px; padding-bottom: 2px; } \
          QToolBar QToolButton:hover { font-weight: bold; } \
          #toolbar { border: none; height: 100%; min-width: 150px; max-width: 150px; }");
    } else {
        resize(1000, 525);
        qApp->setStyleSheet("QToolBar QToolButton { text-align: center; width: 100%; \
          color: white; background-color: darkgreen; padding-left: 5px; padding-right: 5px; \
          padding-top: 2px; padding-bottom: 2px; } \
          QToolBar QToolButton:hover { font-weight: bold; \
          background-color: QLinearGradient(x1: 0, y1: 0, x2: 1, y2: 2, \
          stop: 0 #006400, stop: 1 #FFDF5F); } \
          #toolbar { border: none; height: 100%; min-width: 150px; max-width: 150px; \
          background-color: darkgreen; } \
          QMenuBar { color: white; background-color: darkgreen; } \
          QMenuBar::item { color: white; background-color: transparent; \
          padding-top: 6px; padding-bottom: 6px; \
          padding-left: 10px; padding-right: 10px; } \
          QMenuBar::item:selected { background-color: QLinearGradient(x1: 0, y1: 0, x2: 1, y2: 2, \
          stop: 0 #006400, stop: 1 #FFDF5F); } \
          QMenu { border: 1px solid; background-color: ivory; color: black; } \
          QMenu::item { background-color: transparent; } \
          QMenu::item:selected { color: white; background-color: green; }");
    }

    // Accept D&D of URIs
    setAcceptDrops(true);

    // Create actions for the toolbar, menu bar and tray/dock icon
    createActions(nQtStyle);

    // Create application menu bar
    createMenuBar();

    // Create the toolbars
    createToolBars(nQtStyle);

    // Create the tray icon (or setup the dock icon)
    createTrayIcon();

    // Create tabs
    overviewPage = new OverviewPage();

    transactionsPage = new QWidget(this);
    QVBoxLayout *vbox = new QVBoxLayout();
    transactionView = new TransactionView(this);
    vbox->addWidget(transactionView);
    transactionsPage->setLayout(vbox);

    addressBookPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::SendingTab);

    receiveCoinsPage = new AddressBookPage(AddressBookPage::ForEditing, AddressBookPage::ReceivingTab);

    sendCoinsPage = new SendCoinsDialog(this);

    signVerifyMessageDialog = new SignVerifyMessageDialog(this);

    centralWidget = new QStackedWidget(this);
    centralWidget->addWidget(overviewPage);
    centralWidget->addWidget(transactionsPage);
    centralWidget->addWidget(addressBookPage);
    centralWidget->addWidget(receiveCoinsPage);
    centralWidget->addWidget(sendCoinsPage);
    setCentralWidget(centralWidget);

    // Create status bar
    statusBar();

    // Status bar notification icons
    QFrame *frameBlocks = new QFrame();
    frameBlocks->setContentsMargins(0,0,0,0);
    frameBlocks->setMinimumWidth(88);
    frameBlocks->setMaximumWidth(88);
    QHBoxLayout *frameBlocksLayout = new QHBoxLayout(frameBlocks);
    frameBlocksLayout->setContentsMargins(3,0,3,0);
    frameBlocksLayout->setSpacing(3);
    labelEncryptionIcon = new QLabel();
    labelStakeMining = new QLabel();
    labelConnectionsIcon = new QLabel();
    labelBlocksIcon = new QLabel();
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelEncryptionIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelStakeMining);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelConnectionsIcon);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelBlocksIcon);
    frameBlocksLayout->addStretch();

    // Progress bar and label for blocks download
    progressBarLabel = new QLabel();
    progressBarLabel->setVisible(false);
    progressBar = new QProgressBar();
    progressBar->setAlignment(Qt::AlignCenter);
    progressBar->setVisible(false);

    /* OS & theme independent style; widgets must be added prior to styling */
    progressBar->setStyleSheet("QProgressBar { color: black; background-color: transparent; border: 1px solid grey; border-radius: 2px; padding: 1px; text-align: center; } \
      QProgressBar::chunk { background: QLinearGradient(x1: 0, y1: 0, x2: 1, y2: 0, stop: 0 #FF7F00, stop: 1 #FFD77F); margin: 0px; }");  

    statusBar()->addWidget(progressBarLabel);
    statusBar()->addWidget(progressBar);
    statusBar()->addPermanentWidget(frameBlocks);

    // Clicking on a transaction on the overview page simply sends you to transaction history page
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), this, SLOT(gotoHistoryPage()));
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), transactionView, SLOT(focusTransaction(QModelIndex)));

    // Double-clicking on a transaction on the transaction history page shows details
    connect(transactionView, SIGNAL(doubleClicked(QModelIndex)), transactionView, SLOT(showDetails()));

    rpcConsole = new RPCConsole(this);
    connect(consoleAction, SIGNAL(triggered()), rpcConsole, SLOT(showConsole()));
    connect(trafficAction, SIGNAL(triggered()), rpcConsole, SLOT(showTraffic()));

    blockExplorer = new BlockExplorer(this);
    connect(explorerAction, SIGNAL(triggered()), blockExplorer, SLOT(gotoBlockExplorer()));

    // Clicking on "Verify Message" in the address book sends you to the verify message tab
    connect(addressBookPage, SIGNAL(verifyMessage(QString)), this, SLOT(gotoVerifyMessageTab(QString)));
    // Clicking on "Sign Message" in the receive coins page sends you to the sign message tab
    connect(receiveCoinsPage, SIGNAL(signMessage(QString)), this, SLOT(gotoSignMessageTab(QString)));

    /* Selecting block explorer in the transaction page menu redirects to the block explorer */ 
    connect(transactionView, SIGNAL(blockExplorerSignal(QString)), blockExplorer,
      SLOT(gotoBlockExplorer(QString)));

    gotoOverviewPage();
}

BitcoinGUI::~BitcoinGUI()
{
    if(trayIcon) // Hide tray icon, as deleting will let it linger until quit (on Ubuntu)
        trayIcon->hide();
#ifdef Q_OS_MAC
    delete appMenuBar;
#endif
}

void BitcoinGUI::createActions(int nQtStyle) {
    QActionGroup *tabGroup = new QActionGroup(this);

    overviewAction = new QAction(QIcon(":/icons/overview"), tr("&Overview"), this);
    overviewAction->setToolTip(tr("Show general overview of wallet"));
    overviewAction->setCheckable(true);
    overviewAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_1));
    tabGroup->addAction(overviewAction);
    connect(overviewAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(overviewAction, SIGNAL(triggered()), this, SLOT(gotoOverviewPage()));

    sendCoinsAction = new QAction(QIcon(":/icons/send"), tr("&Send"), this);
    sendCoinsAction->setToolTip(tr("Send coins to an Orbitcoin address"));
    sendCoinsAction->setCheckable(true);
    sendCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_2));
    tabGroup->addAction(sendCoinsAction);
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(gotoSendCoinsPage()));

    receiveCoinsAction = new QAction(QIcon(":/icons/receiving_addresses"), tr("&Receive"), this);
    receiveCoinsAction->setToolTip(tr("Show the list of addresses for receiving payments"));
    receiveCoinsAction->setCheckable(true);
    receiveCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_3));
    tabGroup->addAction(receiveCoinsAction);
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(gotoReceiveCoinsPage()));

    historyAction = new QAction(QIcon(":/icons/history"), tr("&Payments"), this);
    historyAction->setToolTip(tr("Browse your payment history"));
    historyAction->setCheckable(true);
    historyAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_4));
    tabGroup->addAction(historyAction);
    connect(historyAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(gotoHistoryPage()));

    addressBookAction = new QAction(QIcon(":/icons/address-book"), tr("&Addresses"), this);
    addressBookAction->setToolTip(tr("Edit the list of stored addresses and labels"));
    addressBookAction->setCheckable(true);
    addressBookAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_5));
    tabGroup->addAction(addressBookAction);
    connect(addressBookAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(addressBookAction, SIGNAL(triggered()), this, SLOT(gotoAddressBookPage()));

    consoleAction = new QAction(QIcon(":/icons/debugwindow"), tr("&Console"), this);
    consoleAction->setToolTip(tr("Open the RPC console"));
    consoleAction->setCheckable(false);
    consoleAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_6));
    tabGroup->addAction(consoleAction);
    /* RPC console action connected already */

    explorerAction = new QAction(QIcon(":/icons/explorer"), tr("&Explorer"), this);
    explorerAction->setToolTip(tr("Open the block explorer"));
    explorerAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_7));
    explorerAction->setCheckable(false);
    tabGroup->addAction(explorerAction);
    /* Block explorer action connected already */

    toggleHideAction = new QAction(QIcon(":/icons/orbitcoin"), tr("&Show / Hide"), this);
    connect(toggleHideAction, SIGNAL(triggered()), this, SLOT(toggleHidden()));

    cloneWalletAction = new QAction(QIcon(":/icons/filesave"), tr("&Clone"), this);
    connect(cloneWalletAction, SIGNAL(triggered()), this, SLOT(cloneWallet()));

    optionsAction = new QAction(QIcon(":/icons/options"), tr("&Options"), this);
    optionsAction->setMenuRole(QAction::PreferencesRole);
    connect(optionsAction, SIGNAL(triggered()), this, SLOT(optionsClicked()));

    lockWalletToggleAction = new QAction(QIcon(":/icons/lock_open"), tr("&Unlock"), this);
    connect(lockWalletToggleAction, SIGNAL(triggered()), this, SLOT(lockWalletToggle()));

    exportWalletAction = new QAction(QIcon(":/icons/key_export"), tr("&Export keys"), this);
    connect(exportWalletAction, SIGNAL(triggered()), this, SLOT(exportWallet()));

    importWalletAction = new QAction(QIcon(":/icons/key_import"), tr("&Import keys"), this);
    connect(importWalletAction, SIGNAL(triggered()), this, SLOT(importWallet()));

    quitAction = new QAction(QIcon(":/icons/quit"), tr("E&xit"), this);
    quitAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Q));
    quitAction->setMenuRole(QAction::QuitRole);
    connect(quitAction, SIGNAL(triggered()), qApp, SLOT(quit()));

    trafficAction = new QAction(QIcon(":/icons/traffic"), tr("&Network activity"), this);

    stakeMinerToggleAction = new QAction(this);
    stakeMinerToggle(true);
    connect(stakeMinerToggleAction, SIGNAL(triggered()), this, SLOT(stakeMinerToggle()));

    encryptWalletAction = new QAction(QIcon(":/icons/lock_closed"), tr("Encrypt &wallet"), this);
    encryptWalletAction->setCheckable(true);
    connect(encryptWalletAction, SIGNAL(triggered(bool)), this, SLOT(encryptWallet(bool)));

    changePassphraseAction = new QAction(QIcon(":/icons/key"), tr("&Change passphrase"), this);
    connect(changePassphraseAction, SIGNAL(triggered()), this, SLOT(changePassphrase()));

    inspectWalletAction = new QAction(QIcon(":/icons/inspect"), tr("&Inspect wallet"), this);
    connect(inspectWalletAction, SIGNAL(triggered()), this, SLOT(inspectWallet()));

    repairWalletAction = new QAction(QIcon(":/icons/repair"), tr("&Repair wallet"), this);
    connect(repairWalletAction, SIGNAL(triggered()), this, SLOT(repairWallet()));

    signMessageAction = new QAction(QIcon(":/icons/edit"), tr("&Sign message"), this);
    connect(signMessageAction, SIGNAL(triggered()), this, SLOT(gotoSignMessageTab()));

    verifyMessageAction = new QAction(QIcon(":/icons/transaction_0"), tr("&Verify message"), this);
    connect(verifyMessageAction, SIGNAL(triggered()), this, SLOT(gotoVerifyMessageTab()));

    exportAction = new QAction(QIcon(":/icons/export"), tr("E&xport"), this);
    exportAction->setToolTip(tr("Export the data in the current tab to a file"));
    /* Connected / disconnected on respective tab pages */

    aboutAction = new QAction(QIcon(":/icons/orbitcoin"), tr("&About Orbitcoin"), this);
    aboutAction->setMenuRole(QAction::AboutRole);
    connect(aboutAction, SIGNAL(triggered()), this, SLOT(aboutClicked()));

    aboutQtAction = new QAction(QIcon(":/icons/qt"), tr("About &Qt"), this);
    aboutQtAction->setMenuRole(QAction::AboutQtRole);
    connect(aboutQtAction, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
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

    // Configure the menus
    QMenu *wallet = appMenuBar->addMenu(tr("&Wallet"));
    wallet->addAction(cloneWalletAction);
    wallet->addAction(exportWalletAction);
    wallet->addAction(importWalletAction);
    wallet->addAction(optionsAction);
    wallet->addSeparator();
    wallet->addAction(lockWalletToggleAction);
    wallet->addSeparator();
    wallet->addAction(quitAction);

    QMenu *tools = appMenuBar->addMenu(tr("&Tools"));
    tools->addAction(consoleAction);
    tools->addAction(explorerAction);
    tools->addAction(trafficAction);
    tools->addSeparator();
    tools->addAction(stakeMinerToggleAction);
    tools->addSeparator();
    tools->addAction(encryptWalletAction);
    tools->addAction(changePassphraseAction);
    tools->addSeparator();
    tools->addAction(inspectWalletAction);
    tools->addAction(repairWalletAction);
    tools->addSeparator();
    tools->addAction(signMessageAction);
    tools->addAction(verifyMessageAction);
    tools->addSeparator();
    tools->addAction(exportAction);

    QMenu *help = appMenuBar->addMenu(tr("&Help"));
    help->addAction(aboutAction);
    help->addAction(aboutQtAction);
}

void BitcoinGUI::createToolBars(int nQtStyle)
{
    QToolBar *toolbar = addToolBar(tr("Primary tool bar"));
    toolbar->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
    toolbar->setMovable(false);
    toolbar->setIconSize(QSize(32, 32));

    if(!nQtStyle) {
        toolbar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    } else {
        toolbar->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
        toolbar->setObjectName("toolbar");
        addToolBar(Qt::LeftToolBarArea, toolbar);
        toolbar->setOrientation(Qt::Vertical);
    }

    toolbar->addAction(overviewAction);
    toolbar->addAction(sendCoinsAction);
    toolbar->addAction(receiveCoinsAction);
    toolbar->addAction(historyAction);
    toolbar->addAction(addressBookAction);
    toolbar->addAction(consoleAction);
    toolbar->addAction(explorerAction);

//    QToolBar *toolbar2 = addToolBar(tr("Actions toolbar"));
//    toolbar2->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
//    toolbar2->addAction(exportAction);
}

void BitcoinGUI::setClientModel(ClientModel *clientModel)
{
    this->clientModel = clientModel;
    if(clientModel)
    {
        // Replace some strings and icons, when using the testnet
        if(clientModel->isTestNet())
        {
            setWindowTitle(windowTitle() + QString(" ") + tr("[testnet]"));
#ifndef Q_OS_MAC
            qApp->setWindowIcon(QIcon(":icons/orbitcoin_testnet"));
            setWindowIcon(QIcon(":icons/orbitcoin_testnet"));
#else
            MacDockIconHandler::instance()->setIcon(QIcon(":icons/orbitcoin_testnet"));
#endif
            if(trayIcon)
            {
                trayIcon->setToolTip(tr("Orbitcoin client") + QString(" ") + tr("[testnet]"));
                trayIcon->setIcon(QIcon(":/icons/toolbar_testnet"));
                toggleHideAction->setIcon(QIcon(":/icons/toolbar_testnet"));
            }

            aboutAction->setIcon(QIcon(":/icons/toolbar_testnet"));
        }

        // Keep up to date with client
        setNumConnections(clientModel->getNumConnections());
        connect(clientModel, SIGNAL(numConnectionsChanged(int)), this, SLOT(setNumConnections(int)));

        setNumBlocks(clientModel->getNumBlocks(), clientModel->getNumBlocksOfPeers());
        connect(clientModel, SIGNAL(numBlocksChanged(int,int)), this, SLOT(setNumBlocks(int,int)));
        connect(clientModel, SIGNAL(numBlocksChanged(int,int)), this, SLOT(setStakeMining()));

        // Report errors from network/worker thread
        connect(clientModel, SIGNAL(error(QString,QString,bool)), this, SLOT(error(QString,QString,bool)));

        rpcConsole->setClientModel(clientModel);
        addressBookPage->setOptionsModel(clientModel->getOptionsModel());
        receiveCoinsPage->setOptionsModel(clientModel->getOptionsModel());
    }
}

void BitcoinGUI::setWalletModel(WalletModel *walletModel)
{
    this->walletModel = walletModel;
    if(walletModel)
    {
        // Report errors from wallet thread
        connect(walletModel, SIGNAL(error(QString,QString,bool)), this, SLOT(error(QString,QString,bool)));

        // Put transaction list in tabs
        transactionView->setModel(walletModel);

        overviewPage->setModel(walletModel);
        addressBookPage->setModel(walletModel->getAddressTableModel());
        receiveCoinsPage->setModel(walletModel->getAddressTableModel());
        sendCoinsPage->setModel(walletModel);
        signVerifyMessageDialog->setModel(walletModel);

        setEncryptionStatus(walletModel->getEncryptionStatus());
        connect(walletModel, SIGNAL(encryptionStatusChanged(int)), this, SLOT(setEncryptionStatus(int)));

        // Balloon pop-up for new transaction
        connect(walletModel->getTransactionTableModel(), SIGNAL(rowsInserted(QModelIndex,int,int)),
                this, SLOT(incomingTransaction(QModelIndex,int,int)));

        // Ask for passphrase if needed
        connect(walletModel, SIGNAL(requireUnlock()), this, SLOT(unlockWallet()));
    }
}

void BitcoinGUI::createTrayIcon()
{
    QMenu *trayIconMenu;
#ifndef Q_OS_MAC
    trayIcon = new QSystemTrayIcon(this);
    trayIconMenu = new QMenu(this);
    trayIcon->setContextMenu(trayIconMenu);
    trayIcon->setToolTip(tr("Orbitcoin client"));
    trayIcon->setIcon(QIcon(":/icons/toolbar"));
    connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
            this, SLOT(trayIconActivated(QSystemTrayIcon::ActivationReason)));
    trayIcon->show();
#else
    // Note: On Mac, the dock icon is used to provide the tray's functionality.
    MacDockIconHandler *dockIconHandler = MacDockIconHandler::instance();
    trayIconMenu = dockIconHandler->dockMenu();
#endif

    // Configuration of the tray icon (or dock icon) icon menu
    trayIconMenu->addAction(toggleHideAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(sendCoinsAction);
    trayIconMenu->addAction(receiveCoinsAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(signMessageAction);
    trayIconMenu->addAction(verifyMessageAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(optionsAction);
    trayIconMenu->addAction(consoleAction);
    trayIconMenu->addAction(explorerAction);
#ifndef Q_OS_MAC // This is built-in on Mac
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(quitAction);
#endif

    notificator = new Notificator(qApp->applicationName(), trayIcon);
}

#ifndef Q_OS_MAC
void BitcoinGUI::trayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if(reason == QSystemTrayIcon::Trigger)
    {
        // Click on system tray icon triggers show/hide of the main window
        toggleHideAction->trigger();
    }
}
#endif

void BitcoinGUI::optionsClicked()
{
    if(!clientModel || !clientModel->getOptionsModel())
        return;
    OptionsDialog dlg;
    dlg.setModel(clientModel->getOptionsModel());
    dlg.exec();
}

void BitcoinGUI::aboutClicked()
{
    AboutDialog dlg;
    dlg.setModel(clientModel);
    dlg.exec();
}

void BitcoinGUI::setStakeMining() {
    QString tooltip;
    bool fStakeIcon = true;

    if(!fStakeGen) {
        fStakeIcon = false;
        tooltip = tr("Staking disabled");
    } else {
        if(!clientModel->getNumConnections()) {
            fStakeIcon = false;
            tooltip = tr("Wallet is offline, staking paused");
        } else if(clientModel->inInitialBlockDownload()) {
            fStakeIcon = false;
            tooltip = tr("Wallet is synchronising, staking paused");
        } else if(walletModel->getEncryptionStatus() == WalletModel::Locked) {
            fStakeIcon = false;
            tooltip = tr("Wallet is locked, staking paused");
        } else {
            /* Caches the results for 10 minutes */
            if((GetTime() - 600) > nLastWalletStakeTime) {
                walletModel->getStakeWeight(nMinWeightInputs, nAvgWeightInputs, nMaxWeightInputs, nTotalStakeWeight);
                nLastWalletStakeTime = GetTime();
            } 
            if(!nTotalStakeWeight) {
                fStakeIcon = false;
                tooltip = tr("No mature coins found, staking paused");
            } else {
                fStakeIcon = true;
                tooltip = tr("Staking enabled for %1 inputs weighing %2 coin days") \
                  .arg(nMinWeightInputs + nAvgWeightInputs + nMaxWeightInputs).arg(nTotalStakeWeight);
                tooltip += QString("<br>");
                tooltip += tr("Inputs: %1 min. age, %2 avg. age, %3 max. age") \
                  .arg(nMinWeightInputs).arg(nAvgWeightInputs).arg(nMaxWeightInputs);
            }
        }
    }

    /* Don't wrap words */
    tooltip = QString("<nobr>") + tooltip + QString("</nobr>");

    labelStakeMining->setToolTip(tooltip);

    if(fStakeIcon)
      labelStakeMining->setPixmap(QIcon(":/icons/staking_on").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
    else
      labelStakeMining->setPixmap(QIcon(":/icons/staking_off").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
}

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
    labelConnectionsIcon->setPixmap(QIcon(icon).pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
    labelConnectionsIcon->setToolTip(tr("%n active connection(s) to the Orbitcoin network", "", count));
}

void BitcoinGUI::setNumBlocks(int count, int nTotalBlocks)
{
    // don't show / hide the progress bar and it's label if we have no connection(s) to the network
    if (!clientModel || clientModel->getNumConnections() == 0)
    {
        progressBarLabel->setVisible(false);
        progressBar->setVisible(false);

        return;
    }

    QString tooltip;
    QString strStatusBarWarnings = clientModel->getStatusBarWarnings();
    QDateTime lastBlockDate = clientModel->getLastBlockDate();
    QDateTime currentDate = QDateTime::currentDateTime();
    int secs = lastBlockDate.secsTo(currentDate);

    /* count > nTotalBlocks if the former is above the last checkpoint
     * and the median chain height of the peers connected is low */
    if(count < nTotalBlocks) {
        tooltip = tr("Processed %1 of %2 blocks of the transaction history").arg(count).arg(nTotalBlocks);
    } else {
        tooltip = tr("Processed %1 blocks of the transaction history").arg(count);
    }

    /* Taskbar icons: a spinner if catching up, a tick otherwise;
     * testnet is allowed to be well behind the current time */
    if(((secs < 90*60) || clientModel->isTestNet()) && count >= nTotalBlocks) {

        tooltip = tr("Up to date") + QString("<br>") + tooltip;
        labelBlocksIcon->setPixmap(QIcon(":/icons/synced").pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));

        tooltip += QString("<br>") + tr("The current PoW difficulty is %1").arg(clientModel->getDifficulty(false));
        tooltip += QString("<br>") + tr("The current PoS difficulty is %1").arg(clientModel->getDifficulty(true));

        progressBarLabel->setVisible(false);
        progressBar->setVisible(false);

        overviewPage->showOutOfSyncWarning(false);
    } else {
        /* Better represent time from the last generated block */
        QString timeBehindText;
        if(secs < 48*60*60) {
            timeBehindText = tr("%n hours","",secs/(60*60));
        } else if(secs < 14*24*60*60) {
            timeBehindText = tr("%n days","",secs/(24*60*60));
        } else {
            timeBehindText = tr("%n weeks","",secs/(7*24*60*60));
        }

        QString blocksBehindText = tr("%n blocks","", nTotalBlocks - count);


        if(strStatusBarWarnings.isEmpty()) {
            progressBarLabel->setText(tr("Synchronising with the network..."));
            progressBarLabel->setVisible(true);
            if(count < nTotalBlocks) {
                progressBar->setFormat(tr("%1 or %2 behind").arg(blocksBehindText).arg(timeBehindText));
                progressBar->setMaximum(nTotalBlocks);
            } else {
                progressBar->setFormat(tr("%1 behind").arg(timeBehindText));
                progressBar->setMaximum(count);

            }
            progressBar->setValue(count);
            progressBar->setVisible(true);
        } else {
            progressBarLabel->setText(clientModel->getStatusBarWarnings());
            progressBarLabel->setVisible(true);
            progressBar->setVisible(false);
        }

        tooltip = tr("Catching up...") + QString("<br>") + tooltip;
        if(count != prevBlocks) {
            labelBlocksIcon->setPixmap(QIcon(QString(
                ":/movies/spinner-%1").arg(spinnerFrame, 2, 10, QChar('0')))
                .pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
            spinnerFrame = (spinnerFrame + 1) % SPINNER_FRAMES;
        }
        prevBlocks = count;

        tooltip += QString("<br>");
        tooltip += tr("The last received block was generated %1 ago").arg(timeBehindText);
        tooltip += QString("<br>");
        tooltip += tr("Transactions after this will not yet be visible");

        overviewPage->showOutOfSyncWarning(true);
    }

    // Don't word-wrap this (fixed-width) tooltip
    tooltip = QString("<nobr>") + tooltip + QString("</nobr>");

    labelBlocksIcon->setToolTip(tooltip);
    progressBarLabel->setToolTip(tooltip);
    progressBar->setToolTip(tooltip);
}

void BitcoinGUI::error(const QString &title, const QString &message, bool modal)
{
    // Report errors from network/worker thread
    if(modal)
    {
        QMessageBox::critical(this, title, message, QMessageBox::Ok, QMessageBox::Ok);
    } else {
        notificator->notify(Notificator::Critical, title, message);
    }
}

void BitcoinGUI::changeEvent(QEvent *e)
{
    QMainWindow::changeEvent(e);
#ifndef Q_OS_MAC // Ignored on Mac
    if(e->type() == QEvent::WindowStateChange)
    {
        if(clientModel && clientModel->getOptionsModel()->getMinimizeToTray())
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
    if(clientModel)
    {
#ifndef Q_OS_MAC // Ignored on Mac
        if(!clientModel->getOptionsModel()->getMinimizeToTray() &&
           !clientModel->getOptionsModel()->getMinimizeOnClose())
        {
            qApp->quit();
        }
#endif
    }
    QMainWindow::closeEvent(event);
}

void BitcoinGUI::askFee(qint64 nFeeRequired, bool *payFee) {

    QString strMessage = tr(
      "This transaction is oversized. It is possible to send it for a fee of %1. "
      "Are you ready to pay?"
      ).arg(BitcoinUnits::formatWithUnit(BitcoinUnits::BTC, nFeeRequired));

    QMessageBox::StandardButton retval = QMessageBox::question(this,
      tr("Transaction fee request"), strMessage,
      QMessageBox::Yes|QMessageBox::Cancel, QMessageBox::Yes);

    *payFee = (retval == QMessageBox::Yes);
}

void BitcoinGUI::incomingTransaction(const QModelIndex & parent, int start, int end)
{
    if(!walletModel || !clientModel)
        return;
    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent)
                    .data(Qt::EditRole).toULongLong();
    if(!clientModel->inInitialBlockDownload())
    {
        // On new transaction, make an info balloon
        // Unless the initial block download is in progress, to Lastent balloon-spam
        QString date = ttm->index(start, TransactionTableModel::Date, parent)
                        .data().toString();
        QString type = ttm->index(start, TransactionTableModel::Type, parent)
                        .data().toString();
        QString address = ttm->index(start, TransactionTableModel::ToAddress, parent)
                        .data().toString();
        QIcon icon = qvariant_cast<QIcon>(ttm->index(start,
                            TransactionTableModel::ToAddress, parent)
                        .data(Qt::DecorationRole));

        notificator->notify(Notificator::Information,
                            (amount)<0 ? tr("Sent transaction") :
                                         tr("Incoming transaction"),
                              tr("Date: %1\n"
                                 "Amount: %2\n"
                                 "Type: %3\n"
                                 "Address: %4\n")
                              .arg(date)
                              .arg(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(), amount, true))
                              .arg(type)
                              .arg(address), icon);
    }
}

void BitcoinGUI::gotoOverviewPage()
{
    overviewAction->setChecked(true);
    centralWidget->setCurrentWidget(overviewPage);

    exportAction->setEnabled(false);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}

void BitcoinGUI::gotoHistoryPage()
{
    historyAction->setChecked(true);
    centralWidget->setCurrentWidget(transactionsPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), transactionView, SLOT(exportClicked()));
}

void BitcoinGUI::gotoAddressBookPage()
{
    addressBookAction->setChecked(true);
    centralWidget->setCurrentWidget(addressBookPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), addressBookPage, SLOT(exportClicked()));
}

void BitcoinGUI::gotoReceiveCoinsPage()
{
    receiveCoinsAction->setChecked(true);
    centralWidget->setCurrentWidget(receiveCoinsPage);

    exportAction->setEnabled(true);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
    connect(exportAction, SIGNAL(triggered()), receiveCoinsPage, SLOT(exportClicked()));
}

void BitcoinGUI::gotoSendCoinsPage()
{
    sendCoinsAction->setChecked(true);
    centralWidget->setCurrentWidget(sendCoinsPage);

    exportAction->setEnabled(false);
    disconnect(exportAction, SIGNAL(triggered()), 0, 0);
}

void BitcoinGUI::gotoSignMessageTab(QString addr)
{
    // call show() in showTab_SM()
    signVerifyMessageDialog->showTab_SM(true);

    if(!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void BitcoinGUI::gotoVerifyMessageTab(QString addr)
{
    // call show() in showTab_VM()
    signVerifyMessageDialog->showTab_VM(true);

    if(!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

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
        int nValidUrisFound = 0;
        QList<QUrl> uris = event->mimeData()->urls();
        foreach(const QUrl &uri, uris)
        {
            if (sendCoinsPage->handleURI(uri.toString()))
                nValidUrisFound++;
        }

        // if valid URIs were found
        if (nValidUrisFound)
            gotoSendCoinsPage();
        else
            notificator->notify(Notificator::Warning, tr("URI handling"), tr("URI can not be parsed! This can be caused by an invalid Orbitcoin address or malformed URI parameters."));
    }

    event->acceptProposedAction();
}

void BitcoinGUI::handleURI(QString strURI)
{
    // URI has to be valid
    if (sendCoinsPage->handleURI(strURI))
    {
        showNormalIfMinimized();
        gotoSendCoinsPage();
    }
    else
        notificator->notify(Notificator::Warning, tr("URI handling"), tr("URI can not be parsed! This can be caused by an invalid Orbitcoin address or malformed URI parameters."));
}

void BitcoinGUI::setEncryptionStatus(int status)
{
    switch(status)
    {
    case WalletModel::Unencrypted:
        labelEncryptionIcon->hide();
        encryptWalletAction->setChecked(false);
        encryptWalletAction->setEnabled(true);
        changePassphraseAction->setEnabled(false);
        lockWalletToggleAction->setEnabled(false);
        break;
    case(WalletModel::Unlocked):
    case(WalletModel::UnlockedStaking):
        labelEncryptionIcon->show();
        labelEncryptionIcon->setPixmap(QIcon(":/icons/lock_open").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        if(status == WalletModel::Unlocked)
          labelEncryptionIcon->setToolTip(tr("Wallet is encrypted and unlocked"));
        else
          labelEncryptionIcon->setToolTip(tr("Wallet is encrypted and unlocked for staking only"));
        encryptWalletAction->setChecked(true);
        encryptWalletAction->setEnabled(false);
        changePassphraseAction->setEnabled(true);
        lockWalletToggleAction->setIcon(QIcon(":/icons/lock_closed"));
        lockWalletToggleAction->setText(tr("&Lock"));
        break;
    case WalletModel::Locked:
        labelEncryptionIcon->show();
        labelEncryptionIcon->setPixmap(QIcon(":/icons/lock_closed").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        labelEncryptionIcon->setToolTip(tr("Wallet is encrypted and locked"));
        encryptWalletAction->setChecked(true);
        encryptWalletAction->setEnabled(false);
        changePassphraseAction->setEnabled(true);
        lockWalletToggleAction->setIcon(QIcon(":/icons/lock_open"));
        lockWalletToggleAction->setText(tr("&Unlock"));
        break;
    }
    setStakeMining();
}

void BitcoinGUI::encryptWallet(bool status)
{
    if(!walletModel)
        return;
    AskPassphraseDialog dlg(status ? AskPassphraseDialog::Encrypt:
                                     AskPassphraseDialog::Decrypt, this);
    dlg.setModel(walletModel);
    dlg.exec();

    setEncryptionStatus(walletModel->getEncryptionStatus());
}

void BitcoinGUI::cloneWallet() {

   if(!walletModel)
     return;

   WalletModel::UnlockContext ctx(walletModel->requestUnlock());
   if(!ctx.isValid())
     return;

#if (QT_VERSION < 0x050000)
    QString saveDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
    QString saveDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif

    QString filename = QFileDialog::getSaveFileName(this, tr("Clone Wallet"), saveDir, tr("Wallet Data (*.dat)"));
    if(!filename.isEmpty()) {
        if(walletModel->cloneWallet(filename)) {
            QMessageBox::information(this,
              tr("Cloning Complete"),
              tr("A copy of your wallet has been saved to:<br>%1").arg(filename));
        } else {
            QMessageBox::critical(this,
              tr("Cloning Failed"),
              tr("There was an error while making a copy of your wallet."));
        }
    }
}

void BitcoinGUI::exportWallet() {

   if(!walletModel)
     return;

   WalletModel::UnlockContext ctx(walletModel->requestUnlock());
   if(!ctx.isValid())
     return;

#if (QT_VERSION < 0x050000)
    QString saveDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
    QString saveDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif

    QString filename = QFileDialog::getSaveFileName(this, tr("Export Wallet Keys"), saveDir, tr("Wallet Text (*.txt)"));
    if(!filename.isEmpty()) {
        if(walletModel->exportWallet(filename)) {
            QMessageBox::information(this,
              tr("Export Complete"),
              tr("All keys of your wallet have been exported into:<br>%1").arg(filename));
        } else {
            QMessageBox::critical(this,
              tr("Export Failed"),
              tr("There was an error while exporting your wallet keys."));
        }
    }
}

void BitcoinGUI::importWallet() {

   if(!walletModel)
     return;


   WalletModel::UnlockContext ctx(walletModel->requestUnlock());
   if(!ctx.isValid())
     return;

#if (QT_VERSION < 0x050000)
    QString openDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
#else
    QString openDir = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
#endif

    QString filename = QFileDialog::getOpenFileName(this, tr("Import Wallet Keys"), openDir, tr("Wallet Text (*.txt)"));
    if(!filename.isEmpty()) {
        if(walletModel->importWallet(filename)) {
            QMessageBox::information(this,
              tr("Import Complete"),
              tr("All keys have been imported into your wallet from:<br>%1").arg(filename));
        } else {
            QMessageBox::critical(this,
              tr("Import Failed"),
              tr("There was an error while importing wallet keys from:<br>%1").arg(filename));
        }
    }
}

void BitcoinGUI::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void BitcoinGUI::unlockWallet()
{
    if(!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if(walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}

void BitcoinGUI::lockWalletToggle() {

    if(!walletModel)
      return;

    if(walletModel->getEncryptionStatus() == WalletModel::Locked) {
        AskPassphraseDialog dlg(AskPassphraseDialog::UnlockStaking, this);
        dlg.setModel(walletModel);
        dlg.exec();
    } else {
        walletModel->setWalletLocked(true);
    }
}

/* Enables or disables the internal stake miner;
 * only sets the menu icon and text on the initial run */
void BitcoinGUI::stakeMinerToggle(bool fInitial) {
    bool fStakeGenInt = fStakeGen;

    if(fInitial) {
        fStakeGenInt = GetBoolArg("-stakegen", fStakeGen);
        fStakeGenInt = ~fStakeGenInt & 0x1;
    }

    if(fStakeGenInt) {
        if(!fInitial) fStakeGen = false;
        stakeMinerToggleAction->setIcon(QIcon(":/icons/staking_on"));
        stakeMinerToggleAction->setText(tr("&Enable PoS mining"));
    } else {
        if(!fInitial) fStakeGen = true;
        stakeMinerToggleAction->setIcon(QIcon(":/icons/staking_off"));
        stakeMinerToggleAction->setText(tr("&Disable PoS mining"));
    }

    if(!fInitial)
      setStakeMining();
}

void BitcoinGUI::showNormalIfMinimized(bool fToggleHidden)
{
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

void BitcoinGUI::inspectWallet() {
    int nMismatchSpent;
    int nOrphansFound;
    int64 nBalanceInQuestion;

    if(!walletModel)
      return;

    walletModel->repairWallet(nMismatchSpent, nOrphansFound, nBalanceInQuestion, true);

    if(!nMismatchSpent && !nOrphansFound)
      notificator->notify(Notificator::Warning,
        tr("Wallet Inspection Report"),
        tr("Integrity test passed, nothing to fix.\n"));
    else
      notificator->notify(Notificator::Warning,
        tr("Wallet Inspection Report"),
        tr("Integrity test failed!\n\n"
           "Orphans found: %1\n"
           "Mismatched outputs detected: %2\n"
           "Amount in question: %3\n\n"
           "Please clone your wallet and repair it.\n")
        .arg(nOrphansFound)
        .arg(nMismatchSpent)
        .arg(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(),
          nBalanceInQuestion, true)));
}

void BitcoinGUI::repairWallet() {
    int nMismatchSpent;
    int nOrphansFound;
    int64 nBalanceInQuestion;

    if(!walletModel)
      return;

    walletModel->repairWallet(nMismatchSpent, nOrphansFound, nBalanceInQuestion, false);

    if(!nMismatchSpent && !nOrphansFound)
      notificator->notify(Notificator::Warning,
        tr("Wallet Repair Report"),
        tr("Integrity test passed, nothing to fix.\n"));
    else
      notificator->notify(Notificator::Warning,
        tr("Wallet Repair Report"),
        tr("Wallet repaired successfully!\n\n"
           "Orphans removed: %1\n"
           "Mismatched outputs corrected: %2\n"
           "Amount affected by repair: %3\n")
        .arg(nOrphansFound)
        .arg(nMismatchSpent)
        .arg(BitcoinUnits::formatWithUnit(walletModel->getOptionsModel()->getDisplayUnit(),
          nBalanceInQuestion, true)));
}

