#define BOOST_TEST_MODULE Orbitcoin Test Suite
#include <boost/test/unit_test.hpp>
#include <boost/filesystem.hpp>

#include "db.h"
#include "txdb.h"
#include "wallet.h"
#include "util.h"

/* All unresolved externs of init.cpp */
unsigned int nMsgSleep = 20;
unsigned int nMinerSleep = 2000;
uint nStakeMinTime = 48;
uint nStakeMinDepth = 0;
unsigned int nNodeLifespan = 7;
unsigned int nDerivationMethodIndex = 0;

CWallet* pwalletMain;
CClientUIInterface uiInterface;

extern bool fPrintToConsole;
extern void noui_connect();

struct TestingSetup {
    CCoinsViewDB *pcoinsdbview;
    boost::filesystem::path pathTemp;
    boost::thread_group threadGroup;

    TestingSetup() {
        fPrintToDebugger = true; // don't want to write to debug.log file
        noui_connect();
        bitdb.MakeMock();
        pathTemp = GetTempPath() / strprintf("test_orbitcoin_%lu_%i", (unsigned long)GetTime(), (int)(GetRand(100000)));
        boost::filesystem::create_directories(pathTemp);
        mapArgs["-datadir"] = pathTemp.string();
        pblocktree = new CBlockTreeDB(true);
        pcoinsdbview = new CCoinsViewDB(true);
        pcoinsTip = new CCoinsViewCache(*pcoinsdbview);
        LoadBlockIndex();
        bool fFirstRun;
        pwalletMain = new CWallet("wallet.dat");
        pwalletMain->LoadWallet(fFirstRun);
        RegisterWallet(pwalletMain);
    }
    ~TestingSetup()
    {
        threadGroup.interrupt_all();
        threadGroup.join_all();
        delete pwalletMain;
        pwalletMain = NULL;
        delete pcoinsTip;
        delete pcoinsdbview;
        delete pblocktree;
        bitdb.Flush(true);
        boost::filesystem::remove_all(pathTemp);
    }
};

BOOST_GLOBAL_FIXTURE(TestingSetup);

void Shutdown(void* parg)
{
  exit(0);
}

void StartShutdown()
{
  exit(0);
}

