// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alert.h"
#include "checkpoints.h"
#include "db.h"
#include "txdb.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
#include "kernel.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>


using namespace std;
using namespace boost;

//
// Global state
//

CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CTxMemPool mempool;
unsigned int nTransactionsUpdated = 0;

map<uint256, CBlockIndex*> mapBlockIndex;
set<pair<COutPoint, unsigned int> > setStakeSeen;

CBigNum bnProofOfWorkLimit(~uint256(0) >> 20); // 0.000244140625 PoW difficulty is the lowest possible
CBigNum bnProofOfStakeLimit(~uint256(0) >> 20); // the same for PoS
uint256 nPoWBase = uint256("0x00000000ffff0000000000000000000000000000000000000000000000000000"); // difficulty-1 target

CBigNum bnProofOfWorkLimitTestNet(~uint256(0) >> 16);
CBigNum bnProofOfStakeLimitTestNet(~uint256(0) >> 16);

/* [Initial] positive time weight after 5 days for livenet */
uint nStakeMinAgeOne = 5 * 24 * 60 * 60;
/* [Current] positive time weight after 1 day for livenet */
uint nStakeMinAgeTwo = 1 * 24 * 60 * 60;
/* The time weight limit is 15 days after the min. age for livenet */
uint nStakeMaxAge = 15 * 24 * 60 * 60;

/* [Initial] interval of 6 hours between stake modifiers for livenet */
uint nModifierIntervalOne = 6 * 60 * 60;
/* [Previous] interval of 3 hours between stake modifiers for livenet */
uint nModifierIntervalTwo = 3 * 60 * 60;
/* [Current] interval of 40 minutes between stake modifiers for livenet */
uint nModifierIntervalThree = 40 * 60;

/* Try to combine inputs while staking up to this limit */
int64 nCombineThreshold = MIN_STAKE_AMOUNT;
/* Don't split outputs while staking below this limit */
int64 nSplitThreshold = 2 * MIN_STAKE_AMOUNT;

/* The base time unit is 30 seconds */
const uint nBaseTargetSpacing = 30;

int nBaseMaturity = BASE_MATURITY;
CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;

uint256 nBestChainTrust = 0;
uint256 nBestInvalidTrust = 0;

uint256 hashBestChain = 0;
CBlockIndex* pindexBest = NULL;
int64 nTimeBestReceived = 0;
set<CBlockIndex*, CBlockIndexTrustComparator> setBlockIndexValid; // may contain all CBlockIndex*'s that have validness >=BLOCK_VALID_TRANSACTIONS, and must contain those who aren't failed

CMedianFilter<int> cPeerBlockCounts(5, 0); // Amount of blocks that other nodes claim to have

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;
set<pair<COutPoint, unsigned int> > setStakeSeenOrphan;
map<uint256, uint256> mapProofOfStake;

map<uint256, CTransaction> mapOrphanTransactions;
map<uint256, set<uint256> > mapOrphanTransactionsByPrev;

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "Orbitcoin Signed Message:\n";

// Settings
int64 nTransactionFee = MIN_TX_FEE;
int64 nMinimumInputValue = TX_DUST;
int64 nStakeMinValue = 1 * COIN;

extern enum Checkpoints::CPMode CheckpointsMode;

//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets


void RegisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.insert(pwalletIn);
    }
}

void UnregisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.erase(pwalletIn);
    }
}

// check whether the passed transaction is from us
bool static IsFromMe(CTransaction& tx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->IsFromMe(tx))
            return true;
    return false;
}

// get the wallet transaction with the given hash (if it exists)
bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->GetTransaction(hashTx,wtx))
            return true;
    return false;
}

// erases transaction with the given hash from all wallets
void static EraseFromWallets(uint256 hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->EraseFromWallet(hash);
}

// make sure all wallets know about the given transaction, in the given block
void SyncWithWallets(const uint256 &hash, const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fConnect)
{
    if (!fConnect)
    {
        // ppcoin: wallets need to refund inputs when disconnecting coinstake
        if (tx.IsCoinStake())
        {
            BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
                if (pwallet->IsFromMe(tx))
                    pwallet->DisableTransaction(tx);
        }
        return;
    }

    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->AddToWalletIfInvolvingMe(hash, tx, pblock, fUpdate);
}

// notify wallets about a new best chain
void static SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

// notify wallets about an updated transaction
void static UpdatedTransaction(const uint256& hashTx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

// dump all wallets
void static PrintWallets(const CBlock& block)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->PrintWallet(block);
}

// notify wallets about an incoming inventory (for request counts)
void static Inventory(const uint256& hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->Inventory(hash);
}

// ask wallets to resend their transactions
void ResendWalletTransactions(bool fForce)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->ResendWalletTransactions(fForce);
}


//////////////////////////////////////////////////////////////////////////////
//
// CCoinsView implementations
//

bool CCoinsView::GetCoins(uint256 txid, CCoins &coins) { return false; }
bool CCoinsView::SetCoins(uint256 txid, const CCoins &coins) { return false; }
bool CCoinsView::HaveCoins(uint256 txid) { return false; }
CBlockIndex *CCoinsView::GetBestBlock() { return NULL; }
bool CCoinsView::SetBestBlock(CBlockIndex *pindex) { return false; }
bool CCoinsView::BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex) { return false; }
bool CCoinsView::GetStats(CCoinsStats &stats) { return false; }

CCoinsViewBacked::CCoinsViewBacked(CCoinsView &viewIn) : base(&viewIn) { }
bool CCoinsViewBacked::GetCoins(uint256 txid, CCoins &coins) { return base->GetCoins(txid, coins); }
bool CCoinsViewBacked::SetCoins(uint256 txid, const CCoins &coins) { return base->SetCoins(txid, coins); }
bool CCoinsViewBacked::HaveCoins(uint256 txid) { return base->HaveCoins(txid); }
CBlockIndex *CCoinsViewBacked::GetBestBlock() { return base->GetBestBlock(); }
bool CCoinsViewBacked::SetBestBlock(CBlockIndex *pindex) { return base->SetBestBlock(pindex); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::GetStats(CCoinsStats &stats) { return base->GetStats(stats); }

bool CCoinsViewBacked::BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex) { return base->BatchWrite(mapCoins, pindex); }

CCoinsViewCache::CCoinsViewCache(CCoinsView &baseIn, bool fDummy) : CCoinsViewBacked(baseIn), pindexTip(NULL) { }

bool CCoinsViewCache::GetCoins(uint256 txid, CCoins &coins) {
    if (cacheCoins.count(txid)) {
        coins = cacheCoins[txid];
        return true;
    }
    if (base->GetCoins(txid, coins)) {
        cacheCoins[txid] = coins;
        return true;
    }
    return false;
}

// Select coins from read-only cache or database
bool CCoinsViewCache::GetCoinsReadOnly(uint256 txid, CCoins &coins) {
    if (cacheCoins.count(txid)) {
        coins = cacheCoins[txid]; // get from cache
        return true;
    }
    if (cacheCoinsReadOnly.count(txid)) {
        coins = cacheCoinsReadOnly[txid]; // get from read-only cache
        return true;
    }
    if (base->GetCoins(txid, coins)) {
        cacheCoinsReadOnly[txid] = coins; // save to read-only cache
        return true;
    }
    return false;
}

std::map<uint256,CCoins>::iterator CCoinsViewCache::FetchCoins(uint256 txid) {
    std::map<uint256,CCoins>::iterator it = cacheCoins.find(txid);
    if (it != cacheCoins.end())
        return it;
    CCoins tmp;
    if (!base->GetCoins(txid,tmp))
        return it;
    std::pair<std::map<uint256,CCoins>::iterator,bool> ret = cacheCoins.insert(std::make_pair(txid, tmp));
    return ret.first;
}

CCoins &CCoinsViewCache::GetCoins(uint256 txid) {
    std::map<uint256,CCoins>::iterator it = FetchCoins(txid);
    assert(it != cacheCoins.end());
    return it->second;
}

bool CCoinsViewCache::SetCoins(uint256 txid, const CCoins &coins) {
    cacheCoins[txid] = coins;
    return true;
}

bool CCoinsViewCache::HaveCoins(uint256 txid) {
    return FetchCoins(txid) != cacheCoins.end();
}

CBlockIndex *CCoinsViewCache::GetBestBlock() {
    if (pindexTip == NULL)
        pindexTip = base->GetBestBlock();
    return pindexTip;
}

bool CCoinsViewCache::SetBestBlock(CBlockIndex *pindex) {
    pindexTip = pindex;
    return true;
}

bool CCoinsViewCache::BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex) {
    for (std::map<uint256, CCoins>::const_iterator it = mapCoins.begin(); it != mapCoins.end(); it++)
        cacheCoins[it->first] = it->second;
    pindexTip = pindex;
    return true;
}

bool CCoinsViewCache::Flush() {
    cacheCoinsReadOnly.clear(); // purge read-only cache

    bool fOk = base->BatchWrite(cacheCoins, pindexTip);
    if (fOk)
        cacheCoins.clear();
    return fOk;
}

unsigned int CCoinsViewCache::GetCacheSize() {
    return cacheCoins.size();
}

/** CCoinsView that brings transactions from a memorypool into view.
    It does not check for spendings by memory pool transactions. */
CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView &baseIn, CTxMemPool &mempoolIn) : CCoinsViewBacked(baseIn), mempool(mempoolIn) { }

bool CCoinsViewMemPool::GetCoins(uint256 txid, CCoins &coins) {
    if (base->GetCoins(txid, coins))
        return true;
    if (mempool.exists(txid)) {
        const CTransaction &tx = mempool.lookup(txid);
        coins = CCoins(tx, MEMPOOL_HEIGHT, -1);
        return true;
    }
    return false;
}

bool CCoinsViewMemPool::HaveCoins(uint256 txid) {
    return mempool.exists(txid) || base->HaveCoins(txid);
}

CCoinsViewCache *pcoinsTip = NULL;
CBlockTreeDB *pblocktree = NULL;

//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CTransaction& tx)
{
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:

    size_t nSize = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);

    if (nSize > 5000)
    {
        printf("ignoring large orphan tx (size: %" PRIszu ", hash: %s)\n",
          nSize, hash.ToString().substr(0,10).c_str());
        return false;
    }

    mapOrphanTransactions[hash] = tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);

    printf("stored orphan tx %s (mapsz %" PRIszu ")\n",
      hash.ToString().substr(0,10).c_str(), mapOrphanTransactions.size());

    return true;
}

void static EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CTransaction& tx = mapOrphanTransactions[hash];
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        mapOrphanTransactionsByPrev[txin.prevout.hash].erase(hash);
        if (mapOrphanTransactionsByPrev[txin.prevout.hash].empty())
            mapOrphanTransactionsByPrev.erase(txin.prevout.hash);
    }
    mapOrphanTransactions.erase(hash);
}

unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, CTransaction>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}







//////////////////////////////////////////////////////////////////////////////
//
// CTransaction
//

bool CTransaction::IsStandard() const
{
    if (nVersion > CTransaction::CURRENT_VERSION)
        return false;

    // Disallow large transaction comments
    if(strTxComment.length() > MAX_TX_COMMENT_LEN) return false;

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // Biggest 'standard' txin is a 3-signature 3-of-3 CHECKMULTISIG
        // pay-to-script-hash, which is 3 ~80-byte signatures, 3
        // ~65-byte public keys, plus a few script ops.
        if (txin.scriptSig.size() > 500)
            return false;
        if (!txin.scriptSig.IsPushOnly())
            return false;
    }
    BOOST_FOREACH(const CTxOut& txout, vout) {
        if (!::IsStandard(txout.scriptPubKey))
            return false;
        if (txout.nValue == 0)
            return false;
    }
    return true;
}

//
// Check transaction inputs, and make sure any
// pay-to-script-hash transactions are evaluating IsStandard scripts
//
// Why bother? To avoid denial-of-service attacks; an attacker
// can submit a standard HASH... OP_EQUAL transaction,
// which will get accepted into blocks. The redemption
// script can be anything; an attacker could use a very
// expensive-to-check-upon-redemption script like:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1
//
bool CTransaction::AreInputsStandard(CCoinsViewCache& mapInputs) const
{
    if (IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut& prev = GetOutputFor(vin[i], mapInputs);

        vector<vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig the
        // IsStandard() call returns false
        vector<vector<unsigned char> > stack;
        if(!EvalScript(stack, vin[i].scriptSig, *this, i, SCRIPT_VERIFY_NONE, 0))
          return(false);

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            vector<vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (!Solver(subscript, whichType2, vSolutions2))
                return false;
            if (whichType2 == TX_SCRIPTHASH)
                return false;

            int tmpExpected;
            tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
            if (tmpExpected < 0)
                return false;
            nArgsExpected += tmpExpected;
        }

        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

unsigned int
CTransaction::GetLegacySigOpCount() const
{
    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}


int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    if (fClient)
    {
        if (hashBlock == 0)
            return 0;
    }
    else
    {
        CBlock blockTmp;
        if (pblock == NULL) {
            CCoins coins;
            if (pcoinsTip->GetCoins(GetHash(), coins)) {
                CBlockIndex *pindex = FindBlockByHeight(coins.nHeight);
                if (pindex) {
                    if (!blockTmp.ReadFromDisk(pindex))
                        return 0;
                    pblock = &blockTmp;
                }
            }
        }

        if (pblock) {
        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == (int)pblock->vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
        }
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}

bool CTransaction::CheckTransaction() const
{
    // Basic checks that don't depend on any context
    if (vin.empty())
        return DoS(10, error("CTransaction::CheckTransaction() : vin empty"));
    if (vout.empty())
        return DoS(10, error("CTransaction::CheckTransaction() : vout empty"));
    // Size limits
    if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return DoS(100, error("CTransaction::CheckTransaction() : size limits failed"));

    // Check for negative or overflow output values
    int64 nValueOut = 0;
    for (unsigned int i = 0; i < vout.size(); i++)
    {
        const CTxOut& txout = vout[i];
        if(txout.IsEmpty() && !IsCoinBase() && !IsCoinStake())
          return DoS(100, error("CTransaction::CheckTransaction() : non-base transaction with an empty output"));
        if(txout.nValue < 0)
          return DoS(100, error("CTransaction::CheckTransaction() : transaction output is negative"));
        nValueOut += txout.nValue;
        if(!MoneyRange(nValueOut))
          return DoS(100, error("CTransaction::CheckTransaction() : transaction amount is out of range"));
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return false;
        vInOutPoints.insert(txin.prevout);
    }

    if (IsCoinBase())
    {
        if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
            return DoS(100, error("CTransaction::CheckTransaction() : coinbase script size is invalid"));
    }
    else
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (txin.prevout.IsNull())
                return DoS(10, error("CTransaction::CheckTransaction() : prevout is null"));
    }

    return true;
}

int64 CTransaction::GetMinFee(unsigned int nBytes, bool fAllowFree,
                              enum GetMinFee_mode mode) const
{
    // Base fee is either MIN_TX_FEE or MIN_RELAY_TX_FEE
    int64 nBaseFee = (mode == GMF_RELAY) ? MIN_RELAY_TX_FEE : MIN_TX_FEE;

    unsigned int nNewBlockSize = (mode == GMF_SEND) ? nBytes : 1000 + nBytes;
    // Add a base fee per every 1000 bytes of transaction data
    int64 nMinFee = (1 + (int64)nBytes / 1000) * nBaseFee;

    if(fAllowFree) {
        if(mode == GMF_SEND) {
            // Limit size of free high priority transactions
            if(nBytes < 2000) nMinFee = 0;
        } else {
            // GMF_BLOCK, GMF_RELAY:
            // Limit block space for free transactions
            if(nNewBlockSize < 11000) nMinFee = 0;
        }
    }

    // Dust spam filter: require a base fee for any micro output
    BOOST_FOREACH(const CTxOut& txout, vout)
      if(txout.nValue < TX_DUST) nMinFee += nBaseFee;

    // Raise the price as the block approaches full
    if((mode != GMF_SEND) && (nNewBlockSize >= MAX_BLOCK_SIZE_GEN/2)) {
        if(nNewBlockSize >= MAX_BLOCK_SIZE_GEN) return MAX_MONEY;
        nMinFee *= MAX_BLOCK_SIZE_GEN / (MAX_BLOCK_SIZE_GEN - nNewBlockSize);
        if(!MoneyRange(nMinFee)) nMinFee = MAX_MONEY;
    }

    /* Transactions with comments require additional fees to deal with spam */
    uint nCommentLength = strTxComment.length();
    if(nCommentLength) {
        if(nCommentLength > 15)
          /* Long comment, high fee */
          nMinFee += 10 * nBaseFee;
        else
          /* Short comment, low fee */
          nMinFee += nBaseFee;
    }

    return(nMinFee);
}

void CTxMemPool::pruneSpent(const uint256 &hashTx, CCoins &coins)
{
    LOCK(cs);

    std::map<COutPoint, CInPoint>::iterator it = mapNextTx.lower_bound(COutPoint(hashTx, 0));

    // iterate over all COutPoints in mapNextTx whose hash equals the provided hashTx
    while (it != mapNextTx.end() && it->first.hash == hashTx) {
        coins.Spend(it->first.n); // and remove those outputs from coins
        it++;
    }
}

bool CTxMemPool::accept(CTransaction &tx, bool fCheckInputs, bool* pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!tx.CheckTransaction())
        return error("CTxMemPool::accept() : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return tx.DoS(100, error("CTxMemPool::accept() : coinbase as individual tx"));

    // Coinstake is also only valid in a block, not as a loose transaction
    if (tx.IsCoinStake())
        return tx.DoS(100, error("CTxMemPool::accept() : coinstake as individual tx"));

    // To help v0.1.5 clients who would see it as a negative number
    if ((int64)tx.nLockTime > std::numeric_limits<int>::max())
        return error("CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");

    // Rather not work on nonstandard transactions (unless -testnet)
    if (!fTestNet && !tx.IsStandard())
        return error("CTxMemPool::accept() : nonstandard transaction type");

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();
    {
        LOCK(cs);
        if (mapTx.count(hash))
            return false;
    }

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        COutPoint outpoint = tx.vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;

            // Allow replacing with a newer version of the same transaction
            if (i != 0)
                return false;
            ptxOld = mapNextTx[outpoint].ptx;
            if (ptxOld->IsFinal())
                return false;
            if (!tx.IsNewerThan(*ptxOld))
                return false;
            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                COutPoint outpoint = tx.vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
                    return false;
            }
            break;
        }
    }

    if (fCheckInputs)
    {
        CCoinsViewCache &view = *pcoinsTip;

        // do we already have it?
        if (view.HaveCoins(hash))
            return false;

        // do all inputs exist?
        BOOST_FOREACH(const CTxIn txin, tx.vin) {
            if (!view.HaveCoins(txin.prevout.hash)) {
                if (pfMissingInputs)
                    *pfMissingInputs = true;
                return false;
            }
        }

        if (!tx.HaveInputs(view))
            return error("CTxMemPool::accept() : inputs already spent");

        // Check for non-standard pay-to-script-hash in inputs
        if (!tx.AreInputsStandard(view) && !fTestNet)
            return error("CTxMemPool::accept() : nonstandard transaction input");

        // Note: if you modify this code to accept non-standard transactions, then
        // you should add code here to check that the transaction does a
        // reasonable number of ECDSA signature verifications.

        int64 nFees = tx.GetValueIn(view)-tx.GetValueOut();
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

        // Don't accept it if it can't get into a block
        // The default setting is to allow free transactions
        int64 txMinFee = tx.GetMinFee(nSize, true, GMF_RELAY);
        if(nFees < txMinFee)
          return(error("CTxMemPool::accept() : not enough fees for tx %s, %" PRI64d " < %" PRI64d,
            hash.ToString().c_str(), nFees, txMinFee));


        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (nFees < MIN_RELAY_TX_FEE)
        {
            static CCriticalSection cs;
            static double dFreeCount;
            static int64 nLastTime;
            int64 nNow = GetTime();

            {
                LOCK(cs);
                // Use an exponentially decaying ~10-minute window:
                dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
                nLastTime = nNow;
                // -limitfreerelay unit is thousand-bytes-per-minute
                // At default rate it would take over a month to fill 1GB
                if (dFreeCount > GetArg("-limitfreerelay", 15)*10*1000 && !IsFromMe(tx))
                    return error("CTxMemPool::accept() : free transaction rejected by rate limiter");
                if (fDebug)
                    printf("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
                dFreeCount += nSize;
            }
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if(!tx.CheckInputs(view, CS_ALWAYS,
          SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_DERSIG)) {
            return error("CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().substr(0,10).c_str());
        }
    }

    // Store transaction in memory
    {
        LOCK(cs);
        if (ptxOld)
        {
            printf("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            remove(*ptxOld);
        }
        addUnchecked(hash, tx);
    }

    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    if (ptxOld)
        EraseFromWallets(ptxOld->GetHash());

    printf("CTxMemPool::accept() : accepted tx %s (poolsz %" PRIszu ")\n",
      hash.ToString().substr(0,10).c_str(), mapTx.size());

    return true;
}

bool CTransaction::AcceptToMemoryPool(bool fCheckInputs, bool* pfMissingInputs)
{
    return mempool.accept(*this, fCheckInputs, pfMissingInputs);
}

bool CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call CTxMemPool::accept to properly check the transaction first.
    {
        mapTx[hash] = tx;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
            mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}


bool CTxMemPool::remove(CTransaction &tx)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        uint256 hash = tx.GetHash();
        if (mapTx.count(hash))
        {
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
                mapNextTx.erase(txin.prevout);
            mapTx.erase(hash);
            nTransactionsUpdated++;
        }
    }
    return true;
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    ++nTransactionsUpdated;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}

/* Returns a transaction depth in the main chain or
 *  0 = in the memory pool, not yet in the main chain
 * -1 = failed transaction */
int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet) const {
    bool fTxMempool = mempool.exists(GetHash());

    if((hashBlock == 0) || (nIndex == -1))
      return(fTxMempool ? 0 : -1);

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if(mi == mapBlockIndex.end())
      return(fTxMempool ? 0 : -1);

    CBlockIndex* pindex = (*mi).second;
    if(!pindex || !pindex->IsInMainChain())
      return(fTxMempool ? 0 : -1);

    // Make sure the merkle branch connects to this block
    if(!fMerkleVerified) {
        if(CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
          return(fTxMempool ? 0 : -1);
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return(pindexBest->nHeight - pindex->nHeight + 1);
}

int CMerkleTx::GetBlocksToMaturity() const
{
    if (!(IsCoinBase() || IsCoinStake()))
        return 0;
    return max(0, (nBaseMaturity + 1) - GetDepthInMainChain());
}


bool CMerkleTx::AcceptToMemoryPool(bool fCheckInputs)
{
    if (fClient)
    {
        if (!IsInMainChain() && !ClientCheckInputs())
            return false;
        return CTransaction::AcceptToMemoryPool(false);
    }
    else
    {
        return CTransaction::AcceptToMemoryPool(fCheckInputs);
    }
}

bool CWalletTx::AcceptWalletTransaction(bool fCheckInputs)
{

    {
        LOCK(mempool.cs);
        // Add previous supporting transactions first
        BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
        {
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
            {
                uint256 hash = tx.GetHash();
                if (!mempool.exists(hash) && pcoinsTip->HaveCoins(hash))
                    tx.AcceptToMemoryPool(fCheckInputs);
            }
        }
        return AcceptToMemoryPool(fCheckInputs);
    }
    return false;
}

// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &txOut, uint256 &hashBlock, bool fAllowSlow)
{
    CBlockIndex *pindexSlow = NULL;
    {
        LOCK(cs_main);
        {
            LOCK(mempool.cs);
            if (mempool.exists(hash))
            {
                txOut = mempool.lookup(hash);
                return true;
            }
        }

        if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
            int nHeight = -1;
            {
                CCoinsViewCache &view = *pcoinsTip;
                CCoins coins;
                if (view.GetCoins(hash, coins))
                    nHeight = coins.nHeight;
            }
            if (nHeight > 0)
                pindexSlow = FindBlockByHeight(nHeight);
        }
    }

    if (pindexSlow) {
        CBlock block;
        if (block.ReadFromDisk(pindexSlow)) {
            BOOST_FOREACH(const CTransaction &tx, block.vtx) {
                if (tx.GetHash() == hash) {
                    txOut = tx;
                    hashBlock = pindexSlow->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}


//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static CBlockIndex* pblockindexFBBHLast;
CBlockIndex* FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;
    if (nHeight < nBestHeight / 2)
        pblockindex = pindexGenesisBlock;
    else
        pblockindex = pindexBest;
    if (pblockindexFBBHLast && abs(nHeight - pblockindex->nHeight) > abs(nHeight - pblockindexFBBHLast->nHeight))
        pblockindex = pblockindexFBBHLast;
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;
    while (pblockindex->nHeight < nHeight)
        pblockindex = pblockindex->pnext;
    pblockindexFBBHLast = pblockindex;
    return pblockindex;
}

bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions)
{
    if (!fReadTransactions)
    {
        *this = pindex->GetBlockHeader();
        return true;
    }
    if (!ReadFromDisk(pindex->GetBlockPos(), fReadTransactions))
        return false;
    if (GetHash() != pindex->GetBlockHash())
        return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
    return true;
}

uint256 static GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

// ppcoin: find block wanted by given orphan block
uint256 WantedByOrphan(const CBlock* pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblockOrphan->hashPrevBlock))
        pblockOrphan = mapOrphanBlocks[pblockOrphan->hashPrevBlock];
    return pblockOrphan->hashPrevBlock;
}

int64 GetProofOfWorkReward(int nHeight, int64 nFees) {
    int64 nSubsidy = 0;

    if(nHeight > 0)  nSubsidy = 100000 * COIN;
    if(nHeight > 10) nSubsidy = 0.25 * COIN;

    if(fTestNet) {
        if(nHeight >  nTestnetForkTwo) nSubsidy = 1 * COIN;
    } else {
        if(nHeight >  nForkFour)   nSubsidy = 2 * COIN;
        if(nHeight >  nBonanzaOne) nSubsidy = 1 * COIN;
        if(nHeight >  2000000)     nSubsidy >>= (((nHeight - 1) / 500000) - 4);
    }

    return(nSubsidy + nFees);
}

int64 GetProofOfStakeReward(int nHeight, int64 nFees) {
    int64 nSubsidy = 0;

    if(fTestNet) {
        if(nHeight <= nTestnetForkTwo) nFees = 0;
        if(nHeight >  nTestnetForkTwo) nSubsidy = 1 * COIN;
    } else {
        if(nHeight <= nForkFour)   nFees = 0;
        if(nHeight >  nForkFour)   nSubsidy = 10 * COIN;
        if(nHeight >  nBonanzaOne) nSubsidy = 5 * COIN;
        if(nHeight >  nBonanzaTwo) nSubsidy = 1 * COIN;
        if(nHeight >  2000000)     nSubsidy >>= (((nHeight - 1) / 500000) - 4);
    }

    return(nSubsidy + nFees);
}

int64 inline GetTargetSpacingWorkMax() {

    if(fTestNet) return 3 * nBaseTargetSpacing;
    return 12 * nBaseTargetSpacing;
}

// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake, bool fPrettyPrint) {
    CBigNum bnTargetLimit, bnNew;

    /* Separate range limits */
    if(fTestNet) {
        if(fProofOfStake) bnTargetLimit = bnProofOfStakeLimitTestNet;
        else bnTargetLimit = bnProofOfWorkLimitTestNet;
    } else {
        if(fProofOfStake) bnTargetLimit = bnProofOfStakeLimit;
        else bnTargetLimit = bnProofOfWorkLimit;
    }

    /* The genesis block */
    if(pindexLast == NULL) return bnTargetLimit.GetCompact();
    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    /* The 1st block */
    if(pindexPrev->pprev == NULL) return bnTargetLimit.GetCompact();
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    /* The 2nd block */
    if(pindexPrevPrev->pprev == NULL) return bnTargetLimit.GetCompact();
    /* The next block */
    int nHeight = pindexLast->nHeight + 1;

    /* The hard fork to NeoScrypt */
    if(fTestNet) {
        if(!fNeoScrypt && (nHeight >= nTestnetForkFive))
          fNeoScrypt = true;
    } else {
        if(!fNeoScrypt && (nHeight >= nForkSix))
          fNeoScrypt = true;
    }

    if((fTestNet && (nHeight <= nTestnetForkThree)) ||
      (!fTestNet && (nHeight <= nForkFour))) {

        /* Legacy every block retargets of the PPC style */

        int64 nTargetTimespan = 60 * 60;
        int64 nInterval, nTargetSpacing, nActualSpacing;

        if(fProofOfStake)
          nTargetSpacing = nBaseTargetSpacing;
        else
          nTargetSpacing = min(GetTargetSpacingWorkMax(),
            (int64)nBaseTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight));

        nActualSpacing = (int64)pindexPrev->nTime - (int64)pindexPrevPrev->nTime;

        /* Initial hard forked limit */
        if(fTestNet || (nHeight > nForkOne)) nActualSpacing = max(nActualSpacing, (int64)0);

        /* Further hard forked limits */
        if(nHeight > nForkThree) {
            nActualSpacing = max(nActualSpacing, (int64)15);
            nActualSpacing = min(nActualSpacing, (int64)90);
        }

        if(fPrettyPrint) {
            fProofOfStake? printf("RETARGET PoS ") : printf("RETARGET PoW ");
            printf("heights: pindexLast = %d, pindexPrev = %d, pindexPrevPrev = %d\n",
              pindexLast->nHeight, pindexPrev->nHeight, pindexPrevPrev->nHeight);
            printf("RETARGET time stamps: pindexLast = %u, pindexPrev = %u, pindexPrevPrev = %u\n",
              pindexLast->nTime, pindexPrev->nTime, pindexPrevPrev->nTime);
        }

        nInterval = nTargetTimespan / nTargetSpacing;

        bnNew.SetCompact(pindexPrev->nBits);
        bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
        bnNew /= ((nInterval + 1) * nTargetSpacing);

        if(bnNew > bnTargetLimit) bnNew = bnTargetLimit;

        if(fPrettyPrint)
          printf("RETARGET nTargetTimespan = %" PRI64d ", nTargetSpacing = %" PRI64d \
            ", nInterval = %" PRI64d "\n", nTargetTimespan, nTargetSpacing, nInterval);

    } else {

        /* Orbitcoin Super Shield (OSS);
         * retargets every block using two averaging windows of 5 and 20 blocks,
         * 0.25 damping and further oscillation limiting */

        int64 nIntervalShort = 5, nIntervalLong = 20, nTargetSpacing, nTargetTimespan,
              nActualTimespan, nActualTimespanShort, nActualTimespanLong, nActualTimespanAvg,
              nActualTimespanMax, nActualTimespanMin;

        if(fTestNet) {
            if(nHeight > nTestnetForkSix) {
                if(fProofOfStake) nTargetSpacing = 6 * nBaseTargetSpacing;
                else nTargetSpacing = 12 * nBaseTargetSpacing;
            } else {
                if(fProofOfStake) nTargetSpacing = 4 * nBaseTargetSpacing;
                else nTargetSpacing = 2 * nBaseTargetSpacing;
            }
        } else {
            if(nHeight > nForkSeven) {
                if(fProofOfStake) nTargetSpacing = 6 * nBaseTargetSpacing;
                else nTargetSpacing = 12 * nBaseTargetSpacing;
            } else {
                if(fProofOfStake) {
                    if(nHeight > nBonanzaTwo) nTargetSpacing = 3 * nBaseTargetSpacing;
                    else nTargetSpacing = 4 * nBaseTargetSpacing;
                } else {
                    if(nHeight > nBonanzaTwo) nTargetSpacing = 6 * nBaseTargetSpacing;
                    else nTargetSpacing = 2 * nBaseTargetSpacing;
                }
            }
        }

        nTargetTimespan = nTargetSpacing * nIntervalLong;

        /* The short averaging window */
        const CBlockIndex* pindexShort = pindexPrev;
        for(int i = 0; pindexShort && (i < nIntervalShort); i++)
          pindexShort = GetLastBlockIndex(pindexShort->pprev, fProofOfStake);
        nActualTimespanShort = (int64)pindexPrev->nTime - (int64)pindexShort->nTime;

        /* The long averaging window */
        const CBlockIndex* pindexLong = pindexShort;
        for(int i = 0; pindexLong && (i < (nIntervalLong - nIntervalShort)); i++)
          pindexLong = GetLastBlockIndex(pindexLong->pprev, fProofOfStake);
        nActualTimespanLong = (int64)pindexPrev->nTime - (int64)pindexLong->nTime;

        /* Time warp protection */
        if((fTestNet && (nHeight > nTestnetForkSix)) ||
          (!fTestNet && (nHeight > nForkSeven))) {
            nActualTimespanShort = max(nActualTimespanShort, (nTargetSpacing * nIntervalShort / 2));
            nActualTimespanShort = min(nActualTimespanShort, (nTargetSpacing * nIntervalShort * 2));
            nActualTimespanLong  = max(nActualTimespanLong,  (nTargetSpacing * nIntervalLong  / 2));
            nActualTimespanLong  = min(nActualTimespanLong,  (nTargetSpacing * nIntervalLong  * 2));
        } else {
            nActualTimespanShort = max(nActualTimespanShort, (nTargetSpacing * nIntervalShort * 3 / 4));
            nActualTimespanShort = min(nActualTimespanShort, (nTargetSpacing * nIntervalShort * 4 / 3));
            nActualTimespanLong  = max(nActualTimespanLong,  (nTargetSpacing * nIntervalLong  * 3 / 4));
            nActualTimespanLong  = min(nActualTimespanLong,  (nTargetSpacing * nIntervalLong  * 4 / 3));
        }

        /* The average of both windows */
        nActualTimespanAvg = (nActualTimespanShort * (nIntervalLong / nIntervalShort) + nActualTimespanLong) / 2;

        /* 0.25 damping */
        nActualTimespan = nActualTimespanAvg + 3 * nTargetTimespan;
        nActualTimespan /= 4;

        if(fPrettyPrint) {
            fProofOfStake? printf("RETARGET PoS ") : printf("RETARGET PoW ");
            printf("heights: Last = %d, Prev = %d, Short = %d, Long = %d\n",
              pindexLast->nHeight, pindexPrev->nHeight, pindexShort->nHeight, pindexLong->nHeight);
            printf("RETARGET time stamps: Last = %u, Prev = %u, Short = %u, Long = %u\n",
              pindexLast->nTime, pindexPrev->nTime, pindexShort->nTime, pindexLong->nTime);
            printf("RETARGET windows: short = %" PRI64d " (%" PRI64d "), long = %" PRI64d \
              ", average = %" PRI64d ", damped = %" PRI64d "\n",
              nActualTimespanShort, nActualTimespanShort * (nIntervalLong / nIntervalShort),
              nActualTimespanLong, nActualTimespanAvg, nActualTimespan);
        }

        /* Oscillation limiters */
        if((fTestNet && (nHeight > nTestnetForkSix)) ||
          (!fTestNet && (nHeight > nForkSeven))) {
            /* +5% to -10% */
            nActualTimespanMin = nTargetTimespan * 100 / 105;
            nActualTimespanMax = nTargetTimespan * 110 / 100;
        } else {
            /* +1% to -2% */
            nActualTimespanMin = nTargetTimespan * 100 / 101;
            nActualTimespanMax = nTargetTimespan * 102 / 100;
        }
        if(nActualTimespan < nActualTimespanMin) nActualTimespan = nActualTimespanMin;
        if(nActualTimespan > nActualTimespanMax) nActualTimespan = nActualTimespanMax;

        /* Retarget */
        bnNew.SetCompact(pindexPrev->nBits);
        bnNew *= nActualTimespan;
        bnNew /= nTargetTimespan;

        if(bnNew > bnTargetLimit) bnNew = bnTargetLimit;

        if(fPrettyPrint)
          printf("RETARGET nTargetTimespan = %" PRI64d ", nActualTimespan = %" PRI64d \
            ", nTargetTimespan/nActualTimespan = %.4f\n",
            nTargetTimespan, nActualTimespan, (float)nTargetTimespan/nActualTimespan);

    }

    if(fPrettyPrint) {
        printf("Before: %08x  %s\n", pindexPrev->nBits,
          CBigNum().SetCompact(pindexPrev->nBits).getuint256().ToString().c_str());
        printf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());
    }

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hashPoW, uint nBits) {
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    /* Range check */
    if((bnTarget <= 0) || (fTestNet && (bnTarget > bnProofOfWorkLimitTestNet)) ||
      (!fTestNet && (bnTarget > bnProofOfWorkLimit)))
      return(error("CheckProofOfWork() : nBits (%08x) below minimum work", nBits));

    /* PoW hash check */
    if(hashPoW > bnTarget.getuint256())
      return(error("CheckProofOfWork() : hash doesn't match nBits"));

    return(true);
}

// Return maximum amount of blocks that other nodes claim to have
int GetNumBlocksOfPeers()
{
    return std::max(cPeerBlockCounts.median(), Checkpoints::GetTotalBlocksEstimate());
}

bool IsInitialBlockDownload()
{
    if (pindexBest == NULL || nBestHeight < Checkpoints::GetTotalBlocksEstimate())
        return true;
    static int64 nLastUpdate;
    static CBlockIndex* pindexLastBest;
    if (pindexBest != pindexLastBest)
    {
        pindexLastBest = pindexBest;
        nLastUpdate = GetTime();
    }
    return(((GetTime() - nLastUpdate) < 10) &&
      (pindexBest->GetBlockTime() < (GetTime() - 4 * 60 * 60)));
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (pindexNew->nChainTrust > nBestInvalidTrust)
    {
        nBestInvalidTrust = pindexNew->nChainTrust;
        pblocktree->WriteBestInvalidTrust(CBigNum(nBestInvalidTrust));
        uiInterface.NotifyBlocksChanged();
    }

    uint256 nBestInvalidBlockTrust = pindexNew->nChainTrust - pindexNew->pprev->nChainTrust;
    uint256 nBestBlockTrust = pindexBest->nHeight != 0 ? (pindexBest->nChainTrust - pindexBest->pprev->nChainTrust) : pindexBest->nChainTrust;

    printf("InvalidChainFound: invalid block=%s  height=%d  " \
      "trust=%s  blktrust=%" PRI64d "  date=%s\n",
      pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
      CBigNum(pindexNew->nChainTrust).ToString().c_str(), nBestInvalidBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockTime()).c_str());
    printf("InvalidChainFound: current best=%s   height=%d  " \
      "trust=%s  blktrust=%" PRI64d "  date=%s\n",
      hashBestChain.ToString().substr(0,20).c_str(), nBestHeight,
      CBigNum(pindexBest->nChainTrust).ToString().c_str(),
      nBestBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());
}

void static InvalidBlockFound(CBlockIndex *pindex) {
    pindex->nStatus |= BLOCK_FAILED_VALID;
    pblocktree->WriteBlockIndex(CDiskBlockIndex(pindex));
    setBlockIndexValid.erase(pindex);
    InvalidChainFound(pindex);
    if (pindex->pnext)
        ConnectBestBlock(); // reorganise away from the failed block
}

bool ConnectBestBlock() {
    do {
        CBlockIndex *pindexNewBest;

        {
            std::set<CBlockIndex*,CBlockIndexTrustComparator>::reverse_iterator it = setBlockIndexValid.rbegin();
            if (it == setBlockIndexValid.rend())
                return true;
            pindexNewBest = *it;
        }

        if (pindexNewBest == pindexBest)
            return true; // nothing to do

        // check ancestry
        CBlockIndex *pindexTest = pindexNewBest;
        std::vector<CBlockIndex*> vAttach;
        do {
            if (pindexTest->nStatus & BLOCK_FAILED_MASK) {
                // mark descendants failed
                CBlockIndex *pindexFailed = pindexNewBest;
                while (pindexTest != pindexFailed) {
                    pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    setBlockIndexValid.erase(pindexFailed);
                    pblocktree->WriteBlockIndex(CDiskBlockIndex(pindexFailed));
                    pindexFailed = pindexFailed->pprev;
                }
                InvalidChainFound(pindexNewBest);
                break;
            }

            if (pindexBest == NULL || pindexTest->nChainTrust > pindexBest->nChainTrust)
                vAttach.push_back(pindexTest);

            if (pindexTest->pprev == NULL || pindexTest->pnext != NULL) {
                reverse(vAttach.begin(), vAttach.end());
                BOOST_FOREACH(CBlockIndex *pindexSwitch, vAttach)
                    if (!SetBestChain(pindexSwitch))
                        return false;
                return true;
            }
            pindexTest = pindexTest->pprev;
        } while(true);
    } while(true);
}

void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = max(GetBlockTime(), GetAdjustedTime());
}

const CTxOut &CTransaction::GetOutputFor(const CTxIn& input, CCoinsViewCache& view)
{
    const CCoins &coins = view.GetCoins(input.prevout.hash);
    assert(coins.IsAvailable(input.prevout.n));
    return coins.vout[input.prevout.n];
}

int64 CTransaction::GetValueIn(CCoinsViewCache& inputs) const
{
    if (IsCoinBase())
        return 0;

    int64 nResult = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
        nResult += GetOutputFor(vin[i], inputs).nValue;

    return nResult;
}

unsigned int CTransaction::GetP2SHSigOpCount(CCoinsViewCache& inputs) const
{
    if (IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut &prevout = GetOutputFor(vin[i], inputs);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig);
    }
    return nSigOps;
}

bool CTransaction::UpdateCoins(CCoinsViewCache &inputs, CTxUndo &txundo, int nHeight, unsigned int nTimeStamp, const uint256 &txhash) const
{
    // mark inputs spent
    if (!IsCoinBase()) {
        BOOST_FOREACH(const CTxIn &txin, vin) {
            CCoins &coins = inputs.GetCoins(txin.prevout.hash);
            if (coins.nTime > nTimeStamp)
                return error("UpdateCoins() : timestamp violation");
            CTxInUndo undo;
            if (!coins.Spend(txin.prevout, undo))
                return error("UpdateCoins() : cannot spend input");
            txundo.vprevout.push_back(undo);
        }
    }

    // add outputs
    if (!inputs.SetCoins(txhash, CCoins(*this, nHeight, nTimeStamp)))
        return error("UpdateCoins() : cannot update output");

    return true;
}

bool CTransaction::HaveInputs(CCoinsViewCache &inputs) const
{
    if (!IsCoinBase()) { 
        // first check whether information about the prevout hash is available
        for (unsigned int i = 0; i < vin.size(); i++) {
            const COutPoint &prevout = vin[i].prevout;
            if (!inputs.HaveCoins(prevout.hash))
                return false;
        }

        // then check whether the actual outputs are available
        for (unsigned int i = 0; i < vin.size(); i++) {
            const COutPoint &prevout = vin[i].prevout;
            const CCoins &coins = inputs.GetCoins(prevout.hash);
            if (!coins.IsAvailable(prevout.n))
                return false;
        }
    }
    return true;
}

bool CTransaction::CheckInputs(CCoinsViewCache &inputs, enum CheckSig_mode csmode, uint flags) const {

    if (!IsCoinBase())
    {
        // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
        // for an attacker to attempt to split the network.
        if (!HaveInputs(inputs))
            return error("CheckInputs() : %s inputs unavailable", GetHash().ToString().substr(0,10).c_str());

        CBlockIndex *pindexBlock = inputs.GetBestBlock();
        int64 nValueIn = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            const COutPoint &prevout = vin[i].prevout;
            const CCoins &coins = inputs.GetCoins(prevout.hash);

            // If prev is coinbase or coinstake, check that it's matured
            if (coins.IsCoinBase() || coins.IsCoinStake()) {
                if (pindexBlock->nHeight - coins.nHeight < nBaseMaturity)
                    return error("CheckInputs() : tried to spend %s at depth %d", coins.IsCoinBase() ? "coinbase" : "coinstake", pindexBlock->nHeight - coins.nHeight);
            }

            // Check transaction timestamp
            if (coins.nTime > nTime)
                return DoS(100, error("CheckInputs() : transaction timestamp earlier than input transaction"));

            // Check for negative or overflow input values
            nValueIn += coins.vout[prevout.n].nValue;
            if (!MoneyRange(coins.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return DoS(100, error("CheckInputs() : txin values out of range"));
        }

        if(IsCoinStake()) {

            /* Do not accept too many inputs */
            if(vin.size() > (uint64)MAX_STAKE_INPUTS)
              return DoS(25, error("CheckInputs() : too many inputs (%u) of a coin stake %s",
                (uint) vin.size(), GetHash().ToString().substr(0,10).c_str()));

            /* Orbitcoin: not using coin age for reward calculation,
             * using for input verification to prevent stake amount manipulations;
             * reward control is in ConnectBlock() when all transactions are processed
             * with all fees present and accounted for */
            uint64 nCoinAge = 0, nCoinAgeFails = 0;
            if(!GetCoinAge(&nCoinAge, &nCoinAgeFails))
              return DoS(50, error("CheckInputs() : unable to calculate coin age for a coin stake %s",
                GetHash().ToString().substr(0,10).c_str()));
            if(nCoinAgeFails)
              return(DoS(50, error("CheckInputs() : %" PRI64u \
                " inputs of a coin stake %s don't meet the min. age requirement",
                nCoinAgeFails, GetHash().ToString().substr(0,10).c_str())));

        } else {

            /* Output must not exceed input for regular transactions */
            if(nValueIn < GetValueOut())
              return DoS(100, error("CheckInputs() : transaction %s input value < output value",
                GetHash().ToString().substr(0,10).c_str()));

        }

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip ECDSA signature verification when connecting blocks
        // before the last blockchain checkpoint. This is safe because block merkle hashes are
        // still computed and checked, and any change will be caught at the next checkpoint.
        if (csmode == CS_ALWAYS || 
            (csmode == CS_AFTER_CHECKPOINT && inputs.GetBestBlock()->nHeight >= Checkpoints::GetTotalBlocksEstimate())) {
            for (unsigned int i = 0; i < vin.size(); i++) {
                const COutPoint &prevout = vin[i].prevout;
                const CCoins &coins = inputs.GetCoins(prevout.hash);

                /* ECDSA signature verification */
                if(!VerifySignature(coins, *this, i, flags, 0)) {

                    return(DoS(100, error("CheckInputs() : transaction %s signature verification failed",
                      GetHash().ToString().substr(0,10).c_str())));

                }
            }
        }
    }

    return true;
}

/* Checks a transaction before accepting to the memory pool */
bool CTransaction::ClientCheckInputs() const {

    /* Coin base and coin stake transactions are never relayed without a block */
    if(IsCoinBase() || IsCoinStake())
      return(false);

    LOCK(mempool.cs);
    int64 nValueIn = 0;
    for(unsigned int i = 0; i < vin.size(); i++) {

        /* Get inputs */
        COutPoint prevout = vin[i].prevout;

        if(!mempool.exists(prevout.hash))
          return(false);

        CTransaction& txPrev = mempool.lookup(prevout.hash);

        /* A subtransaction index check */
        if(prevout.n >= txPrev.vout.size())
          return(false);

        /* A simple value range check */
        if(!MoneyRange(txPrev.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
          return error("ClientCheckInputs() : transaction %s value out of range",
            GetHash().ToString().substr(0,10).c_str());

        /* ECDSA signature verification */
        if(!VerifySignature(CCoins(txPrev, -1, -1), *this, i,
          SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC | SCRIPT_VERIFY_DERSIG, 0))
          return error("ClientCheckInputs() : transaction %s signature verificaton failed",
            GetHash().ToString().substr(0,10).c_str());

        nValueIn += txPrev.vout[prevout.n].nValue;

    }

    /* Output must not exceed input for regular transactions */
    if(nValueIn < GetValueOut())
      return(false);

    return(true);
}

bool CBlock::DisconnectBlock(CBlockIndex *pindex, CCoinsViewCache &view) {
    int i;
    uint j;

    if(pindex != view.GetBestBlock())
      return(error("DisconnectBlock() : block %s initial synchronisation failed",
        pindex->GetBlockHash().ToString().substr(0,20).c_str()));

    CBlockUndo blockUndo;
    {
        CDiskBlockPos pos = pindex->GetUndoPos();
        if (pos.IsNull())
            return error("DisconnectBlock() : no undo data available");
        FILE *file = OpenUndoFile(pos, true);
        if (file == NULL)
            return error("DisconnectBlock() : undo file not available");
        CAutoFile fileUndo(file, SER_DISK, CLIENT_VERSION);
        fileUndo >> blockUndo;
    }

    assert(blockUndo.vtxundo.size() + 1 == vtx.size());

    // undo transactions in reverse order
    for(i = vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = vtx[i];
        uint256 hash = tx.GetHash();

        // don't check coinbase coins for proof-of-stake block
        if(IsProofOfStake() && tx.IsCoinBase())
            continue;

        // check that all outputs are available
        if (!view.HaveCoins(hash))
            return error("DisconnectBlock() : outputs still spent? database corrupted");
        CCoins &outs = view.GetCoins(hash);

        CCoins outsBlock = CCoins(tx, pindex->nHeight, pindex->nTime);
        if (outs != outsBlock)
            return error("DisconnectBlock() : added transaction mismatch? database corrupted");

        // remove outputs
        outs = CCoins();

        // restore inputs
        if (i > 0) { // not coinbases
            const CTxUndo &txundo = blockUndo.vtxundo[i-1];
            assert(txundo.vprevout.size() == tx.vin.size());
            for(j = tx.vin.size(); j-- > 0;) {
                const COutPoint &out = tx.vin[j].prevout;
                const CTxInUndo &undo = txundo.vprevout[j];
                CCoins coins;
                view.GetCoins(out.hash, coins); // this can fail if the prevout was already entirely spent
                if (coins.IsPruned()) {
                    if (undo.nHeight == 0)
                        return error("DisconnectBlock() : undo data doesn't contain tx metadata? database corrupted");
                    coins.fCoinBase = undo.fCoinBase;
                    coins.fCoinStake = undo.fCoinStake;
                    coins.nHeight = undo.nHeight;
                    coins.nTime = undo.nTime;
                    coins.nBlockTime = undo.nBlockTime;
                    coins.nVersion = undo.nVersion;
                } else {
                    if (undo.nHeight != 0)
                        return error("DisconnectBlock() : undo data contains unneeded tx metadata? database corrupted");
                }
                if (coins.IsAvailable(out.n))
                    return error("DisconnectBlock() : prevout output not spent? database corrupted");
                if (coins.vout.size() < out.n+1)
                    coins.vout.resize(out.n+1);
                coins.vout[out.n] = undo.txout;
                if (!view.SetCoins(out.hash, coins))
                    return error("DisconnectBlock() : cannot restore coin inputs");
            }
        }

        /* Synchronise with the wallet */
        SyncWithWallets(vtx[i].GetHash(), vtx[i], this, false, false);
    }

    /* Synchronise with the coins DB */
    if(!view.SetBestBlock(pindex->pprev))
      return(error("DisconnectBlock() : block %s final synchronisation failed",
        pindex->GetBlockHash().ToString().substr(0,20).c_str()));

    return(true);
}

bool FindUndoPos(int nFile, CDiskBlockPos &pos, unsigned int nAddSize);

bool CBlock::ConnectBlock(CBlockIndex* pindex, CCoinsViewCache &view) {
    uint i;

    /* Make sure the block index and coins DB are synchronised;
     * no need to work around the genesis block and its transactions if any
     * because ConnectBlock() doesn't service them anyway */
    if(pindex->pprev != view.GetBestBlock())
      return(error("ConnectBlock() : block %s initial synchronisation failed",
        pindex->GetBlockHash().ToString().substr(0,20).c_str()));

    /* One more merkle root verification */
    if(hashMerkleRoot != BuildMerkleTree())
      return(error("ConnectBlock() : merkle root verification failed"));

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied all blocks whose timestamp was after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes in their
    // initial block download.

    /* Work around duplicate transactions (BIP30) */
    for(i = 0; i < vtx.size(); i++) {
        uint256 hash = GetTxHash(i);
        if(view.HaveCoins(hash) && !view.GetCoins(hash).IsPruned())
          return(error("ConnectBlock() : transaction overwrite attempt detected"));
    }

    CBlockUndo blockundo;

    int64 nFees = 0, nValueIn = 0, nValueOut = 0, nActualStakeReward = 0;
    unsigned int nSigOps = 0;
    for(i = 0; i < vtx.size(); i++) {
        const CTransaction &tx = vtx[i];
        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return DoS(100, error("ConnectBlock() : too many sigops"));

        if(tx.IsCoinBase()) nValueOut += tx.GetValueOut();
        else {

            if (!tx.HaveInputs(view))
                return DoS(100, error("ConnectBlock() : inputs missing/spent"));

            {
                // Add in sigops done by pay-to-script-hash inputs;
                // this is to prevent a "rogue miner" from creating
                // an incredibly-expensive-to-validate block.
                nSigOps += tx.GetP2SHSigOpCount(view);
                if (nSigOps > MAX_BLOCK_SIGOPS)
                     return DoS(100, error("ConnectBlock() : too many sigops"));
            }

            int64 nTxValueOut = tx.GetValueOut();
            int64 nTxValueIn  = tx.GetValueIn(view);

            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;

            if(tx.IsCoinStake()) {
                /* Orbitcoin: combined value of stake inputs must satisfy the limit */ 
                if(!fTestNet && (pindex->nHeight > nForkFour) && (nTxValueIn < MIN_STAKE_AMOUNT))
                  return(DoS(100,
                    error("ConnectBlock() : block %d proof-of-stake input amount too low " \
                      "(%" PRI64d " actual, %" PRI64d " expected)",
                      pindex->nHeight, nActualStakeReward, MIN_STAKE_AMOUNT)));
                nActualStakeReward = nTxValueOut - nTxValueIn;
            } else nFees += nTxValueIn - nTxValueOut;

            if(!tx.CheckInputs(view, CS_AFTER_CHECKPOINT, SCRIPT_VERIFY_P2SH))
                return false;
        }

        // don't create coinbase coins for proof-of-stake block
        if(IsProofOfStake() && tx.IsCoinBase())
            continue;

        CTxUndo txundo;
        if (!tx.UpdateCoins(view, txundo, pindex->nHeight, pindex->nTime, GetTxHash(i)))
            return error("ConnectBlock() : UpdateInputs failed");
        if (!tx.IsCoinBase())
            blockundo.vtxundo.push_back(txundo);
    }

    /* Check PoW block reward */
    if(IsProofOfWork() && (vtx[0].GetValueOut() > GetProofOfWorkReward(pindex->nHeight, nFees)))
      return(DoS(100, error("ConnectBlock() : block %d proof-of-work reward is too high " \
        "(%" PRI64d " actual, %" PRI64d " expected)",
        pindex->nHeight, vtx[0].GetValueOut(), GetProofOfWorkReward(pindex->nHeight, nFees))));

    /* Check PoS block reward */
    if(IsProofOfStake() && (nActualStakeReward > GetProofOfStakeReward(pindex->nHeight, nFees)))
      return(DoS(100, error("ConnectBlock() : block %d proof-of-stake reward is too high " \
        "(%" PRI64d " actual, %" PRI64d " expected)",
        pindex->nHeight, nActualStakeReward, GetProofOfStakeReward(pindex->nHeight, nFees))));

    pindex->nMint = nValueOut - nValueIn + nFees;
    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;

    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull() || (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS)
    {
        if (pindex->GetUndoPos().IsNull()) {
            CDiskBlockPos pos;
            if (!FindUndoPos(pindex->nFile, pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 8))
                return error("ConnectBlock() : FindUndoPos failed");
            if (!blockundo.WriteToDisk(pos))
                return error("ConnectBlock() : CBlockUndo::WriteToDisk failed");

            // update nUndoPos in block index
            pindex->nUndoPos = pos.nPos;
            pindex->nStatus |= BLOCK_HAVE_UNDO;
        }

        pindex->nStatus = (pindex->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_SCRIPTS;

        CDiskBlockIndex blockindex(pindex);
        if (!pblocktree->WriteBlockIndex(blockindex))
            return error("ConnectBlock() : WriteBlockIndex failed");
    }

    /* Synchronise with the coins DB */
    if(!view.SetBestBlock(pindex))
      return(error("ConnectBlock() : block %s final synchronisation failed",
        pindex->GetBlockHash().ToString().substr(0,20).c_str()));

    /* Synchronise with the wallet */
    for(i = 0; i < vtx.size(); i++)
      SyncWithWallets(GetTxHash(i), vtx[i], this, true);

    return(true);
}

bool SetBestChain(CBlockIndex* pindexNew)
{
    CCoinsViewCache &view = *pcoinsTip;

    // special case for attaching the genesis block
    // note that no ConnectBlock is called, so its coinbase output is non-spendable
    if (pindexGenesisBlock == NULL && pindexNew->GetBlockHash() == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))
    {
        view.SetBestBlock(pindexNew);
        if (!view.Flush())
            return false;
        pindexGenesisBlock = pindexNew;
        pindexBest = pindexNew;
        hashBestChain = pindexNew->GetBlockHash();
        nBestHeight = pindexBest->nHeight;
        nBestChainTrust = pindexNew->nChainTrust;
        return true;
    }

    // Find the fork (typically, there is none)
    CBlockIndex* pfork = view.GetBestBlock();
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger)
    {
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev))
                return error("SetBestChain() : plonger->pprev is null");
        if (pfork == plonger)
            break;
        if (!(pfork = pfork->pprev))
            return error("SetBestChain() : pfork->pprev is null");
    }

    // List of what to disconnect (typically nothing)
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = view.GetBestBlock(); pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect (typically only pindexNew)
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    if (vDisconnect.size() > 0) {
        printf("REORGANISE: disconnecting %" PRIszu " blocks; %s..%s\n",
          vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(),
          pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
        printf("REORGANISE: connecting %" PRIszu " blocks; %s..%s\n",
          vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(),
          pindexNew->GetBlockHash().ToString().substr(0,20).c_str());
    }

    // Disconnect shorter branch
    vector<CTransaction> vResurrect;
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect) {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("SetBestChain() : ReadFromDisk for disconnect failed");
        CCoinsViewCache viewTemp(view, true);
        if (!block.DisconnectBlock(pindex, viewTemp))
            return error("SetBestChain() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());
        if (!viewTemp.Flush())
            return error("SetBestChain() : Cache flush failed after disconnect");

        // Queue memory transactions to resurrect
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            if (!tx.IsCoinBase() && !tx.IsCoinStake())
                vResurrect.push_back(tx);
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    BOOST_FOREACH(CBlockIndex *pindex, vConnect) {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("SetBestChain() : ReadFromDisk for connect failed");
        CCoinsViewCache viewTemp(view, true);
        if (!block.ConnectBlock(pindex, viewTemp)) {
            InvalidChainFound(pindexNew);
            InvalidBlockFound(pindex);
            return error("SetBestChain() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());
        }
        if (!viewTemp.Flush())
            return error("SetBestChain() : Cache flush failed after connect");

        // Queue memory transactions to delete
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
    }

    // Make sure it's successfully written to disk before changing memory structure
    bool fIsInitialDownload = IsInitialBlockDownload();
    if (!fIsInitialDownload || view.GetCacheSize()>5000)
        if (!view.Flush())
            return false;

    // At this point, all changes have been done to the database.
    // Proceed by updating the memory structures.

    // Disconnect shorter branch
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;

    // Connect longer branch
    BOOST_FOREACH(CBlockIndex* pindex, vConnect)
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;

    // Resurrect memory transactions that were in the disconnected branch
    BOOST_FOREACH(CTransaction& tx, vResurrect)
        tx.AcceptToMemoryPool(false);

    // Delete redundant memory transactions that are in the connected branch
    BOOST_FOREACH(CTransaction& tx, vDelete)
        mempool.remove(tx);

    // Update best block in wallet (so we can detect restored wallets)
    if (!fIsInitialDownload)
    {
        const CBlockLocator locator(pindexNew);
        ::SetBestChain(locator);
    }

    // New best block
    hashBestChain = pindexNew->GetBlockHash();
    pindexBest = pindexNew;
    pblockindexFBBHLast = NULL;
    nBestHeight = pindexBest->nHeight;
    nBestChainTrust = pindexNew->nChainTrust;
    nTimeBestReceived = GetTime();
    nTransactionsUpdated++;

    uint256 nBestBlockTrust = pindexBest->nHeight != 0 ? (pindexBest->nChainTrust - pindexBest->pprev->nChainTrust) : pindexBest->nChainTrust;

    printf("SetBestChain: new best=%s  height=%d  trust=%s blocktrust=%s  tx=%lu  date=%s\n",
      hashBestChain.ToString().substr(0,20).c_str(), nBestHeight, CBigNum(nBestChainTrust).ToString().c_str(), CBigNum(nBestBlockTrust).ToString().c_str(), (unsigned long)pindexNew->nChainTx,
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    std::string strCmd = GetArg("-blocknotify", "");

    if (!fIsInitialDownload && !strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", hashBestChain.GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}

// Total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are 
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.

/* Reports the total coin age of all inputs of a transaction
 * and the number of inputs failing to meet the min. coin age */
bool CTransaction::GetCoinAge(uint64 *pCoinAge, uint64 *pCoinAgeFails) const {
    uint64 nCoinAgeFails = 0;
    CCoinsViewCache &inputs = *pcoinsTip;
    CBigNum bnCentSecond = 0;
    uint i;

    if(IsCoinBase())
      return(true);

    if(!pCoinAge || !pCoinAgeFails)
      return(false);

    for(i = 0; i < vin.size(); i++) {
        const COutPoint &prevout = vin[i].prevout;
        CCoins coins;

        if(!inputs.GetCoins(prevout.hash, coins))
          continue;

        /* Transaction earlier than input */
        if(nTime < coins.nTime)
          return(false);

        /* Minumum age requirement must be met */
        if(nTime < (coins.nBlockTime + GetStakeMinAge(coins.nBlockTime))) {
            nCoinAgeFails++;
        } else {
            int64 nValueIn = coins.vout[vin[i].prevout.n].nValue;
            bnCentSecond += CBigNum(nValueIn) * (nTime - coins.nTime) / CENT;
        }
    }

    CBigNum bnCoinDay = (bnCentSecond * CENT) / COIN / (24 * 60 * 60);

    if(fDebug && GetBoolArg("-printcoinage"))
      printf("%" PRI64d " transaction inputs < nStakeMinAge, bnCoinDay=%s\n coin-days",
        nCoinAgeFails, bnCoinDay.ToString().c_str());

    *pCoinAge = bnCoinDay.getuint64();
    *pCoinAgeFails = nCoinAgeFails;

    return(true);
}

/* Reports the total coin age consumed by all transactions in a block
 * and the number of transactions with one or more inputs under the min. coin age
 * (coin base transactions are ignored) */
bool CBlock::GetCoinAge(uint64 *pCoinAge, uint64 *pCoinAgeFails) const {
    uint64 nTxCoinAge = 0, nBlockCoinAge = 0, nTxCoinAgeFails = 0, nBlockCoinAgeFails = 0;
    uint i;

    if(!pCoinAge || !pCoinAgeFails)
      return(false);

    for(i = 0; i < vtx.size(); i++) {
        const CTransaction &tx = vtx[i];

        if(tx.GetCoinAge(&nTxCoinAge, &nTxCoinAgeFails)) {
          nBlockCoinAge += nTxCoinAge;
          nBlockCoinAgeFails += nTxCoinAgeFails;
        } else return(false);
    }

    if(fDebug && GetBoolArg("-printcoinage"))
      printf("%" PRI64d " transactions with input(s) < nStakeMinAge, " \
        "nBlockCoinAge=%" PRI64d " coin-days\n",
        nBlockCoinAgeFails, nBlockCoinAge);

    *pCoinAge = nBlockCoinAge;
    *pCoinAgeFails = nBlockCoinAgeFails;

    return(true);
}

bool CBlock::AddToBlockIndex(const CDiskBlockPos &pos)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,20).c_str());

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(*this);
    if (!pindexNew)
        return error("AddToBlockIndex() : new CBlockIndex failed");
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }
    pindexNew->nTx = vtx.size();
    pindexNew->nChainTrust = (pindexNew->pprev ? pindexNew->pprev->nChainTrust : 0) + pindexNew->GetBlockTrust();
    pindexNew->nChainTx = (pindexNew->pprev ? pindexNew->pprev->nChainTx : 0) + pindexNew->nTx;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;

    // Compute stake entropy bit for stake modifier
    if (!pindexNew->SetStakeEntropyBit(GetStakeEntropyBit(pindexNew->nTime)))
        return error("AddToBlockIndex() : SetStakeEntropyBit() failed");

    // Record proof-of-stake hash value
    if (pindexNew->IsProofOfStake())
    {
        if (!mapProofOfStake.count(hash))
            return error("AddToBlockIndex() : hashProofOfStake not found in map");
        pindexNew->hashProofOfStake = mapProofOfStake[hash];
    }

    // Compute stake modifier
    uint64 nStakeModifier = 0;
    bool fGeneratedStakeModifier = false;
    if (!ComputeNextStakeModifier(pindexNew->pprev, nStakeModifier, fGeneratedStakeModifier))
        return error("AddToBlockIndex() : ComputeNextStakeModifier() failed");
    pindexNew->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
    pindexNew->nStakeModifierChecksum = GetStakeModifierChecksum(pindexNew);
    if(!CheckStakeModifierCheckpoints(pindexNew->nHeight, pindexNew->nStakeModifierChecksum))
      return(error("AddToBlockIndex() : rejected by stake modifier checkpoint height=%d, " \
        "modifier=0x%016" PRI64x, pindexNew->nHeight, nStakeModifier));

    setBlockIndexValid.insert(pindexNew);

    pblocktree->WriteBlockIndex(CDiskBlockIndex(pindexNew));

    // New best?
    if (!ConnectBestBlock())
        return false;

    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = GetTxHash(0);
    }

    pblocktree->Flush();

    uiInterface.NotifyBlocksChanged();
    return true;
}

bool FindBlockPos(CDiskBlockPos &pos, unsigned int nAddSize, unsigned int nHeight,
  uint64 nTime, bool fKnown = false) {
    bool fUpdatedLast = false;

    LOCK(cs_LastBlockFile);

    if(fKnown) {
        if(nLastBlockFile != pos.nFile) {
            nLastBlockFile = pos.nFile;
            infoLastBlockFile.SetNull();
            pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile);
            fUpdatedLast = true;
        }
    } else {
        while((infoLastBlockFile.nSize + nAddSize) >= MAX_BLOCKFILE_SIZE) {
            printf("Leaving block file %i: %s\n",
              nLastBlockFile, infoLastBlockFile.ToString().c_str());
            /* Flush the last block file to disk */
            CDiskBlockPos posOld(nLastBlockFile, 0);
            FILE *fileOld = OpenBlockFile(posOld);
            if(fileOld) {
                FileTruncate(fileOld, infoLastBlockFile.nSize);
                fflush(fileOld);
                if(FileCommit(fileOld))
                  return(error("FindBlockPos() : FileCommit() on block file failed"));
                fclose(fileOld);
            } else return(error("FindBlockPos() : OpenBlockFile() on block file failed"));
            fileOld = OpenUndoFile(posOld);
            if(fileOld) {
                FileTruncate(fileOld, infoLastBlockFile.nUndoSize);
                fflush(fileOld);
                if(FileCommit(fileOld))
                  return(error("FindBlockPos() : FileCommit() on undo file failed"));
                fclose(fileOld);
            } else return(error("FindBlockPos() : OpenBlockFile() on undo file failed"));
            nLastBlockFile++;
            infoLastBlockFile.SetNull();
            pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile);
            fUpdatedLast = true;
        }
        pos.nFile = nLastBlockFile;
        pos.nPos = infoLastBlockFile.nSize;
    }

    infoLastBlockFile.nSize += nAddSize;
    infoLastBlockFile.AddBlock(nHeight, nTime);

    if(!fKnown) {
        uint nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        uint nNewChunks = (infoLastBlockFile.nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if(nNewChunks > nOldChunks) {
            FILE *file = OpenBlockFile(pos);
            if(file) {
                printf("Pre-allocating up to position 0x%x in blk%05u.dat\n",
                  nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
            }
            fclose(file);
        }
    }

    if (!pblocktree->WriteBlockFileInfo(nLastBlockFile, infoLastBlockFile))
        return error("FindBlockPos() : cannot write updated block info");
    if (fUpdatedLast)
        pblocktree->WriteLastBlockFile(nLastBlockFile);

    return true;
}

bool FindUndoPos(int nFile, CDiskBlockPos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    if (nFile == nLastBlockFile) {
        pos.nPos = infoLastBlockFile.nUndoSize;
        nNewSize = (infoLastBlockFile.nUndoSize += nAddSize);
        if (!pblocktree->WriteBlockFileInfo(nLastBlockFile, infoLastBlockFile))
            return error("FindUndoPos() : cannot write updated block info");
    } else {
        CBlockFileInfo info;
        if (!pblocktree->ReadBlockFileInfo(nFile, info))
            return error("FindUndoPos() : cannot read block info");
        pos.nPos = info.nUndoSize;
        nNewSize = (info.nUndoSize += nAddSize);
        if (!pblocktree->WriteBlockFileInfo(nFile, info))
            return error("FindUndoPos() : cannot write updated block info");
    }

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        FILE *file = OpenUndoFile(pos);
        if (file) {
            printf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
            AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
        }
        fclose(file);
    }

    return true;
}

bool CBlock::CheckBlock() const {

    if(fReindex) {
        /* Merkle root verification */
        if(hashMerkleRoot != BuildMerkleTree()) return(false);
        return(true);
    }

    uint nAdjTime = GetAdjustedTime();

    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    // Size limits
    if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return DoS(100, error("CheckBlock() : size limits failed"));

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return DoS(100, error("CheckBlock() : first tx is not coinbase"));
    for (unsigned int i = 1; i < vtx.size(); i++)
        if (vtx[i].IsCoinBase())
            return DoS(100, error("CheckBlock() : more than one coinbase"));

    // Check for block and coin base time stamps
    if(GetBlockTime() > nForkTwoTime) {
        if(GetBlockTime() > FutureDrift(nAdjTime))
          return error("CheckBlock() : block has a time stamp too far in the future");
        if(GetBlockTime() > FutureDrift((int64)vtx[0].nTime))
          return DoS(50, error("CheckBlock() : coin base time stamp is too far in the past"));
    }

    if(IsProofOfStake()) {

        // Coinbase output should be empty if proof-of-stake block
        if (vtx[0].vout.size() != 1 || !vtx[0].vout[0].IsEmpty())
            return DoS(100, error("CheckBlock() : coinbase output not empty for proof-of-stake block"));

        // Second transaction must be coinstake, the rest must not be
        if (vtx.empty() || !vtx[1].IsCoinStake())
            return DoS(100, error("CheckBlock() : second tx is not coinstake"));
        for (unsigned int i = 2; i < vtx.size(); i++)
            if (vtx[i].IsCoinStake())
                return DoS(100, error("CheckBlock() : more than one coinstake"));

        // Check coinstake timestamp
        if(!CheckCoinStakeTimestamp(GetBlockTime(), (int64)vtx[1].nTime))
          return(DoS(50, error("CheckBlock() : coin stake time stamp violation " \
          "nTimeBlock=%" PRI64d " nTimeTx=%u", GetBlockTime(), vtx[1].nTime)));

        /* Proof-of-stake block signature verification is done by ProcessBlock()
         * after passing most of the initial (less expensive) tests */

    } else {

        /* Proof-of-work verification against target */
        if(!CheckProofOfWork(GetHashPoW(), nBits))
          return(DoS(50, error("CheckBlock() : proof-of-work verification failed")));

        /* Proof-of-work block signature verification */
        if(!CheckWorkSignature())
          return(DoS(100, error("CheckBlock() : bad proof-of-work block signature")));

    }

    // Check transactions
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        if (!tx.CheckTransaction())
            return DoS(tx.nDoS, error("CheckBlock() : CheckTransaction failed"));

        // check transaction timestamp
        if (GetBlockTime() < (int64)tx.nTime)
            return DoS(50, error("CheckBlock() : block timestamp earlier than transaction timestamp"));
    }

    /* Merkle root verification */
    if(hashMerkleRoot != BuildMerkleTree())
      return(DoS(100, error("CheckBlock() : merkle root verification failed")));

    /* Check for duplicate transactions */
    uint i;
    set<uint256> uniqueTx;
    for(i = 0; i < vtx.size(); i++)
      uniqueTx.insert(GetTxHash(i));
    if(uniqueTx.size() != vtx.size())
      return(DoS(100, error("CheckBlock() : duplicate transaction found")));

    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        nSigOps += tx.GetLegacySigOpCount();
    }
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return DoS(100, error("CheckBlock() : out-of-bounds SigOpCount"));

    return(true);
}


bool CBlock::AcceptBlock(CDiskBlockPos *dbp) {

    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AcceptBlock() : block already in mapBlockIndex");

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
        return DoS(10, error("AcceptBlock() : prev block not found"));
    CBlockIndex* pindexPrev = (*mi).second;
    int nHeight = pindexPrev->nHeight+1;

    if(fReindex && (dbp != NULL)) {
        /* Skip all remaining checks and actions, add the block to the index */
        uint nBlockSize = ::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos = *dbp;
        if(!FindBlockPos(blockPos, nBlockSize + 8, nHeight, nTime, 1))
          return(error("AcceptBlock() : FindBlockPos() failed while reindexing"));
        if(!AddToBlockIndex(blockPos))
          return(error("AcceptBlock() : AddToBlockIndex() failed while reindexing"));
        return(true);
    }

    // Check proof-of-work or proof-of-stake
    if(nBits != GetNextTargetRequired(pindexPrev, IsProofOfStake(), false))
      return DoS(100, error("AcceptBlock() : incorrect proof-of-%s amount", IsProofOfWork() ? "work" : "stake"));

    uint nOurTime   = (uint)GetAdjustedTime();

    /* Check for time stamp (past limit #1) */
    if(nTime <= (uint)pindexPrev->GetMedianTimePast())
      return(DoS(20, error("AcceptBlock() : block %s height %d has a time stamp behind the median",
        hash.ToString().substr(0,20).c_str(), nHeight)));

    if(nHeight > nForkThree) {

        /* Check for time stamp (future limit) */
        if(nTime > (nOurTime + 3 * 60))
          return(DoS(5, error("AcceptBlock() : block %s height %d has a time stamp too far in the future",
            hash.ToString().substr(0,20).c_str(), nHeight)));

        /* Check for time stamp (past limit #2) */
        if(nTime <= (pindexPrev->nTime - 5 * 60))
          return(DoS(20, error("AcceptBlock() : block %s height %d has a time stamp too far in the past",
            hash.ToString().substr(0,20).c_str(), nHeight)));

    }

    if(!IsInitialBlockDownload()) {

        /* Old block limiter; to be disabled after nForkSeven */
        if((nHeight > nForkThree) &&
          (nTime <= ((uint)pindexPrev->GetMedianTimePast() + BLOCK_LIMITER_TIME_OLD))) {
            return(DoS(5, error("AcceptBlock() : block %s height %d rejected by the block limiter (old)",
              hash.ToString().substr(0,20).c_str(), nHeight)));
        }

        /* Old future travel detector for the block limiter; to be disabled after nForkSeven */
        if((nHeight > nForkFive) &&
          (nTime > (nOurTime + 60)) &&
          ((pindexPrev->GetAverageTimePast(5, 20) + BLOCK_LIMITER_TIME_OLD) > nOurTime)) {
            return(DoS(5, error("AcceptBlock() : block %s height %d rejected by the future travel detector (old)",
              hash.ToString().substr(0,20).c_str(), nHeight)));
        }

        /* New block limiter */
        if((nHeight > nForkSeven) &&
          (nTime <= ((uint)pindexPrev->GetMedianTimePast() + BLOCK_LIMITER_TIME_NEW))) {
            return(DoS(5, error("AcceptBlock() : block %s height %d rejected by the block limiter",
              hash.ToString().substr(0,20).c_str(), nHeight)));
        }

        /* New future travel detector for the block limiter */
        if((nHeight > nForkSeven) &&
          (nTime > (nOurTime + 60)) &&
          ((pindexPrev->GetAverageTimePast(5, 40) + BLOCK_LIMITER_TIME_NEW) > nOurTime)) {
            return(DoS(5, error("AcceptBlock() : block %s height %d rejected by the future travel detector",
              hash.ToString().substr(0,20).c_str(), nHeight)));
        }

    }

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!tx.IsFinal(nHeight, GetBlockTime()))
            return DoS(10, error("AcceptBlock() : contains a non-final transaction"));

    // Check that the block chain matches the known block chain up to a checkpoint
    if (!Checkpoints::CheckHardened(nHeight, hash))
        return DoS(100, error("AcceptBlock() : rejected by hardened checkpoint lock-in at %d", nHeight));

    /* Check against advanced checkpoints */
    if(!IsInitialBlockDownload()) {
        bool cpSatisfies = Checkpoints::CheckSync(hash, pindexPrev);

        /* Failed blocks are rejected in strict mode */
        if((CheckpointsMode == Checkpoints::STRICT) && !cpSatisfies)
          return(error("AcceptBlock() : block %s height %d rejected by the ACP",
            hash.ToString().substr(0,20).c_str(), nHeight));

        /* Failed blocks are accepted in advisory mode with a warning issued */
        if((CheckpointsMode == Checkpoints::ADVISORY) && !cpSatisfies)
          strMiscWarning = _("WARNING: failed against the ACP!");
    }

    /* Don't accept v1 blocks after this point */
    if(!fTestNet && (nTime > nForkTwoTime)) {
        CScript expect = CScript() << nHeight;
        if(!std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
          return(DoS(100, error("AcceptBlock() : incorrect block height in coin base")));
    }

    /* Don't accept blocks with bogus version numbers after this point */
    if((nHeight >= nForkSix) || (fTestNet && (nHeight >= nTestnetForkFive))) {
        if(nVersion != 2)
          return(DoS(100, error("AcceptBlock() : incorrect block version %u", nVersion)));
    }

    // Write block to history file
    unsigned int nBlockSize = ::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION);
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
        return error("AcceptBlock() : out of disk space");
    CDiskBlockPos blockPos;
    {
        if (!FindBlockPos(blockPos, nBlockSize+8, nHeight, nTime))
            return error("AcceptBlock() : FindBlockPos failed");
    }
    if (!WriteToDisk(blockPos))
        return error("AcceptBlock() : WriteToDisk failed");
    if (!AddToBlockIndex(blockPos))
        return error("AcceptBlock() : AddToBlockIndex failed");

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
    if (hashBestChain == hash)
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
            if (nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
                pnode->PushInventory(CInv(MSG_BLOCK, hash));
    }

    /* Process an advanced checkpoint pending */
    if(!IsInitialBlockDownload()) Checkpoints::AcceptPendingSyncCheckpoint();

    return true;
}

uint256 CBlockIndex::GetBlockTrust() const
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    if(bnTarget <= 0) return 0;

    int64 time = GetBlockTime();

    /* First protocol (PPC style) */

    if((fTestNet && (time < nTestnetForkOneTime)) ||
      (!fTestNet && (time < nForkTwoTime)))
        return (IsProofOfStake()? ((CBigNum(1)<<256) / (bnTarget+1)).getuint256() : 1);

    /* Third protocol (ORB style) */

    if((fTestNet && (time >= nTestnetForkTwoTime)) ||
      (!fTestNet && (time >= nForkThreeTime))) {

        uint256 nBlockTrust;

        if(IsProofOfWork()) {

            /* Difficulty is the trust base for PoW */
            uint256 nBaseTrust = ((bnProofOfWorkLimit + 1) / (bnTarget + 1)).getuint256();

            /* Simple trust for the first 10 blocks */
            if(!pprev || (pprev->nHeight < 10))
              return(nBaseTrust);

            const CBlockIndex *pindexP1 = pprev;
            const CBlockIndex *pindexP2 = pindexP1->pprev;

            if(pindexP1->IsProofOfStake()) {
                /* 100% trust for PoW following PoS */
                nBlockTrust = nBaseTrust;
            } else {
                if(pindexP2->IsProofOfStake()) {
                    /* 50% trust for PoS->PoW->[PoW] */
                    nBlockTrust = (nBaseTrust >> 1);
                } else {
                    /* 25% trust for PoW->PoW->[PoW] and so on */
                    nBlockTrust = (nBaseTrust >> 2);
                }
            }

        } else {

            const CBlockIndex *pindexP1 = pprev;
            const CBlockIndex *pindexP2 = pindexP1->pprev;
            const CBlockIndex *pindexP3 = pindexP2->pprev;

            /* PoS difficulty is an unreliable source for trust scoring;
             * use the full trust of the previous PoW block as a basis instead */

            uint256 nPrevTrust = pindexP1->nChainTrust - pindexP2->nChainTrust;

            if(pindexP1->IsProofOfWork()) {
                /* 200% trust for PoS following PoW */
                if(pindexP2->IsProofOfStake()) {
                    /* PoS->PoW->[PoS]: 100% to 200% */
                    nBlockTrust = (nPrevTrust << 1);
                } else {
                    if(pindexP3->IsProofOfStake()) {
                        /* PoS->PoW->PoW->[PoS]: 50% to 200% */
                        nBlockTrust = (nPrevTrust << 2);
                    } else {
                        /* PoW->PoW->PoW->PoS: 25% to 200% */
                        nBlockTrust = (nPrevTrust << 3);
                    }
                }
            } else {
                /* PoS following at least one PoS */
                if(pindexP2->IsProofOfWork()) {
                    /* 150% of trust for PoW->PoS->[PoS] */
                    nBlockTrust = (CBigNum(nPrevTrust) * 3 / 4).getuint256();
                } else {
                    /* PoS following at least two PoS */
                    if(pindexP3->IsProofOfWork()) {
                        /* 100% of trust for PoW->PoS->PoS->[PoS] */
                        nBlockTrust = (CBigNum(nPrevTrust) * 2 / 3).getuint256();
                    } else {
                        /* PoS following at least three PoS */
                        const CBlockIndex *pindexP4 = pindexP3->pprev;
                        if(pindexP4->IsProofOfWork()) {
                            /* 50% of trust for PoW->PoS->PoS->PoS->[PoS] */
                            nBlockTrust = (nPrevTrust >> 1);
                        } else {
                            /* 50% of trust for PoS->PoS->PoS->PoS->[PoS] */
                            nBlockTrust = nPrevTrust;
                        }
                    }
                }
            }

        }

        if(nBlockTrust < (uint256)1) nBlockTrust = (uint256)1;

        return(nBlockTrust);

    }

    /* Second protocol (NVC style) */

    // Calculate work amount for block
    uint256 nPoWTrust = (CBigNum(nPoWBase) / (bnTarget+1)).getuint256();

    // Set nPowTrust to 1 if we are checking PoS block or PoW difficulty is too low
    nPoWTrust = (IsProofOfStake() || nPoWTrust < 1) ? 1 : nPoWTrust;

    // Return nPoWTrust for the first 12 blocks
    if (pprev == NULL || pprev->nHeight < 12)
        return nPoWTrust;

    const CBlockIndex* currentIndex = pprev;

    if(IsProofOfStake())
    {
        CBigNum bnNewTrust = (CBigNum(1)<<256) / (bnTarget+1);

        // Return 1/3 of score if parent block is not the PoW block
        if (!pprev->IsProofOfWork())
            return (bnNewTrust / 3).getuint256();

        int nPoWCount = 0;

        // Check last 12 blocks type
        while (pprev->nHeight - currentIndex->nHeight < 12)
        {
            if (currentIndex->IsProofOfWork())
                nPoWCount++;
            currentIndex = currentIndex->pprev;
        }

        // Return 1/3 of score if less than 3 PoW blocks found
        if (nPoWCount < 3)
            return (bnNewTrust / 3).getuint256();

        return bnNewTrust.getuint256();
    }
    else
    {
        CBigNum bnLastBlockTrust = CBigNum(pprev->nChainTrust - pprev->pprev->nChainTrust);

        // Return nPoWTrust + 2/3 of previous block score if two parent blocks are not PoS blocks
        if (!(pprev->IsProofOfStake() && pprev->pprev->IsProofOfStake()))
            return nPoWTrust + (2 * bnLastBlockTrust / 3).getuint256();

        int nPoSCount = 0;

        // Check last 12 blocks type
        while (pprev->nHeight - currentIndex->nHeight < 12)
        {
            if (currentIndex->IsProofOfStake())
                nPoSCount++;
            currentIndex = currentIndex->pprev;
        }

        // Return nPoWTrust + 2/3 of previous block score if less than 7 PoS blocks found
        if (nPoSCount < 7)
            return nPoWTrust + (2 * bnLastBlockTrust / 3).getuint256();

        bnTarget.SetCompact(pprev->nBits);

        if (bnTarget <= 0)
            return 0;

        CBigNum bnNewTrust = (CBigNum(1)<<256) / (bnTarget+1);

        // Return nPoWTrust + full trust score for previous block nBits
        return nPoWTrust + bnNewTrust.getuint256();
    }
}


bool ProcessBlock(CNode* pfrom, CBlock* pblock, CDiskBlockPos *dbp) {
    uint256 hash = pblock->GetHash();

    /* Duplicate block check */
    if(mapBlockIndex.count(hash))
      return error("ProcessBlock() : block %s height %d have already",
        hash.ToString().substr(0,20).c_str(), mapBlockIndex[hash]->nHeight);
    if(mapOrphanBlocks.count(hash))
      return error("ProcessBlock() : orphan block %s have already",
        hash.ToString().substr(0,20).c_str());

    /* Ask for a pending advanced checkpoint if any */
    if(pfrom && !IsInitialBlockDownload())
      Checkpoints::AskForPendingSyncCheckpoint(pfrom);

    /* DDoS protection: duplicate stakes are allowed only if referenced
     * by an orphan child block and a pending advanced checkpoint */
    if(!fReindex && pblock->IsProofOfStake()) {
        if(setStakeSeen.count(pblock->GetProofOfStake()) &&
          !mapOrphanBlocksByPrev.count(hash) &&
          !Checkpoints::WantedByPendingSyncCheckpoint(hash)) {
            return(error("ProcessBlock() : block %s duplicate proof-of-stake (%s, %d)",
              hash.ToString().substr(0,20).c_str(),
              pblock->GetProofOfStake().first.ToString().c_str(),
              pblock->GetProofOfStake().second));
        }
    }

    /* Basic block integrity checks including PoW target and signature verification */
    if(!pblock->CheckBlock())
      return(error("ProcessBlock() : CheckBlock() FAILED"));

    if(pblock->IsProofOfStake()) { 
        bool fCritical = true;
        uint256 hashProofOfStake;

        // Verify proof-of-stake script, hash target and signature
        if(!pblock->CheckStakeSignature(hashProofOfStake, fCritical)) {

            if(fCritical) {
                /* A critical PoS error which cannot be tolerated */
                if(pfrom) pfrom->Misbehaving(100);
                return(error("ProcessBlock() : block %s invalid proof-of-stake",
                  hash.ToString().substr(0,20).c_str()));
            } else {
                /* A non-critical PoS error may be worked around later */
                if(pfrom && (pblock->GetBlockTime() > Checkpoints::GetLastCheckpointTime())
                  && !IsInitialBlockDownload()) pfrom->Misbehaving(1);
                printf("ProcessBlock(): block %s proof-of-stake check failed, try again later\n",
                  hash.ToString().substr(0,20).c_str());
                return(false);
            }
        }

        /* Add this valid stake to the map if it isn't there */ 
        if(!mapProofOfStake.count(hash))
          mapProofOfStake.insert(make_pair(hash, hashProofOfStake));
    }

    // If don't already have its previous block, shunt it off to holding area until we get it
    if (!mapBlockIndex.count(pblock->hashPrevBlock))
    {
        printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().substr(0,20).c_str());
        CBlock* pblock2 = new CBlock(*pblock);

        if (pblock2->IsProofOfStake())
        {
            // Limited duplicity on stake: prevents block flood attack
            // Duplicate stake allowed only when there is orphan child block
            if(setStakeSeenOrphan.count(pblock2->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash)
              && !Checkpoints::WantedByPendingSyncCheckpoint(hash))
              return error("ProcessBlock() : duplicate proof-of-stake (%s, %d) for orphan block %s",
                pblock2->GetProofOfStake().first.ToString().c_str(), pblock2->GetProofOfStake().second,
                hash.ToString().c_str());
            else
                setStakeSeenOrphan.insert(pblock2->GetProofOfStake());
        }

        mapOrphanBlocks.insert(make_pair(hash, pblock2));
        mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));

        // Ask this guy to fill in what we're missing
        if (pfrom)
        {
            pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(pblock2));
            // ppcoin: getblocks may not obtain the ancestor block rejected
            // earlier by duplicate-stake check so we ask for it again directly
            if (!IsInitialBlockDownload())
                pfrom->AskFor(CInv(MSG_BLOCK, WantedByOrphan(pblock2)));

        }
        return true;
    }

    // Store to disk
    if(!pblock->AcceptBlock(dbp))
      return(error("ProcessBlock() : AcceptBlock() FAILED"));

    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (unsigned int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock* pblockOrphan = (*mi).second;
            if (pblockOrphan->AcceptBlock())
                vWorkQueue.push_back(pblockOrphan->GetHash());
            mapOrphanBlocks.erase(pblockOrphan->GetHash());
            setStakeSeenOrphan.erase(pblockOrphan->GetProofOfStake());
            delete pblockOrphan;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }

    printf("ProcessBlock: ACCEPTED\n");

    /* Checkpoint master sends a new advanced checkpoint
     * according to the depth specified by -checkpointdepth */
    if(pfrom && !CSyncCheckpoint::strMasterPrivKey.empty())
      Checkpoints::SendSyncCheckpoint(Checkpoints::AutoSelectSyncCheckpoint());

    return true;
}

// novacoin: attempt to generate suitable proof-of-stake
bool CBlock::SignBlock(CWallet& wallet, int64 nStakeReward) {

    // if we are trying to sign
    //    something except proof-of-stake block template
    if (!vtx[0].vout[0].IsEmpty())
        return false;

    // if we are trying to sign
    //    a complete proof-of-stake block
    if (IsProofOfStake())
        return true;

    static int64 nLastCoinStakeSearchTime = GetAdjustedTime(); // startup timestamp

    CKey key;
    CTransaction txCoinStake;
    int64 nSearchTime = txCoinStake.nTime; // search to current time

    if (nSearchTime > nLastCoinStakeSearchTime)
    {
        if (wallet.CreateCoinStake(wallet, nBits, nSearchTime-nLastCoinStakeSearchTime, txCoinStake, key, nStakeReward))
        {
            if(txCoinStake.nTime >= max((pindexBest->GetMedianTimePast() + BLOCK_LIMITER_TIME_NEW + 1),
              PastDrift(pindexBest->GetBlockTime()))) {

                // make sure coinstake would meet timestamp protocol
                //    as it would be the same as the block timestamp
                vtx[0].nTime = nTime = txCoinStake.nTime;
                nTime = max((pindexBest->GetMedianTimePast() + BLOCK_LIMITER_TIME_NEW + 1), GetMaxTransactionTime());
                nTime = max(GetBlockTime(), PastDrift(pindexBest->GetBlockTime()));

                // we have to make sure that we have no future timestamps in
                //    our transactions set
                for (vector<CTransaction>::iterator it = vtx.begin(); it != vtx.end();)
                    if (it->nTime > nTime) { it = vtx.erase(it); } else { ++it; }

                vtx.insert(vtx.begin() + 1, txCoinStake);
                hashMerkleRoot = BuildMerkleTree();

                // append a signature to our block
                return key.Sign(GetHash(), vchBlockSig);
            }
        }
        nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
        nLastCoinStakeSearchTime = nSearchTime;
    }

    return false;
}


/* Sign a proof-of-work block;
 * NOTE: these signatures were made obsolete after the switch to NeoScrypt,
 * must be empty in order to pass validation and save ~71 byte of block size */
bool CBlock::SignWorkBlock(const CKeyStore& keystore) {
    vector<valtype> vSolutions;
    txnouttype whichType;
    uint i;

    /* Don't attempt to sign a PoS block */
    if(vtx[0].vout[0].IsEmpty()) return(false);

    for(i = 0; i < vtx[0].vout.size(); i++) {
        const CTxOut& txout = vtx[0].vout[i];

        Solver(txout.scriptPubKey, whichType, vSolutions);

        /* TX_PUBKEY is the standard signature */
        if(whichType == TX_PUBKEY) {
            valtype& vchPubKey = vSolutions[0];
            CKey key;

            if(!keystore.GetKey(Hash160(vchPubKey), key))
              continue;
            if(key.GetPubKey() != vchPubKey)
              continue;
            if(!key.Sign(GetHash(), vchBlockSig))
              continue;
            return(true);
        }
    }

    printf("SignWorkBlock() : failed to sign a proof-of-work block\n");
    return(false);
}

/* Get a proof-of-stake generation key */
bool CBlock::GetGenerator(CKey& key) const {
    vector<valtype> vSolutions;
    txnouttype whichType;

    /* Don't attempt to verify a PoW block */
    if(!vtx[0].vout[0].IsEmpty())
      return(false);

    const CTxOut& txout = vtx[1].vout[1];
    if(!Solver(txout.scriptPubKey, whichType, vSolutions))
      return(false);

    /* TX_PUBKEY is the standard signature */
    if(whichType == TX_PUBKEY) {
        valtype& vchPubKey = vSolutions[0];

        /* Set up the key and return accordingly */
        return(key.SetPubKey(vchPubKey));
    }

    return(false);
}

/* Verify a proof-of-stake block signature */
bool CBlock::CheckStakeSignature(uint256& hashProofOfStake, bool& fCritical) const {
    uint256 hashTarget = 0;
    fCritical = true;
    CKey key;

    /* Critical failure: invalid key */
    if(!GetGenerator(key))
      return(false);

    /* Critical failure: absent block signature */
    if(vchBlockSig.empty())
      return(false);

    /* Critical failure: invalid block signature */
    if(!key.Verify(GetHash(), vchBlockSig))
      return(false);

    /* Verify hash target and coin stake signature */
    if(!CheckProofOfStake(vtx[1], nBits, hashProofOfStake, hashTarget, fCritical, false))
      return(false);

    return(true);
}

/* Verify a proof-of-work block signature */
bool CBlock::CheckWorkSignature() const {
    vector<valtype> vSolutions;
    txnouttype whichType;
    int nBlockHeight;
    uint i;

    /* Don't attempt to verify a PoS block */
    if(vtx[0].vout[0].IsEmpty())
      return(false);

    nBlockHeight = GetBlockHeight();
    if((fTestNet && (nBlockHeight >= nTestnetForkFive)) ||
      (!fTestNet && (nBlockHeight >= nForkSix))) {
        /* Insist on empty PoW block signatures */
        return(vchBlockSig.empty());
    }

    for(i = 0; i < vtx[0].vout.size(); i++) {
        const CTxOut& txout = vtx[0].vout[i];

        Solver(txout.scriptPubKey, whichType, vSolutions);

        /* TX_PUBKEY is the standard signature */
        if(whichType == TX_PUBKEY) {
            valtype& vchPubKey = vSolutions[0];
            CKey key;

            if(!key.SetPubKey(vchPubKey))
              continue;
            if(vchBlockSig.empty())
              continue;
            if(!key.Verify(GetHash(), vchBlockSig))
              continue;
            return(true);
        }
    }

    return(false);
}

bool CheckDiskSpace(uint64 nAdditionalBytes)
{
    uint64 nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
    {
        fShutdown = true;
        string strMessage = _("Warning: Disk space is low!");
        strMiscWarning = strMessage;
        printf("*** %s\n", strMessage.c_str());
        uiInterface.ThreadSafeMessageBox(strMessage, "Orbitcoin", CClientUIInterface::OK | CClientUIInterface::ICON_EXCLAMATION | CClientUIInterface::MODAL);
        StartShutdown();
        return false;
    }
    return true;
}


CCriticalSection cs_LastBlockFile;
CBlockFileInfo infoLastBlockFile;
int nLastBlockFile = 0;

FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return NULL;
    boost::filesystem::path path = GetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
    boost::filesystem::create_directories(path.parent_path());
    FILE* file = fopen(path.string().c_str(), "rb+");
    if (!file && !fReadOnly)
        file = fopen(path.string().c_str(), "wb+");
    if (!file) {
        printf("Unable to open file %s\n", path.string().c_str());
        return NULL;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            printf("Unable to seek to position %u of %s\n", pos.nPos, path.string().c_str());
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "blk", fReadOnly);
}

FILE *OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "rev", fReadOnly);
}

CBlockIndex * InsertBlockIndex(uint256 hash)
{
    if (hash == 0)
        return NULL;

    // Return existing
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("InsertBlockIndex() : new CBlockIndex failed");
    mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

/* Testnet related chain settings */
void InitTestnet() {

    if(!fTestNet) return;

    pchMessageStart[0] = 0xFD;
    pchMessageStart[1] = 0xF2;
    pchMessageStart[2] = 0xF0;
    pchMessageStart[3] = 0xEF;

    bnProofOfStakeLimit = bnProofOfStakeLimitTestNet;
    bnProofOfWorkLimit  = bnProofOfWorkLimitTestNet;

    /* Positive time weight after 20 minutes */
    nStakeMinAgeOne = 20 * 60;
    nStakeMinAgeTwo = 20 * 60;
    /* Full time weight at 20 hours (+20 minutes) */
    nStakeMaxAge = 20 * 60 * 60;
    /* [Initial] interval of 1 minute between stake modifiers */
    nModifierIntervalOne = 60;
    /* [Current] interval of 30 seconds between stake modifiers */
    nModifierIntervalTwo = 30;
    nBaseMaturity = BASE_MATURITY_TESTNET;
}

bool static LoadBlockIndexDB()
{
    if (!pblocktree->LoadBlockIndexGuts())
        return false;

    if (fRequestShutdown)
        return true;

    // Calculate nChainTrust
    vector<pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*)& item, vSortedByHeight)
    {
        CBlockIndex* pindex = item.second;
        pindex->nChainTrust = (pindex->pprev ? pindex->pprev->nChainTrust : 0) + pindex->GetBlockTrust();
        pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS && !(pindex->nStatus & BLOCK_FAILED_MASK))
            setBlockIndexValid.insert(pindex);

        // Calculate stake modifier checksum
        pindex->nStakeModifierChecksum = GetStakeModifierChecksum(pindex);
        if(!CheckStakeModifierCheckpoints(pindex->nHeight, pindex->nStakeModifierChecksum))
          return(error("LoadBlockIndexDB() : failed stake modifier checkpoint height=%d, " \
            "modifier=0x%016" PRI64x, pindex->nHeight, pindex->nStakeModifier));
    }

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    printf("LoadBlockIndexDB(): last block file = %i\n", nLastBlockFile);
    if (pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile))
        printf("LoadBlockIndexDB(): last block file: %s\n", infoLastBlockFile.ToString().c_str());

    // Load hashBestChain pointer to end of best chain
    pindexBest = pcoinsTip->GetBestBlock();
    if (pindexBest == NULL)
    {
        if (pindexGenesisBlock == NULL)
            return true;
        return error("LoadBlockIndexDB() : hashBestChain not loaded");
    }
    hashBestChain = pindexBest->GetBlockHash();
    nBestHeight = pindexBest->nHeight;
    nBestChainTrust = pindexBest->nChainTrust;

    // set 'next' pointers in best chain
    CBlockIndex *pindex = pindexBest;
    while(pindex != NULL && pindex->pprev != NULL) {
         CBlockIndex *pindexPrev = pindex->pprev;
         pindexPrev->pnext = pindex;
         pindex = pindexPrev;
    }
    printf("LoadBlockIndexDB(): hashBestChain=%s  height=%d date=%s\n",
        hashBestChain.ToString().substr(0,20).c_str(), nBestHeight,
        DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    // Load sync-checkpoint
    if (!pblocktree->ReadSyncCheckpoint(Checkpoints::hashSyncCheckpoint))
        return error("LoadBlockIndexDB() : hashSyncCheckpoint not loaded");
    printf("LoadBlockIndexDB(): synchronized checkpoint %s\n", Checkpoints::hashSyncCheckpoint.ToString().c_str());

    // Load bnBestInvalidTrust, OK if it doesn't exist
    CBigNum bnBestInvalidTrust;
    pblocktree->ReadBestInvalidTrust(bnBestInvalidTrust);
    nBestInvalidTrust = bnBestInvalidTrust.getuint256();

    // Verify blocks in the best chain
    int nCheckLevel = GetArg("-checklevel", 1);
    int nCheckDepth = GetArg( "-checkblocks", 500);
    if (nCheckDepth == 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > nBestHeight)
        nCheckDepth = nBestHeight;
    printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CBlockIndex* pindexFork = NULL;
    for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
    {
        if (fRequestShutdown || pindex->nHeight < nBestHeight-nCheckDepth)
            break;
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("LoadBlockIndexDB() : block.ReadFromDisk failed");
        // check level 1: verify block validity
        if (nCheckLevel>0 && !block.CheckBlock())
        {
            printf("LoadBlockIndexDB() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pindex->pprev;
        }
        // TODO: stronger verifications
    }
    if (pindexFork && !fRequestShutdown)
    {
        // TODO: reorg back
        return error("LoadBlockIndexDB(): chain database corrupted");
    }

    return true;
}

bool LoadBlockIndex(bool fAllowNew) {

    //
    // Init with genesis block
    //
    if(!LoadBlockIndexDB()) return false;

    // Init with genesis block
    if(mapBlockIndex.empty()) {

        if(!fAllowNew) return false;

        CTransaction txNew;
        CBlock block;

        if(!fTestNet) {

            // The Orbitcoin genesis block:
            // CBlock(hash=683373dac7ec1b01a9e10d4f5ef3dda0bf4c31ddefe5cffa14550dc0c776e699, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=7ff8c320f9141cbc8714f295d4a3091a57191922752d087429e5b6ddd80019f8, nTime=1375030725, nBits=1e0fffff, nNonce=1774394, vtx=1, vchBlockSig=)
            //   Coinbase(hash=7ff8c320f9, nTime=1375030700, ver=2, vin.size=1, vout.size=1, nLockTime=0)
            //     CTxIn(COutPoint(0000000000, 4294967295), coinbase 04ffff001d020f27464f6d6e69636f6d2c205075626c69636973206d6572676520696e746f2062696767657374206164206669726d202d20555341546f6461792c204a756c792032382c2032303133)
            //     CTxOut(empty)
            //   vMerkleTree: 7ff8c320f9

            const char* pszTimestamp = "Omnicom, Publicis merge into biggest ad firm - USAToday, July 28, 2013";
            txNew.vin.resize(1);
            txNew.vout.resize(1);
            txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(9999) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
            txNew.vout[0].SetEmpty();
            txNew.nTime = 1375030700;
            txNew.strTxComment = "text:Orbitcoin genesis block";
            block.vtx.push_back(txNew);
            block.hashPrevBlock = 0;
            block.hashMerkleRoot = block.BuildMerkleTree();
            block.nVersion = 1;
            block.nTime    = 1375030725;
            block.nBits    = bnProofOfWorkLimit.GetCompact();
            block.nNonce   = 1774394;

        } else {

            // The Orbitcoin testnet genesis block:
            // CBlock(hash=0000a6a079a91fe96443c0be34a0b140057d4259f51286c9d99d175238bf4b7f, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=872a72de06678cd706521062eba11895314377ae1d4d1eb7eb83e864bbd497ef, nTime=1392724800, nBits=1f00ffff, nNonce=97337, vtx=1, vchBlockSig=)
            //   Coinbase(hash=872a72de06, nTime=1392724800, ver=2, vin.size=1, vout.size=1, nLockTime=0, strTxComment=text:Orbitcoin testnet genesis)
            //     CTxIn(COutPoint(0000000000, 4294967295), coinbase 04ffff001d020f274c6941737465726f6964203230303020454d32363a2027706f74656e7469616c6c792068617a6172646f75732720737061636520726f636b20746f20666c7920636c6f736520746f204561727468202d2054686520477561726469616e202d2031382f4665622f32303134)
            //     CTxOut(nValue=1.00, scriptPubKey=049023f10bccda76f971d6417d420c6bb5735d3286669ce03b49c5fea07078f0e07b19518ee1c0a4f81bcf56a5497ad7d8200ce470eea8c6e2cf65f1ee503f0d3e OP_CHECKSIG)
            //   vMerkleTree: 872a72de06

            const char* pszTimestamp = "Asteroid 2000 EM26: 'potentially hazardous' space rock to fly close to Earth - The Guardian - 18/Feb/2014";
            txNew.vin.resize(1);
            txNew.vout.resize(1);
            txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(9999) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
            txNew.vout[0].nValue = 1 * COIN;
            txNew.vout[0].scriptPubKey = CScript() << ParseHex("049023F10BCCDA76F971D6417D420C6BB5735D3286669CE03B49C5FEA07078F0E07B19518EE1C0A4F81BCF56A5497AD7D8200CE470EEA8C6E2CF65F1EE503F0D3E") << OP_CHECKSIG;
            txNew.nTime = 1392724800;
            txNew.strTxComment = "text:Orbitcoin testnet genesis block";
            block.vtx.push_back(txNew);
            block.hashPrevBlock = 0;
            block.hashMerkleRoot = block.BuildMerkleTree();
            block.nVersion = 1;
            block.nTime    = 1392724800;
            block.nBits    = bnProofOfWorkLimit.GetCompact();
            block.nNonce   = 97337;

        }

        //// debug print
        printf("%s\n", block.GetHash().ToString().c_str());
        printf("%s\n", block.hashMerkleRoot.ToString().c_str());

        if(!fTestNet) assert(block.hashMerkleRoot == uint256("0x7ff8c320f9141cbc8714f295d4a3091a57191922752d087429e5b6ddd80019f8"));
        else assert(block.hashMerkleRoot == uint256("0x872a72de06678cd706521062eba11895314377ae1d4d1eb7eb83e864bbd497ef"));

        // If no match on genesis block hash, then generate one
        if(false && ((fTestNet && (block.GetHash() != hashGenesisBlockTestNet)) ||
                    (!fTestNet && (block.GetHash() != hashGenesisBlock)))) {

            printf("Genesis block mining...\n");

            uint profile = fNeoScrypt ? 0x0 : 0x3;
            uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
            uint256 hash;

            while(true) {
                neoscrypt((uchar *) &block.nVersion, (uchar *) &hash, profile);
                if(hash <= hashTarget) break;
                if(!(block.nNonce & 0xFFF))
                  printf("nonce %08X: hash = %s (target = %s)\n",
                    block.nNonce, hash.ToString().c_str(),
                    hashTarget.ToString().c_str());
                ++block.nNonce;
                if(!block.nNonce) {
                    printf("nonce limit reached, incrementing time\n");
                    ++block.nTime;
                }
            }
            printf("block.nTime = %u \n", block.nTime);
            printf("block.nNonce = %u \n", block.nNonce);
            printf("block.GetHash = %s\n", block.GetHash().ToString().c_str());
            printf("block.GetHashPoW = %s\n", block.GetHashPoW().ToString().c_str());
        }

        block.print();
        if(!fTestNet) assert(block.GetHash() == hashGenesisBlock);
        else assert(block.GetHash() == hashGenesisBlockTestNet);

        // Start new block file
        unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        if (!FindBlockPos(blockPos, nBlockSize+8, 0, block.nTime))
            return error("AcceptBlock() : FindBlockPos failed");
        if (!block.WriteToDisk(blockPos))
            return error("LoadBlockIndex() : writing genesis block to disk failed");
        if (!block.AddToBlockIndex(blockPos))
            return error("LoadBlockIndex() : genesis block not accepted");

        // initialize synchronized checkpoint
        if (!Checkpoints::WriteSyncCheckpoint((!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet)))
            return error("LoadBlockIndex() : failed to init sync checkpoint");
    }

    string strPubKey = "";
    // if checkpoint master key changed must reset sync-checkpoint
    if (!pblocktree->ReadCheckpointPubKey(strPubKey) || strPubKey != CSyncCheckpoint::strMasterPubKey)
    {
        {
            LOCK(Checkpoints::cs_hashSyncCheckpoint);
            // write checkpoint master key to db
            if (!pblocktree->WriteCheckpointPubKey(CSyncCheckpoint::strMasterPubKey))
                return error("LoadBlockIndex() : failed to write new checkpoint master key to db");
        }

        if ((!fTestNet) && !Checkpoints::ResetSyncCheckpoint())
            return error("LoadBlockIndex() : failed to reset sync-checkpoint");
    }

    return true;
}

void PrintBlockTree()
{
    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
       }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d (blk%05u.dat:0x%x)  %s  tx %" PRIszu "",
          pindex->nHeight, pindex->GetBlockPos().nFile, pindex->GetBlockPos().nPos,
          DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(), block.vtx.size());

        PrintWallets(block);

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}

bool ReadBlockFromDisk(CBlock &block, const CDiskBlockPos &pos) {
    block.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if(filein.IsNull())
      return(error("ReadBlockFromDisk() : OpenBlockFile() failed for %s", pos.ToString().c_str()));

    // Read block
    try {
        filein >> block;
    } catch(const std::exception& e) {
        return(error("ReadBlockFromDisk(): deserialise or I/O error at %s", pos.ToString().c_str()));
    }

    return(true);
}

bool LoadExternalBlockFile(FILE* fileIn, CDiskBlockPos *dbp) {
    int64 nStart = GetTimeMillis();

    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBlockPos> mapBlocksUnknownParent;

    uint nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2 * MAX_BLOCK_SIZE, MAX_BLOCK_SIZE + 8,
          SER_DISK, CLIENT_VERSION);
        uint64 nRewind = blkdat.GetPos();

        while(!blkdat.eof()) {
            boost::this_thread::interruption_point();
            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            uint nSize = 0;
            try {
                // locate a header
                uchar buf[4];
                blkdat.FindByte(pchMessageStart[0]);
                nRewind = blkdat.GetPos() + 1;
                blkdat >> FLATDATA(buf);
                if(memcmp(buf, pchMessageStart, 4))
                  continue;
                // read size
                blkdat >> nSize;
                if((nSize < 80) || (nSize > MAX_BLOCK_SIZE))
                  continue;
            } catch(const std::exception &) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64 nBlockPos = blkdat.GetPos();
                if(dbp)
                  dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                CBlock block;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                uint256 hash = block.GetHash();

                /* Genesis block requires special processing */
                if(hash == (fTestNet ? hashGenesisBlockTestNet : hashGenesisBlock)) {
                    if(!fReindex) continue; /* already in the index if bootstrapping */
                    block.BuildMerkleTree();
                    block.print();
                    uint nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
                    CDiskBlockPos blockPos;
                    if(dbp != NULL) blockPos = *dbp;
                    else break;
                    if(!FindBlockPos(blockPos, nBlockSize + 8, 0, block.nTime, 1)) {
                        printf("FindBlockPos() failed on the genesis block\n");
                        break;
                    }
                    if(!block.AddToBlockIndex(blockPos)) {
                        printf("AddToBlockIndex() failed on the genesis block\n");
                        break;
                    }
                    Checkpoints::WriteSyncCheckpoint(fTestNet ? hashGenesisBlockTestNet : hashGenesisBlock);
                    nLoaded = 1;
                    continue;
                }

                // detect out of order blocks, and store them for later
                if(mapBlockIndex.find(block.hashPrevBlock) == mapBlockIndex.end()) {
                    printf("LoadExternalBlockFile() : out of order block %s, parent %s not known\n",
                      hash.ToString().c_str(), block.hashPrevBlock.ToString().c_str());
                    if(dbp)
                      mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                    continue;
                }

                // process in case the block isn't known yet
                if((mapBlockIndex.count(hash) == 0) ||
                  ((mapBlockIndex[hash]->nStatus & BLOCK_HAVE_DATA) == 0)) {
                    if(ProcessBlock(NULL, &block, dbp))
                      nLoaded++;
                    else
                      break;
                }

                // Recursively process earlier encountered successors of this block
                deque<uint256> queue;
                queue.push_back(hash);
                while(!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBlockPos>::iterator, std::multimap<uint256, CDiskBlockPos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while(range.first != range.second) {
                        std::multimap<uint256, CDiskBlockPos>::iterator it = range.first;
                        if(ReadBlockFromDisk(block, it->second)) {
                            printf("LoadExternalBlockFile() : processing out of order child %s of %s\n",
                              block.GetHash().ToString().c_str(), head.ToString().c_str());
                            if(ProcessBlock(NULL, &block, &it->second)) {
                                nLoaded++;
                                queue.push_back(block.GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                    }
                }
            } catch(std::exception &e) {
                printf("LoadExternalBlockFile() : deserialise or I/O error caught while loading blocks\n");
            }
        }
    } catch(std::runtime_error &e) {
        printf("LoadExternalBlockFile() : system error caught while loading blocks\n");
        return(false);
    }

    if(nLoaded > 0) {
        printf("Loaded %u blocks from external file in %" PRI64d "ms\n",
          nLoaded, GetTimeMillis() - nStart);
        return(true);
    }

    return(false);
}


//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;

extern string strMintMessage;
extern string strMintWarning;

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;

    if (GetBoolArg("-testsafemode"))
        strRPC = "test";

    // ppcoin: wallet lock warning for minting
    if (strMintWarning != "")
    {
        nPriority = 0;
        strStatusBar = strMintWarning;
    }

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // * Should not enter safe mode for longer invalid chain
    // * If sync-checkpoint is too old do not enter safe mode
    // * Display warning only in the STRICT mode
    if (CheckpointsMode == Checkpoints::STRICT && Checkpoints::IsSyncCheckpointTooOld(60 * 60 * 24 * 10) &&
        !fTestNet && !IsInitialBlockDownload())
    {
        nPriority = 100;
        strStatusBar = _("WARNING: Checkpoint is too old. Wait for block chain to download, or notify developers.");
    }

    // ppcoin: if detected invalid checkpoint enter safe mode
    if (Checkpoints::hashInvalidCheckpoint != 0)
    {
        nPriority = 3000;
        strStatusBar = strRPC = _("WARNING: Invalid checkpoint found! Displayed transactions may not be correct! You may need to upgrade, or notify developers.");
    }

    // Alerts
    {
        LOCK(cs_mapAlerts);
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
                if (nPriority > 1000)
                    strRPC = strStatusBar;
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings() : invalid parameter");
    return "error";
}








//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:
        {
            bool txInMap = false;
            {
                LOCK(mempool.cs);
                txInMap = mempool.exists(inv.hash);
            }
            return txInMap || mapOrphanTransactions.count(inv.hash) ||
                pcoinsTip->HaveCoins(inv.hash);
        }
    case MSG_BLOCK:
        return mapBlockIndex.count(inv.hash) ||
               mapOrphanBlocks.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}




// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
unsigned char pchMessageStart[4] = { 0xe4, 0xef, 0xdb, 0xfd };

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    static map<CService, CPubKey> mapReuseKey;
    RandAddSeedPerfmon();

    if(fDebug)
      printf("received: %s (%" PRIszu " bytes)\n", strCommand.c_str(), vRecv.size());

    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        printf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

    if (strCommand == "version")
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            pfrom->Misbehaving(1);
            return false;
        }

        int64 nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64 nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion < MIN_PROTO_VERSION)
        {
            // Since February 20, 2012, the protocol is initiated at version 209,
            // and earlier versions are no longer supported
            printf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }

        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty())
            vRecv >> pfrom->strSubVer;
        if (!vRecv.empty())
            vRecv >> pfrom->nStartingHeight;

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            pfrom->addrLocal = addrMe;
            SeenLocal(addrMe);
        }

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            printf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->fDisconnect = true;
            return true;
        }

        /* Disconnect all obsolete clients after 1 Oct 2016 12:00:00 GMT */
        uint nAdjTime = GetAdjustedTime();
        if(nAdjTime > nForkThreeTime) {
            if(pfrom->nVersion < MIN_PROTOCOL_VERSION) {
                printf("obsolete node %s with client %d, disconnecting\n",
                  pfrom->addr.ToString().c_str(), pfrom->nVersion);
                pfrom->fDisconnect = true;
                return(true);
            }
        }

        // record my external IP reported by peer
        if (addrFrom.IsRoutable() && addrMe.IsRoutable())
            addrSeenByPeer = addrMe;

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        AddTimeData(pfrom->addr, nTime);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->vSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (!fNoListen && !IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable())
                    pfrom->PushAddress(addr);
            }

            /* Ask for new peer addresses */
            if(pfrom->fOneShot || (addrman.size() < 1000)) {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            addrman.Good(pfrom->addr);
        } else {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                addrman.Add(addrFrom, addrFrom);
                addrman.Good(addrFrom);
            }
        }

        /* Ask for new blocks */
        static int nAskedForBlocks = 0;
        if(!pfrom->fClient && !pfrom->fOneShot &&
          (pfrom->nStartingHeight > nBestHeight) &&
          ((nAskedForBlocks < 1) || (vNodes.size() <= 1))) {
            nAskedForBlocks++;
            pfrom->PushGetBlocks(pindexBest, uint256(0));
        }

        // Relay alerts
        {
            LOCK(cs_mapAlerts);
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
                item.second.RelayTo(pfrom);
        }

        // Relay sync-checkpoint
        {
            LOCK(Checkpoints::cs_hashSyncCheckpoint);
            if (!Checkpoints::checkpointMessage.IsNull())
                Checkpoints::checkpointMessage.RelayTo(pfrom);
        }

        pfrom->fSuccessfullyConnected = true;

        printf("receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());

        cPeerBlockCounts.input(pfrom->nStartingHeight);

        if(IsInitialBlockDownload()) {
            /* Aggressive synchronisation:
             * ask this peer for inventory if nothing received in the last 5 seconds */
            if((pfrom->nStartingHeight > nBestHeight) && ((GetTime() - nTimeBestReceived) > 5LL))
              pfrom->PushGetBlocks(pindexBest, uint256(0));
        } else {
            Checkpoints::AskForPendingSyncCheckpoint(pfrom);
        }
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        pfrom->Misbehaving(1);
        return false;
    }


    else if (strCommand == "verack")
    {
        pfrom->vRecv.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    }


    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        if (vAddr.size() > 1000)
        {
            pfrom->Misbehaving(20);
            return(error("message addr size() = %" PRIszu "", vAddr.size()));
        }

        // Store the new addresses
        vector<CAddress> vAddrOk;
        int64 nNow = GetAdjustedTime();
        int64 nSince = nNow - 10 * 60;
        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            if (fShutdown)
                return true;
            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                {
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint64 hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr)/(24*60*60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;
                    BOOST_FOREACH(CNode* pnode, vNodes)
                    {
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }

    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            return(error("message inv size() = %" PRIszu "", vInv.size()));
        }

        // find last block in inv vector
        unsigned int nLastBlock = (unsigned int)(-1);
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++) {
            if (vInv[vInv.size() - 1 - nInv].type == MSG_BLOCK) {
                nLastBlock = vInv.size() - 1 - nInv;
                break;
            }
        }
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];

            if (fShutdown)
                return true;
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(inv);
            if (fDebug)
                printf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");

            if (!fAlreadyHave)
                pfrom->AskFor(inv);
            else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash)) {
                pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash]));
            } else if (nInv == nLastBlock) {
                // In case we are on a very long side-chain, it is possible that we already have
                // the last block in an inv bundle sent in response to getblocks. Try to detect
                // this situation and push another getblocks to continue.
                pfrom->PushGetBlocks(mapBlockIndex[inv.hash], uint256(0));
                if (fDebug)
                    printf("force request: %s\n", inv.ToString().c_str());
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }


    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            return(error("message getdata size() = %" PRIszu "", vInv.size()));
        }

        if (fDebugNet || (vInv.size() != 1))
            printf("received getdata (%" PRIszu " invsz)\n", vInv.size());

        BOOST_FOREACH(const CInv& inv, vInv)
        {
            if (fShutdown)
                return true;
            if (fDebugNet || (vInv.size() == 1))
                printf("received getdata for: %s\n", inv.ToString().c_str());

            if (inv.type == MSG_BLOCK)
            {
                // Send block from disk
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    CBlock block;
                    block.ReadFromDisk((*mi).second);
                    pfrom->PushMessage("block", block);

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // ppcoin: send latest proof-of-work block to allow the
                        // download node to accept as orphan (proof-of-stake 
                        // block might be rejected by stake connection check)
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, GetLastBlockIndex(pindexBest, false)->GetBlockHash()));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                bool pushed = false;
                {
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_TX) {
                    LOCK(mempool.cs);
                    if (mempool.exists(inv.hash)) {
                        CTransaction tx = mempool.lookup(inv.hash);
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << tx;
                        pfrom->PushMessage("tx", ss);
                    }
                }
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }


    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        /* Time limit for responding to a particular peer */
        uint nCurrentTime = (uint)GetTime();
        if((nCurrentTime - 5U) < pfrom->nLastGetblocksReceived) {
            return(error("message getblocks spam"));
        } else {
            pfrom->nLastGetblocksReceived = nCurrentTime;
        }

        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;
        int nLimit = 1000;
        printf("getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str(), nLimit);
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                printf("  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
                // ppcoin: tell downloading node about the latest block if it's
                // without risk being rejected due to stake connection check
                if((hashStop != hashBestChain) &&
                  ((pindex->GetBlockTime() + nStakeMinAgeTwo) > pindexBest->GetBlockTime()))
                  pfrom->PushInventory(CInv(MSG_BLOCK, hashBestChain));
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                printf("  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().substr(0,20).c_str());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }
    else if (strCommand == "checkpoint")
    {
        CSyncCheckpoint checkpoint;
        vRecv >> checkpoint;

        if (checkpoint.ProcessSyncCheckpoint(pfrom))
        {
            // Relay
            pfrom->hashCheckpointKnown = checkpoint.hashCheckpoint;
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
                checkpoint.RelayTo(pnode);
        }
    }

    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->pnext;
        }

        vector<CBlock> vHeaders;
        int nLimit = 2000;
        printf("getheaders %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().substr(0,20).c_str());
        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }


    else if (strCommand == "tx")
    {
        vector<uint256> vWorkQueue;
        vector<uint256> vEraseQueue;
        CDataStream vMsg(vRecv);
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        bool fMissingInputs = false;
        if (tx.AcceptToMemoryPool(true, &fMissingInputs))
        {
            SyncWithWallets(inv.hash, tx, NULL, true);
            RelayTransaction(tx, inv.hash);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);
            vEraseQueue.push_back(inv.hash);

            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (set<uint256>::iterator mi = mapOrphanTransactionsByPrev[hashPrev].begin();
                     mi != mapOrphanTransactionsByPrev[hashPrev].end();
                     ++mi)
                {
                    const uint256& orphanTxHash = *mi;
                    CTransaction& orphanTx = mapOrphanTransactions[orphanTxHash];
                    bool fMissingInputs2 = false;

                    if (orphanTx.AcceptToMemoryPool(true, &fMissingInputs2))
                    {
                        printf("   accepted orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                        SyncWithWallets(inv.hash, tx, NULL, true);
                        RelayTransaction(orphanTx, orphanTxHash);
                        mapAlreadyAskedFor.erase(CInv(MSG_TX, orphanTxHash));
                        vWorkQueue.push_back(orphanTxHash);
                        vEraseQueue.push_back(orphanTxHash);
                    }
                    else if (!fMissingInputs2)
                    {
                        // invalid orphan
                        vEraseQueue.push_back(orphanTxHash);
                        printf("   removed invalid orphan tx %s\n", orphanTxHash.ToString().substr(0,10).c_str());
                    }
                }
            }

            BOOST_FOREACH(uint256 hash, vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            AddOrphanTx(tx);

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
            if (nEvicted > 0)
                printf("mapOrphan overflow, removed %u tx\n", nEvicted);
        }
        if (tx.nDoS) pfrom->Misbehaving(tx.nDoS);
    }


    else if (strCommand == "block")
    {
        CBlock block;
        vRecv >> block;
        uint256 hashBlock = block.GetHash();
        int nBlockHeight = block.GetBlockHeight();

        if(nBlockHeight > (nBestHeight + 5000)) {
            /* Discard this block because cannot verify it any time soon */
            printf("received and discarded distant block %s height %d\n",
              hashBlock.ToString().substr(0,20).c_str(), nBlockHeight);
            /* Aggressive synchronisation:
             * ask this peer for inventory if nothing received in the last 5 seconds */
            if((pfrom->nStartingHeight > nBestHeight) && ((GetTime() - nTimeBestReceived) > 5LL))
              pfrom->PushGetBlocks(pindexBest, uint256(0));
        } else {
            printf("received block %s height %d\n",
              hashBlock.ToString().substr(0,20).c_str(), nBlockHeight);

            CInv inv(MSG_BLOCK, hashBlock);
            pfrom->AddInventoryKnown(inv);

            if(ProcessBlock(pfrom, &block))
              mapAlreadyAskedFor.erase(inv);

            if(block.nDoS)
              pfrom->Misbehaving(block.nDoS);
        }
    }


    else if (strCommand == "getaddr")
    {
        // Don't return addresses older than nCutOff timestamp
        int64 nCutOff = GetTime() - (nNodeLifespan * 24 * 60 * 60);
        pfrom->vAddrToSend.clear();
        vector<CAddress> vAddr = addrman.GetAddr();
        BOOST_FOREACH(const CAddress &addr, vAddr)
            if(addr.nTime > nCutOff)
                pfrom->PushAddress(addr);
    }


    else if (strCommand == "mempool")
    {
        std::vector<uint256> vtxid;
        mempool.queryHashes(vtxid);
        vector<CInv> vInv;
        for (unsigned int i = 0; i < vtxid.size(); i++) {
            CInv inv(MSG_TX, vtxid[i]);
            vInv.push_back(inv);
            if (i == (MAX_INV_SZ - 1))
                    break;
        }
        if (vInv.size() > 0)
            pfrom->PushMessage("inv", vInv);
    }


    else if (strCommand == "checkorder")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        if (!GetBoolArg("-allowreceivebyip"))
        {
            pfrom->PushMessage("reply", hashReply, (int)2, string(""));
            return true;
        }

        CWalletTx order;
        vRecv >> order;

        /// we have a chance to check the order here

        // Keep giving the same key to the same ip until they use it
        if (!mapReuseKey.count(pfrom->addr))
            pwalletMain->GetKeyFromPool(mapReuseKey[pfrom->addr], true);

        // Send back approval of order and pubkey to use
        CScript scriptPubKey;
        scriptPubKey << mapReuseKey[pfrom->addr] << OP_CHECKSIG;
        pfrom->PushMessage("reply", hashReply, (int)0, scriptPubKey);
    }


    else if (strCommand == "reply")
    {
        uint256 hashReply;
        vRecv >> hashReply;

        CRequestTracker tracker;
        {
            LOCK(pfrom->cs_mapRequests);
            map<uint256, CRequestTracker>::iterator mi = pfrom->mapRequests.find(hashReply);
            if (mi != pfrom->mapRequests.end())
            {
                tracker = (*mi).second;
                pfrom->mapRequests.erase(mi);
            }
        }
        if (!tracker.IsNull())
            tracker.fn(tracker.param1, vRecv);
    }


    else if(strCommand == "ping") {
        /* Pong response according to BIP31 */
        uint64 nonce = 0;
        vRecv >> nonce;
        pfrom->PushMessage("pong", nonce);
    }


    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0)
        {
            if (alert.ProcessAlert())
            {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    LOCK(cs_vNodes);
                    BOOST_FOREACH(CNode* pnode, vNodes)
                        alert.RelayTo(pnode);
                }
            }
            else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                pfrom->Misbehaving(10);
            }
        }
    }


    else
    {
        // Ignore unknown commands for extensibility
    }


    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
            AddressCurrentlyConnected(pfrom->addr);


    return true;
}

bool ProcessMessages(CNode* pfrom)
{
    CDataStream& vRecv = pfrom->vRecv;
    if (vRecv.empty())
        return true;
    //if (fDebug)
    //    printf("ProcessMessages(%u bytes)\n", vRecv.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //

    while (true)
    {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->vSend.size() >= SendBufferSize())
            break;

        // Scan for message start
        CDataStream::iterator pstart = search(vRecv.begin(), vRecv.end(), BEGIN(pchMessageStart), END(pchMessageStart));
        int nHeaderSize = vRecv.GetSerializeSize(CMessageHeader());
        if (vRecv.end() - pstart < nHeaderSize)
        {
            if ((int)vRecv.size() > nHeaderSize)
            {
                printf("\n\nPROCESSMESSAGE MESSAGESTART NOT FOUND\n\n");
                vRecv.erase(vRecv.begin(), vRecv.end() - nHeaderSize);
            }
            break;
        }
        if((pstart - vRecv.begin()) > 0)
          printf("\n\nPROCESSMESSAGE SKIPPED %" PRIpdd " BYTES\n\n",
            pstart - vRecv.begin());
        vRecv.erase(vRecv.begin(), pstart);

        // Read header
        vector<char> vHeaderSave(vRecv.begin(), vRecv.begin() + nHeaderSize);
        CMessageHeader hdr;
        vRecv >> hdr;
        if (!hdr.IsValid())
        {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;
        if (nMessageSize > MAX_SIZE)
        {
            printf("ProcessMessages(%s, %u bytes) : nMessageSize > MAX_SIZE\n", strCommand.c_str(), nMessageSize);
            continue;
        }
        if (nMessageSize > vRecv.size())
        {
            // Rewind and wait for rest of message
            vRecv.insert(vRecv.begin(), vHeaderSave.begin(), vHeaderSave.end());
            break;
        }

        // Checksum
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.nChecksum)
        {
            printf("ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
               strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Copy message to its own buffer
        CDataStream vMsg(vRecv.begin(), vRecv.begin() + nMessageSize, vRecv.nType, vRecv.nVersion);
        vRecv.ignore(nMessageSize);

        // Process message
        bool fRet = false;
        try
        {
            {
                LOCK(cs_main);
                fRet = ProcessMessage(pfrom, strCommand, vMsg);
            }
            if (fShutdown)
                return true;
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from over-long size
                printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else
            {
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        }
        catch (std::exception& e) {
            PrintExceptionContinue(&e, "ProcessMessages()");
        } catch (...) {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
            printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);
    }

    vRecv.Compact();
    return true;
}


bool SendMessages(CNode* pto, bool fSendTrickle)
{
    TRY_LOCK(cs_main, lockMain);
    if (lockMain) {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        // Keep-alive ping. We send a nonce of zero because we don't use it anywhere
        // right now.
        if (pto->nLastSend && GetTime() - pto->nLastSend > 30 * 60 && pto->vSend.empty()) {
            uint64 nonce = 0;
            pto->PushMessage("ping", nonce);
        }

        // Resend wallet transactions that haven't gotten in a block yet
        ResendWalletTransactions();

        // Address refresh broadcast
        static int64 nLastRebroadcast;
        if (!IsInitialBlockDownload() && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
        {
            {
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    if (nLastRebroadcast)
                        pnode->setAddrKnown.clear();

                    // Rebroadcast our address
                    if (!fNoListen)
                    {
                        CAddress addr = GetLocalAddress(&pnode->addr);
                        if (addr.IsRoutable())
                            pnode->PushAddress(addr);
                    }
                }
            }
            nLastRebroadcast = GetTime();
        }

        //
        // Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }


        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    // always trickle our own transactions
                    if (!fTrickleWait)
                    {
                        CWalletTx wtx;
                        if (GetTransaction(inv.hash, wtx))
                            if (wtx.fFromMe)
                                fTrickleWait = true;
                    }

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);


        //
        // Message: getdata
        //
        vector<CInv> vGetData;
        int64 nNow = GetTime() * 1000000;
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(inv))
            {
                if (fDebugNet)
                    printf("sending getdata: %s\n", inv.ToString().c_str());
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
                mapAlreadyAskedFor[inv] = nNow;
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);

    }
    return true;
}

// Amount compression:
// * If the amount is 0, output 0
// * first, divide the amount (in base units) by the largest power of 10 possible; call the exponent e (e is max 9)
// * if e<9, the last digit of the resulting number cannot be 0; store it as d, and drop it (divide by 10)
//   * call the result n
//   * output 1 + 10*(9*n + d - 1) + e
// * if e==9, we only know the resulting number is not zero, so output 1 + 10*(n - 1) + 9
// (this is decodable, as d is in [1-9] and e is in [0-9])

uint64 CTxOutCompressor::CompressAmount(uint64 n)
{
    if (n == 0)
        return 0;
    int e = 0;
    while (((n % 10) == 0) && e < 9) {
        n /= 10;
        e++;
    }
    if (e < 9) {
        int d = (n % 10);
        assert(d >= 1 && d <= 9);
        n /= 10;
        return 1 + (n*9 + d - 1)*10 + e;
    } else {
        return 1 + (n - 1)*10 + 9;
    }
}

uint64 CTxOutCompressor::DecompressAmount(uint64 x)
{
    // x = 0  OR  x = 1+10*(9*n + d - 1) + e  OR  x = 1+10*(n - 1) + 9
    if (x == 0)
        return 0;
    x--;
    // x = 10*(9*n + d - 1) + e
    int e = x % 10;
    x /= 10;
    uint64 n = 0;
    if (e < 9) {
        // x = 9*n + d - 1
        int d = (x % 9) + 1;
        x /= 9;
        // x = n
        n = x*10 + d;
    } else {
        n = x+1;
    }
    while (e) {
        n *= 10;
        e--;
    }
    return n;
}
