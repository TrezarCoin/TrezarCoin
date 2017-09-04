// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "db.h"
#include "miner.h"
#include "kernel.h"

using namespace std;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

string strMintMessage = "Info: Mining suspended due to locked wallet.";
string strMintWarning;

extern unsigned int nMinerSleep;

// Some explaining would be appreciated
class COrphan
{
public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        printf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
               ptx->GetHash().ToString().substr(0,10).c_str(), dPriority, dFeePerKb);
        BOOST_FOREACH(uint256 hash, setDependsOn)
            printf("   setDependsOn %s\n", hash.ToString().substr(0,10).c_str());
    }
};


uint64 nLastBlockTx = 0;
uint64 nLastBlockSize = 0;
int64 nLastCoinStakeSearchInterval = 0;
 
// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

// CreateNewBlock: create new block (without proof-of-work/proof-of-stake)
CBlock* CreateNewBlock(CWallet* pwallet, bool fProofOfStake, int64 *pStakeReward) {

    /* Reward must be returned for PoS */
    if(fProofOfStake && !pStakeReward)
      return(NULL);

    // Create new block
    CBlock *pblock = new CBlock();
    if(!pblock) return(NULL);

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);

    if(!fProofOfStake) {
        CReserveKey reservekey(pwallet);
        txNew.vout[0].scriptPubKey << reservekey.GetReservedKey() << OP_CHECKSIG;
    }
    else
        txNew.vout[0].SetEmpty();

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN/2);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", 11000);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Fee-per-kilobyte amount considered the same as "free"
    // Be careful setting this: if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    int64 nMinTxFee = MIN_TX_FEE;
    if (mapArgs.count("-mintxfee"))
        ParseMoney(mapArgs["-mintxfee"], nMinTxFee);

    CBlockIndex* pindexPrev = pindexBest;

    pblock->nBits = GetNextTargetRequired(pindexPrev, fProofOfStake, false);

    // Collect memory pool transactions into the block
    int64 nFees = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CCoinsViewCache view(*pcoinsTip, true);

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());
        for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
        {
            CTransaction& tx = (*mi).second;
            if (tx.IsCoinBase() || tx.IsCoinStake() || !tx.IsFinal())
                continue;

            COrphan* porphan = NULL;
            double dPriority = 0;
            int64 nTotalIn = 0;
            bool fMissingInputs = false;
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                // Read prev transaction
                CCoins coins;
                if (!view.GetCoins(txin.prevout.hash, coins))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        printf("ERROR: mempool transaction missing input\n");
                        if (fDebug) assert("mempool transaction missing input" == 0);
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].vout[txin.prevout.n].nValue;
                    continue;
                }
                int64 nValueIn = coins.vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;

                int nConf = pindexPrev->nHeight - coins.nHeight;
                dPriority += (double)nValueIn * nConf;
            }
            if (fMissingInputs) continue;

            // Priority is sum(valuein * age) / txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority /= nTxSize;

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            double dFeePerKb =  double(nTotalIn-tx.GetValueOut()) / (double(nTxSize)/1000.0);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->dFeePerKb = dFeePerKb;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &(*mi).second));
        }

        // Collect transactions into block
        uint64 nBlockSize = 1000;
        uint64 nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty()) {
            int64 nMinFee;
            unsigned int nAdjTime = GetAdjustedTime();

            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // second layer cached modifications just for this transaction
            CCoinsViewCache viewTemp(view, true);

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = tx.GetLegacySigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Timestamp limit
            if ((tx.nTime > nAdjTime) || (fProofOfStake && tx.nTime > pblock->vtx[0].nTime))
                continue;

            /* Low priority transactions up to 500 bytes in size
             * are free unless they get caught by the dust spam filter */
            bool fAllowFree = ((nBlockSize + nTxSize < 1500) || CTransaction::AllowFree(dPriority));
            nMinFee = tx.GetMinFee(nBlockSize, fAllowFree, GMF_BLOCK);

            // Skip free transactions if we're past the minimum block size:
            if (fSortedByFee && (dFeePerKb < nMinTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            // Prioritize by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || (dPriority < COIN * 2880 / 250)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            /* Script verification has been passed already while accepting
             * transactions to the memory pool */
            if(!tx.CheckInputs(viewTemp, CS_ALWAYS, SCRIPT_VERIFY_NONE))
              continue;

            int64 nTxFees = tx.GetValueIn(viewTemp)-tx.GetValueOut();
            if (nTxFees < nMinFee)
                continue;

            nTxSigOps += tx.GetP2SHSigOpCount(viewTemp);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

/*
 * We need to call UpdateCoins using actual block timestamp, so don't perform this here.
 *
            CTxUndo txundo;
            if (!tx.UpdateCoins(viewTemp, txundo, pindexPrev->nHeight+1, pblock->nTime))
                continue;

*/

            // push changes from the second layer cache to the first one
            viewTemp.Flush();
            uint256 hash = tx.GetHash();

            // Added
            pblock->vtx.push_back(tx);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fDebug && GetBoolArg("-printpriority"))
            {
                printf("priority %.1f feeperkb %.1f txid %s\n",
                       dPriority, dFeePerKb, tx.GetHash().ToString().c_str());
            }

            // Add transactions that depend on this one to the priority queue
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        if(fDebug && GetBoolArg("-printpriority"))
          printf("CreateNewBlock(): total size %" PRI64u "\n", nBlockSize);

        if(fProofOfStake) *pStakeReward = GetProofOfStakeReward(pindexPrev->nHeight+1, nFees);
        else pblock->vtx[0].vout[0].nValue = GetProofOfWorkReward(pindexPrev->nHeight+1, nFees);

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        pblock->nTime          = max((pindexPrev->GetMedianTimePast() + BLOCK_LIMITER_TIME + 1),
          pblock->GetMaxTransactionTime());
        pblock->nTime          = max(pblock->GetBlockTime(), PastDrift(pindexPrev->GetBlockTime()));
        if(!fProofOfStake) pblock->UpdateTime(pindexPrev);
        pblock->nNonce         = 0;
        pblock->nVersion = 3;
    }

    return(pblock);
}


void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;

    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required
    pblock->vtx[0].vin[0].scriptSig = (CScript() << nHeight << CBigNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}


/* Prepares a block header for transmission using RPC getwork */
void FormatDataBuffer(CBlock *pblock, uint *pdata) {
    uint i;

    struct {
        int nVersion;
        uint256 hashPrevBlock;
        uint256 hashMerkleRoot;
        uint nTime;
        uint nBits;
        uint nNonce;
    } data;

    data.nVersion       = pblock->nVersion;
    data.hashPrevBlock  = pblock->hashPrevBlock;
    data.hashMerkleRoot = pblock->hashMerkleRoot;
    data.nTime          = pblock->nTime;
    data.nBits          = pblock->nBits;
    data.nNonce         = pblock->nNonce;

    for(i = 0; i < 20; i++)
      pdata[i] = ((uint *) &data)[i];
}


bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey) {
    uint256 hashBlock = pblock->GetHash();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
    int nBlockHeight = pblock->GetBlockHeight();

    if(!pblock->IsProofOfWork())
      return(error("CheckWork() : %s height %d is not a proof-of-work block",
        hashBlock.GetHex().c_str(), nBlockHeight));

    uint256 hashProof = pblock->GetHashPoW();

    if(hashProof > hashTarget)
      return(error("CheckWork() : block %s height %d proof-of-work not meeting target",
        hashBlock.GetHex().c_str(), nBlockHeight));

    printf("CheckWork() : new proof-of-work block of height %d found!\n"
      "  hash:      %s\n  proofhash: %s\n  target:    %s\n",
      nBlockHeight, hashBlock.GetHex().c_str(), hashProof.GetHex().c_str(),
      hashTarget.GetHex().c_str());
    pblock->print();
    printf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != hashBestChain)
            return error("CheckWork() : generated block is stale");

        // Remove key from key pool
        reservekey.KeepKey();

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[hashBlock] = 0;
        }

        // Process this block the same as if we had received it from another node
        if (!ProcessBlock(NULL, pblock))
            return error("CheckWork() : ProcessBlock, block not accepted");
    }

    return true;
}

bool CheckStake(CBlock* pblock, CWallet& wallet) {
    uint256 hashBlock = pblock->GetHash();
    uint256 hashTarget = 0;
    int nBlockHeight = pblock->GetBlockHeight();
    bool fCritical = true;

    if(!pblock->IsProofOfStake())
      return(error("CheckStake() : %s is not a proof-of-stake block",
        hashBlock.GetHex().c_str()));

    uint256 hashProof;

    /* Verify hash target and coin stake signature */
    if(!CheckProofOfStake(pblock->vtx[1], pblock->nBits, hashProof, hashTarget, fCritical, true))
      return(error("CheckStake() : proof-of-stake check failed"));

    printf("CheckStake() : new proof-of-stake block of height %d found!\n"
      "  hash:      %s\n  proofhash: %s\n  target:    %s\n",
      nBlockHeight, hashBlock.GetHex().c_str(), hashProof.GetHex().c_str(),
      hashTarget.GetHex().c_str());
    pblock->print();
    printf("out %s\n", FormatMoney(pblock->vtx[1].GetValueOut()).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if(pblock->hashPrevBlock != hashBestChain)
          return(error("CheckStake() : generated block is stale"));

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[hashBlock] = 0;
        }

        // Process this block the same as if we had received it from another node
        if(!ProcessBlock(NULL, pblock))
          return(error("CheckStake() : ProcessBlock, block not accepted"));
    }

    return true;
}

void StakeMiner(CWallet *pwallet) {
    int64 nStakeReward = 0;

    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    // Make this thread recognisable as a stake mining thread
    RenameThread("trz-stakeminer");

    // Each thread has its own counter
    unsigned int nExtraNonce = 0;

    while(fStakeGen) {

        if(fShutdown) return;

        while (pwallet->IsLocked())
        {
            strMintWarning = strMintMessage;
            Sleep(1000);
            if (fShutdown)
                return;
        }

        while (vNodes.empty() || IsInitialBlockDownload())
        {
            Sleep(1000);
            if (fShutdown)
                return;
        }

        strMintWarning = "";

        /* Create a new block and receive a stake reward expected */
        CBlockIndex* pindexPrev = pindexBest;
        CBlock *pblock = CreateNewBlock(pwallet, true, &nStakeReward);
        if(!pblock) return;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        /* Try to sign the block with the stake reward obtained previously */ 
        if(pblock->SignBlock(*pwallet, nStakeReward)) {
            strMintWarning = _("Stake generation: new block found!");
            SetThreadPriority(THREAD_PRIORITY_NORMAL);
            CheckStake(pblock, *pwallet);
            SetThreadPriority(THREAD_PRIORITY_LOWEST);
        }

        delete(pblock);

        Sleep(nMinerSleep);

    }
}

