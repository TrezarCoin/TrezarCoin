// Copyright (c) 2012-2013 The PPCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp>

#include "kernel.h"
#include "db.h"

using namespace std;

/* Cache of stake modifiers */
static std::map<uint, uint64> mapModifiers;

typedef std::map<int, unsigned int> MapModifierCheckpoints;

// Hard checkpoints of stake modifiers to ensure they are deterministic
static std::map<int, unsigned int> mapStakeModifierCheckpoints =
    boost::assign::map_list_of
        ( 0, 0xFD11F4E7 )
    ;

// Hard checkpoints of stake modifiers to ensure they are deterministic (testNet)
static std::map<int, unsigned int> mapStakeModifierCheckpointsTestNet =
    boost::assign::map_list_of
        ( 0, 0x0e00670bu )
    ;


/* Calculates time weight */
int64 GetWeight(int64 nIntervalBegin, int64 nIntervalEnd) {
    int64 nTimeWeight = 0;

    if(true) {
        /* New rule: nStakeMaxAge is the limit */
        nTimeWeight = nIntervalEnd - nIntervalBegin - nStakeMinAge;
        if(nTimeWeight > (int64)nStakeMaxAge)
          nTimeWeight = (int64)nStakeMaxAge;
    } else {
        /* Old rule: (nStakeMaxAge - nStakeMinAge) is the limit */
        nTimeWeight = nIntervalEnd - nIntervalBegin;
        if(nTimeWeight > (int64)nStakeMaxAge)
          nTimeWeight = (int64)nStakeMaxAge;
        nTimeWeight -= nStakeMinAge;
    }

    return(nTimeWeight);
}

// Get the last stake modifier and its generation time from a given block
static bool GetLastStakeModifier(const CBlockIndex* pindex, uint64& nStakeModifier, int64& nModifierTime)
{
    if (!pindex)
        return error("GetLastStakeModifier: null pindex");
    while (pindex && pindex->pprev && !pindex->GeneratedStakeModifier())
        pindex = pindex->pprev;
    if (!pindex->GeneratedStakeModifier())
        return error("GetLastStakeModifier: no generation at genesis block");
    nStakeModifier = pindex->nStakeModifier;
    nModifierTime = pindex->GetBlockTime();
    return true;
}

// Get selection interval section (in seconds)
static int64 GetStakeModifierSelectionIntervalSection(int nSection, uint nActualModifierInterval)
{
    assert (nSection >= 0 && nSection < 64);
    return (nActualModifierInterval * 63 / (63 + ((63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1))));
}

// Get stake modifier selection interval (in seconds)
static int64 GetStakeModifierSelectionInterval(uint nActualModifierInterval)
{
    int64 nSelectionInterval = 0;
    for (int nSection=0; nSection<64; nSection++)
        nSelectionInterval += GetStakeModifierSelectionIntervalSection(nSection, nActualModifierInterval);
    return nSelectionInterval;
}

// select a block from the candidate blocks in vSortedByTimestamp, excluding
// already selected blocks in vSelectedBlocks, and with timestamp up to
// nSelectionIntervalStop.
static bool SelectBlockFromCandidates(vector<pair<int64, uint256> >& vSortedByTimestamp, map<uint256, const CBlockIndex*>& mapSelectedBlocks,
    int64 nSelectionIntervalStop, uint64 nStakeModifierPrev, const CBlockIndex** pindexSelected)
{
    bool fSelected = false;
    uint256 hashBest = 0;
    *pindexSelected = (const CBlockIndex*) 0;
    BOOST_FOREACH(const PAIRTYPE(int64, uint256)& item, vSortedByTimestamp)
    {
        if (!mapBlockIndex.count(item.second))
            return error("SelectBlockFromCandidates: failed to find block index for candidate block %s", item.second.ToString().c_str());
        const CBlockIndex* pindex = mapBlockIndex[item.second];
        if (fSelected && pindex->GetBlockTime() > nSelectionIntervalStop)
            break;
        if (mapSelectedBlocks.count(pindex->GetBlockHash()) > 0)
            continue;
        // compute the selection hash by hashing its proof-hash and the
        // previous proof-of-stake modifier
        uint256 hashProof = pindex->IsProofOfStake()? pindex->hashProofOfStake : pindex->GetBlockHash();
        CDataStream ss(SER_GETHASH, 0);
        ss << hashProof << nStakeModifierPrev;
        uint256 hashSelection = Hash(ss.begin(), ss.end());
        // the selection hash is divided by 2**32 so that proof-of-stake block
        // is always favored over proof-of-work block. this is to preserve
        // the energy efficiency property
        if (pindex->IsProofOfStake())
            hashSelection >>= 32;
        if (fSelected && hashSelection < hashBest)
        {
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*) pindex;
        }
        else if (!fSelected)
        {
            fSelected = true;
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*) pindex;
        }
    }
    if (fDebug && GetBoolArg("-printstakemodifier"))
        printf("SelectBlockFromCandidates: selection hash=%s\n", hashBest.ToString().c_str());
    return fSelected;
}

// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
// Stake modifier consists of bits each of which is contributed from a
// selected block of a given block group in the past.
// The selection of a block is based on a hash of the block's proof-hash and
// the previous stake modifier.
// Stake modifier is recomputed at a fixed time interval instead of every 
// block. This is to make it difficult for an attacker to gain control of
// additional bits in the stake modifier, even after generating a chain of
// blocks.
bool ComputeNextStakeModifier(const CBlockIndex* pindexPrev, uint64& nStakeModifier, bool& fGeneratedStakeModifier)
{
    nStakeModifier = 0;
    fGeneratedStakeModifier = false;
    if (!pindexPrev)
    {
        fGeneratedStakeModifier = true;
        return true;  // genesis block's modifier is 0
    }
    // First find current stake modifier and its generation block time
    // if it's not old enough, return the same stake modifier
    int64 nModifierTime = 0;
    if (!GetLastStakeModifier(pindexPrev, nStakeModifier, nModifierTime))
        return error("ComputeNextStakeModifier: unable to get last modifier");
    if (fDebug)
    {
        printf("ComputeNextStakeModifier: prev modifier=0x%016" PRI64x" time=%s\n",
          nStakeModifier, DateTimeStrFormat(nModifierTime).c_str());
    }

    uint nActualModifierInterval = nModifierIntervalThree;

    if((nModifierTime / nActualModifierInterval) >= (pindexPrev->GetBlockTime() / nActualModifierInterval))
      return(true);

    // Sort candidate blocks by timestamp
    vector<pair<int64, uint256> > vSortedByTimestamp;
    vSortedByTimestamp.reserve(64 * nActualModifierInterval / nBaseTargetSpacing);
    int64 nSelectionInterval = GetStakeModifierSelectionInterval(nActualModifierInterval);
    int64 nSelectionIntervalStart =
      (pindexPrev->GetBlockTime() / nActualModifierInterval) * nActualModifierInterval - nSelectionInterval;
    const CBlockIndex* pindex = pindexPrev;
    while (pindex && pindex->GetBlockTime() >= nSelectionIntervalStart)
    {
        vSortedByTimestamp.push_back(make_pair(pindex->GetBlockTime(), pindex->GetBlockHash()));
        pindex = pindex->pprev;
    }
    int nHeightFirstCandidate = pindex ? (pindex->nHeight + 1) : 0;
    reverse(vSortedByTimestamp.begin(), vSortedByTimestamp.end());
    sort(vSortedByTimestamp.begin(), vSortedByTimestamp.end());

    // Select 64 blocks from candidate blocks to generate stake modifier
    uint64 nStakeModifierNew = 0;
    int64 nSelectionIntervalStop = nSelectionIntervalStart;
    map<uint256, const CBlockIndex*> mapSelectedBlocks;
    for (int nRound=0; nRound<min(64, (int)vSortedByTimestamp.size()); nRound++)
    {
        // add an interval section to the current selection round
        nSelectionIntervalStop += GetStakeModifierSelectionIntervalSection(nRound, nActualModifierInterval);
        // select a block from the candidates of current round
        if (!SelectBlockFromCandidates(vSortedByTimestamp, mapSelectedBlocks, nSelectionIntervalStop, nStakeModifier, &pindex))
            return error("ComputeNextStakeModifier: unable to select block at round %d", nRound);
        // write the entropy bit of the selected block
        nStakeModifierNew |= (((uint64)pindex->GetStakeEntropyBit()) << nRound);
        // add the selected block from candidates to selected list
        mapSelectedBlocks.insert(make_pair(pindex->GetBlockHash(), pindex));
        if (fDebug && GetBoolArg("-printstakemodifier"))
            printf("ComputeNextStakeModifier: selected round %d stop=%s height=%d bit=%d\n", nRound, DateTimeStrFormat(nSelectionIntervalStop).c_str(), pindex->nHeight, pindex->GetStakeEntropyBit());
    }

    // Print selection map for visualization of the selected blocks
    if (fDebug && GetBoolArg("-printstakemodifier"))
    {
        string strSelectionMap = "";
        // '-' indicates proof-of-work blocks not selected
        strSelectionMap.insert(0, pindexPrev->nHeight - nHeightFirstCandidate + 1, '-');
        pindex = pindexPrev;
        while (pindex && pindex->nHeight >= nHeightFirstCandidate)
        {
            // '=' indicates proof-of-stake blocks not selected
            if (pindex->IsProofOfStake())
                strSelectionMap.replace(pindex->nHeight - nHeightFirstCandidate, 1, "=");
            pindex = pindex->pprev;
        }
        BOOST_FOREACH(const PAIRTYPE(uint256, const CBlockIndex*)& item, mapSelectedBlocks)
        {
            // 'S' indicates selected proof-of-stake blocks
            // 'W' indicates selected proof-of-work blocks
            strSelectionMap.replace(item.second->nHeight - nHeightFirstCandidate, 1, item.second->IsProofOfStake()? "S" : "W");
        }
        printf("ComputeNextStakeModifier: selection height [%d, %d] map %s\n", nHeightFirstCandidate, pindexPrev->nHeight, strSelectionMap.c_str());
    }
    if (fDebug)
    {
        printf("ComputeNextStakeModifier: new modifier=0x%016" PRI64x " time=%s\n",
          nStakeModifierNew, DateTimeStrFormat(pindexPrev->GetBlockTime()).c_str());
    }

    nStakeModifier = nStakeModifierNew;
    fGeneratedStakeModifier = true;
    return true;
}

// The stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
bool GetKernelStakeModifier(uint256 hashBlockFrom, uint64& nStakeModifier,
  int64& nStakeModifierTime, int& nStakeModifierHeight, bool fPrintProofOfStake) {
    nStakeModifier = 0;
    if (!mapBlockIndex.count(hashBlockFrom))
        return error("GetKernelStakeModifier() : block not indexed");
    const CBlockIndex* pindexFrom = mapBlockIndex[hashBlockFrom];
    nStakeModifierTime   = pindexFrom->GetBlockTime();
    nStakeModifierHeight = pindexFrom->nHeight;

    uint nActualModifierInterval = nModifierIntervalThree;

    int64 nStakeModifierSelectionInterval = GetStakeModifierSelectionInterval(nActualModifierInterval);
    const CBlockIndex* pindex = pindexFrom;
    while(nStakeModifierTime < (pindexFrom->GetBlockTime() + nStakeModifierSelectionInterval)) {
        if(!pindex->pnext) {
            if(fPrintProofOfStake ||
              ((pindex->GetBlockTime() + nStakeMinAge - nStakeModifierSelectionInterval) > GetAdjustedTime())) {
                  return(error("GetKernelStakeModifier() : failed attempt at the best block %s (height %d) from block %s (height %d)",
                    pindex->GetBlockHash().ToString().c_str(), pindex->nHeight,
                    hashBlockFrom.ToString().c_str(), nStakeModifierHeight));
            } else return(false);
        }
        pindex = pindex->pnext;
        if(pindex->GeneratedStakeModifier()) {
            nStakeModifierTime   = pindex->GetBlockTime();
            nStakeModifierHeight = pindex->nHeight;
        }
    }
    nStakeModifier = pindex->nStakeModifier;
    return(true);
}

// ppcoin kernel protocol
// coinstake must meet hash target according to the protocol:
// kernel (input 0) must meet the formula
//     hash(nStakeModifier + txPrev.block.nTime + txPrev.offset + txPrev.nTime + txPrev.vout.n + nTime) < bnTarget * nCoinDayWeight
// this ensures that the chance of getting a coinstake is proportional to the
// amount of coin age one owns.
// The reason this hash is chosen is the following:
//   nStakeModifier: scrambles computation to make it very difficult to precompute
//                  future proof-of-stake at the time of the coin's confirmation
//   txPrev.block.nTime: prevent nodes from guessing a good timestamp to
//                       generate transaction for future advantage
//   txPrev.offset: offset of txPrev inside block, to reduce the chance of 
//                  nodes generating coinstake at the same time
//   txPrev.nTime: reduce the chance of nodes generating coinstake at the same
//                 time
//   txPrev.vout.n: output number of txPrev, to reduce the chance of nodes
//                  generating coinstake at the same time
//   block/tx hash should not be used here as they can be generated in vast
//   quantities so as to generate blocks faster, degrading the system back into
//   a proof-of-work situation.
//
bool CheckStakeKernelHash(uint nBits, const CBlock& blockFrom, uint nTxPrevOffset,
  const CTransaction& txPrev, const COutPoint& prevout, uint nTimeTx,
  uint256& hashProofOfStake, uint256& targetProofOfStake, bool& fCritical,
  bool fMiner, bool fPrintProofOfStake) {

    if(nTimeTx < txPrev.nTime)
      return(error("CheckStakeKernelHash() : time stamp violation"));

    uint nTimeBlockFrom = blockFrom.GetBlockTime();
    if((nTimeBlockFrom + nStakeMinAge) > nTimeTx)
      return(error("CheckStakeKernelHash() : min. stake age violation"));

    CBigNum bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    int64 nValueIn = txPrev.vout[prevout.n].nValue;

    uint256 hashBlockFrom = blockFrom.GetHash();

    CBigNum bnCoinDayWeight = CBigNum(nValueIn) * GetWeight((int64)txPrev.nTime, (int64)nTimeTx) / COIN / (24 * 60 * 60);
    targetProofOfStake = (bnCoinDayWeight * bnTargetPerCoinDay).getuint256();

    // Calculate hash
    CDataStream ss(SER_GETHASH, 0);
    uint64 nStakeModifier;
    int64 nStakeModifierTime = 0;
    int nStakeModifierHeight = 0;

    uint nSize = (uint)mapModifiers.size();
    if(nSize >= MODIFIER_CACHE_LIMIT) {
        printf("CheckStakeKernelHash() : cleared %u stake modifier cache records\n", nSize);
        mapModifiers.clear();
    }

    /* Stake modifiers for PoS mining are calculated repeatedly
     * and can be cached to speed up the whole process */
    if(mapModifiers.count(nTimeBlockFrom)) {
        nStakeModifier = mapModifiers[nTimeBlockFrom];
        nModifierCacheHits++;
    } else {
        if(!GetKernelStakeModifier(blockFrom.GetHash(), nStakeModifier,
          nStakeModifierTime, nStakeModifierHeight, fPrintProofOfStake)) {
            fCritical = false;
            return(false);
        }
        mapModifiers.insert(make_pair(nTimeBlockFrom, nStakeModifier));
        nModifierCacheMisses++;
    }

    ss << nStakeModifier << nTimeBlockFrom << nTxPrevOffset << txPrev.nTime << prevout.n << nTimeTx;
    hashProofOfStake = Hash(ss.begin(), ss.end());

    if (fPrintProofOfStake)
    {
        printf("CheckStakeKernelHash() : using modifier 0x%016" PRI64x \
          " at height=%d time=%s of block height=%d time=%s\n",
          nStakeModifier, nStakeModifierHeight,
          DateTimeStrFormat(nStakeModifierTime).c_str(),
          mapBlockIndex[hashBlockFrom]->nHeight,
          DateTimeStrFormat(blockFrom.GetBlockTime()).c_str());
        printf("CheckStakeKernelHash() : check modifier=0x%016" PRI64x \
          " nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u" \
          " nTimeTx=%u hashProof=%s\n",
          nStakeModifier, nTimeBlockFrom, nTxPrevOffset, txPrev.nTime, prevout.n,
          nTimeTx, hashProofOfStake.ToString().c_str());
    }

    // Now check if proof-of-stake hash meets target protocol
    if(CBigNum(hashProofOfStake) > bnCoinDayWeight * bnTargetPerCoinDay) {
        /* Stake miner produces floods of these */
        if(!fMiner) return(error("CheckStakeKernelHash() : proof-of-stake not meeting target"));
        return(false);
    }

    if (fDebug && !fPrintProofOfStake)
    {
        printf("CheckStakeKernelHash() : using modifier 0x%016" PRI64x \
          " at height=%d time=%s of block height=%d time=%s\n",
          nStakeModifier, nStakeModifierHeight,
          DateTimeStrFormat(nStakeModifierTime).c_str(),
          mapBlockIndex[hashBlockFrom]->nHeight,
          DateTimeStrFormat(blockFrom.GetBlockTime()).c_str());
        printf("CheckStakeKernelHash() : pass modifier=0x%016" PRI64x \
          " nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u" \
          " nTimeTx=%u hashProof=%s\n",
          nStakeModifier, nTimeBlockFrom, nTxPrevOffset, txPrev.nTime, prevout.n,
          nTimeTx, hashProofOfStake.ToString().c_str());
    }

    return(true);
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(const CTransaction& tx, unsigned int nBits, uint256& hashProofOfStake,
  uint256& targetProofOfStake, bool& fCritical, bool fMiner) {

    if(!tx.IsCoinStake())
      return(error("CheckProofOfStake() : %s not a coin stake", tx.GetHash().ToString().c_str()));

    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx.vin[0];
    unsigned nTxPos;

    CTransaction txPrev;
    CCoins coins;
    CCoinsViewCache &view = *pcoinsTip;

   /* May happen if the previous transaction isn't in the main chain yet */
    if(!view.GetCoinsReadOnly(txin.prevout.hash, coins)) {
        fCritical = false;
        if(fDebug) return(error("CheckProofOfStake() : cannot find a previous transaction output"));
        return(false);
    }

    CBlockIndex* pindex = FindBlockByHeight(coins.nHeight);

    // Read block and scan it to find txPrev
    CBlock block;
    if (block.ReadFromDisk(pindex)) {
        nTxPos = GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION) - (2 * GetSizeOfCompactSize(0)) + GetSizeOfCompactSize(block.vtx.size());
        BOOST_FOREACH(const CTransaction &tx, block.vtx) {
            if (tx.GetHash() == txin.prevout.hash) {
                txPrev = tx;
                break;
            }
            nTxPos += tx.GetSerializeSize(SER_DISK, CLIENT_VERSION);
        }
    }
    else {
       /* May happen if the block isn't in the main chain yet */
        fCritical = false;
        if(fDebug) return(error("CheckProofOfStake() : cannot load a block requested"));
        return(false);
    }

    const CTxOut& txout = txPrev.vout[txin.prevout.n];

    // Check transaction consistency
    if(txin.prevout.n >= txPrev.vout.size())
      return(error("CheckProofOfStake() : coin stake %s with an invalid input",
        tx.GetHash().ToString().c_str()));

    // Verify script
    if(!VerifyScript(txin.scriptSig, txout.scriptPubKey, tx, 0, SCRIPT_VERIFY_P2SH, 0))
      return(error("CheckProofOfStake() : coin stake %s script verification failed",
        tx.GetHash().ToString().c_str()));

    if(!CheckStakeKernelHash(nBits, block, nTxPos, txPrev, txin.prevout, tx.nTime,
      hashProofOfStake, targetProofOfStake, fCritical, fMiner, fDebug)) {
        if(fDebug) return(error("CheckProofOfStake() : kernel check failed on coin stake %s, proof=%s",
          tx.GetHash().ToString().c_str(), hashProofOfStake.ToString().c_str()));
        return(false);
    }

    return(true);
}

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64 nTimeBlock, int64 nTimeTx)
{
    // v0.3 protocol
    return (nTimeBlock == nTimeTx);
}

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex)
{
    // Hash previous checksum with flags, hashProofOfStake and nStakeModifier
    CDataStream ss(SER_GETHASH, 0);
    if (pindex->pprev)
        ss << pindex->pprev->nStakeModifierChecksum;
    ss << pindex->nFlags << pindex->hashProofOfStake << pindex->nStakeModifier;
    uint256 hashChecksum = Hash(ss.begin(), ss.end());
    hashChecksum >>= (256 - 32);
    return hashChecksum.Get64();
}

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum)
{
    MapModifierCheckpoints& checkpoints = (fTestNet ? mapStakeModifierCheckpointsTestNet : mapStakeModifierCheckpoints);

    if (checkpoints.count(nHeight))
        return nStakeModifierChecksum == checkpoints[nHeight];
    return true;
}
