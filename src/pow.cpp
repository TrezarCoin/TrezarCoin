// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "arith_uint256.h"
#include "chain.h"
#include "key.h"
#include "primitives/block.h"
#include "uint256.h"

#include <algorithm>

/* Locate a block meeting the range and type specified down the block index;
 * for instance, range 1 PoW means to search for the nearest PoW block including
 * the starting one, then find the previous PoW one and return its position */
const CBlockIndex *GetPrevBlockIndex(const CBlockIndex *pindex, unsigned int nRange, const bool fProofOfStake) {

    nRange++;

    while(nRange) {
        if (pindex->IsProofOfStake() == fProofOfStake)
            if (!(--nRange))
                return pindex;

        if (pindex->pprev)
            pindex = pindex->pprev;
        else
            break;
    }

    return NULL;
}


unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, bool fProofOfStake, const Consensus::Params& params)
{
    CBigNum bnNew, bnTargetLimit;
    bnTargetLimit.SetCompact(UintToArith256(params.powLimit).GetCompact());

    /* The genesis block */
    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact();

    /* The latest block of the type requested */
    const CBlockIndex *pindexPrev = GetPrevBlockIndex(pindexLast, 0, fProofOfStake);
    if(pindexPrev == NULL)
        return(bnTargetLimit.GetCompact());

    if (params.fPowNoRetargeting)
        return pindexLast->nBits;

    /* Orbitcoin Super Shield (OSS);
     * retargets every block using two averaging windows of 5 and 20 blocks,
     * 0.25 damping and further oscillation limiting */

     int64_t nIntervalShort = 5, nIntervalLong = 20, nTargetSpacing, nTargetTimespan,
          nActualTimespan, nActualTimespanShort, nActualTimespanLong, nActualTimespanAvg,
          nActualTimespanMax, nActualTimespanMin;

    if (fProofOfStake)
        nTargetSpacing = 6 * params.nBaseTargetSpacing;
    else
        nTargetSpacing = 3 * params.nBaseTargetSpacing;

    nTargetTimespan = nTargetSpacing * nIntervalLong;

    /* The short averaging window */
    const CBlockIndex *pindexShort = GetPrevBlockIndex(pindexPrev, nIntervalShort, fProofOfStake);
    if (!pindexShort)
        return(bnTargetLimit.GetCompact());
    nActualTimespanShort = (int64_t)pindexPrev->nTime - (int64_t)pindexShort->nTime;

    /* The long averaging window */
    const CBlockIndex *pindexLong = GetPrevBlockIndex(pindexShort, nIntervalLong - nIntervalShort, fProofOfStake);
    if (!pindexLong)
        return(bnTargetLimit.GetCompact());
    nActualTimespanLong = (int64_t)pindexPrev->nTime - (int64_t)pindexLong->nTime;

    /* Time warp protection */
    nActualTimespanShort = std::max(nActualTimespanShort, (nTargetSpacing * nIntervalShort / 2));
    nActualTimespanShort = std::min(nActualTimespanShort, (nTargetSpacing * nIntervalShort * 2));
    nActualTimespanLong  = std::max(nActualTimespanLong,  (nTargetSpacing * nIntervalLong  / 2));
    nActualTimespanLong  = std::min(nActualTimespanLong,  (nTargetSpacing * nIntervalLong  * 2));

    /* The average of both windows */
    nActualTimespanAvg = (nActualTimespanShort * (nIntervalLong / nIntervalShort) + nActualTimespanLong) / 2;

    /* 0.25 damping */
    nActualTimespan = nActualTimespanAvg + 3 * nTargetTimespan;
    nActualTimespan /= 4;

    /* Oscillation limiters */
    /* +5% to -10% */
    nActualTimespanMin = nTargetTimespan * 100 / 105;
    nActualTimespanMax = nTargetTimespan * 110 / 100;
    if (nActualTimespan < nActualTimespanMin)
        nActualTimespan = nActualTimespanMin;
    if (nActualTimespan > nActualTimespanMax)
        nActualTimespan = nActualTimespanMax;

    /* Retarget */
    bnNew.SetCompact(pindexPrev->nBits);
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnTargetLimit)
        bnNew = bnTargetLimit;

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return false;

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
        return false;

    return true;
}
