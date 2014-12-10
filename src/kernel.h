// Copyright (c) 2012-2013 The PPCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KERNEL_H
#define KERNEL_H

#include "main.h"

/* Time to elapse before a new stake modifier is computed */
extern uint nModifierIntervalOne;
extern uint nModifierIntervalTwo;
extern uint nModifierIntervalThree;

/* Stake modifier cache size limit */
static const uint MODIFIER_CACHE_LIMIT = 16384;

// MODIFIER_INTERVAL_RATIO:
// ratio of group interval length between the last group and the first group
static const int MODIFIER_INTERVAL_RATIO = 3;

/* Selects the appropriate minimal stake age */
uint GetStakeMinAge(uint nStakeTime);

// Compute the hash modifier for proof-of-stake
bool ComputeNextStakeModifier(const CBlockIndex* pindexPrev, uint64& nStakeModifier, bool& fGeneratedStakeModifier);

// Check whether stake kernel meets hash target
// Sets hashProofOfStake and targetProofOfStake on success return
bool CheckStakeKernelHash(uint nBits, const CBlock& blockFrom, uint nTxPrevOffset,
  const CTransaction& txPrev, const COutPoint& prevout, uint nTimeTx,
  uint256& hashProofOfStake, uint256& targetProofOfStake, bool& fCritical,
  bool fMiner = false, bool fPrintProofOfStake = false);

/* The stake modifier used to hash for a stake kernel is chosen as the stake
 * modifier about a selection interval later than the coin generating the kernel */
bool GetKernelStakeModifier(uint256 hashBlockFrom, uint64& nStakeModifier,
  int64& nStakeModifierTime, int& nStakeModifierHeight, bool fPrintProofOfStake = false);

// Check kernel hash target and coinstake signature
// Sets hashProofOfStake and targetProofOfStake on success return
bool CheckProofOfStake(const CTransaction& tx, unsigned int nBits, uint256& hashProofOfStake, uint256& targetProofOfStake, bool& fCritical, bool fMiner=false);

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64 nTimeBlock, int64 nTimeTx);

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex);

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum);

// Get time weight using supplied timestamps
int64 GetWeight(int64 nIntervalBeginning, int64 nIntervalEnd);

#endif /* KERNEL_H */
