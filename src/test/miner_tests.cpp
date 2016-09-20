#include <boost/test/unit_test.hpp>

#include "init.h"
#include "uint256.h"
#include "wallet.h"
#include "miner.h"

BOOST_AUTO_TEST_SUITE(miner_tests)

BOOST_AUTO_TEST_CASE(CreateNewBlock_basic) {
    CBlock *pblock;
    int64 nStakeReward = 1 * COIN;

    /* Create a PoW block template */
    BOOST_CHECK(pblock = CreateNewBlock(pwalletMain, false));
    delete(pblock);

    /* Create a PoS block template */
    BOOST_CHECK(pblock = CreateNewBlock(pwalletMain, true, &nStakeReward));
    delete(pblock);
}

BOOST_AUTO_TEST_SUITE_END()
