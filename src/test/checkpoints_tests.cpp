//
// Unit tests for block-chain checkpoints
//
#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/test/unit_test.hpp>
#include <boost/foreach.hpp>

#include "checkpoints.h"
#include "util.h"

enum Checkpoints::CPMode CheckpointsMode;

using namespace std;

BOOST_AUTO_TEST_SUITE(checkpoints_tests)

BOOST_AUTO_TEST_CASE(sanity)
{
    uint256 p600000 = uint256("0x00000025e4214dd10eb7a4d7d088935dbc5c05b18574b56574d19c839e48e8ff");
    uint256 p1000010 = uint256("0xbbddf2c25a8b26651d387f232201fcab7a9e2c543a9d12ac2302174800c1d982");
    BOOST_CHECK(Checkpoints::CheckHardened(600000, p600000));
    BOOST_CHECK(Checkpoints::CheckHardened(1000010, p1000010));

    
    // Wrong hashes at checkpoints should fail:
    BOOST_CHECK(!Checkpoints::CheckHardened(600000, p1000010));
    BOOST_CHECK(!Checkpoints::CheckHardened(1000010, p600000));

    // ... but any hash not at a checkpoint should succeed:
    BOOST_CHECK(Checkpoints::CheckHardened(600000+1, p1000010));
    BOOST_CHECK(Checkpoints::CheckHardened(1000010+1, p600000));

    BOOST_CHECK(Checkpoints::GetTotalBlocksEstimate() >= 1000010);
}    

BOOST_AUTO_TEST_SUITE_END()
