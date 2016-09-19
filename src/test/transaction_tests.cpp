#include <map>
#include <string>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/test/unit_test.hpp>

#include "json/json_spirit_writer_template.h"

#include "wallet.h"

using namespace std;
using namespace json_spirit;

// In script_tests.cpp
extern Array read_json(const std::string& filename);
extern bool ParseScript(const std::string &s, CScript &r);

uint ParseScriptFlags(string strFlags){
    uint flags = 0;
    vector<string> words;

    boost::algorithm::split(words, strFlags, boost::algorithm::is_any_of(","));

    static map<string, uint> mapFlagNames;
    if(mapFlagNames.size() == 0) {
        mapFlagNames["NONE"] = SCRIPT_VERIFY_NONE;
        mapFlagNames["P2SH"] = SCRIPT_VERIFY_P2SH;
        mapFlagNames["STRICTENC"] = SCRIPT_VERIFY_STRICTENC;
        mapFlagNames["LOCKTIME"] = SCRIPT_VERIFY_LOCKTIME;
    }

    BOOST_FOREACH(string word, words) {
        if(!mapFlagNames.count(word))
          BOOST_ERROR("Bad test: unknown verification flag '" << word << "'");
        flags |= mapFlagNames[word];
    }

    return(flags);
}

BOOST_AUTO_TEST_SUITE(transaction_tests)

BOOST_AUTO_TEST_CASE(tx_valid)
{
    // Read tests from test/data/tx_valid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2], ...],"],
    // serialised transaction, verbose verification flags
    // ... where all scripts are stringified scripts.
    Array tests = read_json("tx_valid.json");

    BOOST_FOREACH(Value& tv, tests)
    {
        Array test = tv.get_array();
        string strTest = write_string(tv, false);
        if (test[0].type() == array_type)
        {
            if((test.size() != 3) || (test[1].type() != str_type) || (test[2].type() != str_type)) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            map<COutPoint, CScript> mapprevOutScriptPubKeys;
            Array inputs = test[0].get_array();
            bool fValid = true;
            BOOST_FOREACH(Value& input, inputs)
            {
                if (input.type() != array_type)
                {
                    fValid = false;
                    break;
                }
                Array vinput = input.get_array();
                if (vinput.size() != 3)
                {
                    fValid = false;
                    break;
                }

                CScript scriptPubKey = CScript();
                std::string scriptPubKeyString = vinput[2].get_str();
                if(!ParseScript(scriptPubKeyString, scriptPubKey))
                  BOOST_ERROR("scriptPubKey parse error: " << scriptPubKeyString);
                mapprevOutScriptPubKeys[COutPoint(uint256(vinput[0].get_str()),
                  vinput[1].get_int())] = scriptPubKey;
            }
            if (!fValid)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            string transaction = test[1].get_str();
            CDataStream stream(ParseHex(transaction), SER_NETWORK, PROTOCOL_VERSION);
            CTransaction tx;
            stream >> tx;

                BOOST_CHECK_MESSAGE(tx.CheckTransaction(), strTest);

            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout))
                {
                    BOOST_ERROR("Bad test: " << strTest);
                    break;
                }

                uint flags = ParseScriptFlags(test[2].get_str());
                BOOST_CHECK_MESSAGE(VerifyScript(tx.vin[i].scriptSig,
                  mapprevOutScriptPubKeys[tx.vin[i].prevout], tx, i, flags, 0), strTest);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(tx_invalid)
{
    // Read tests from test/data/tx_invalid.json
    // Format is an array of arrays
    // Inner arrays are either [ "comment" ]
    // or [[[prevout hash, prevout index, prevout scriptPubKey], [input 2], ...],"], serializedTransaction, enforceP2SH
    // ... where all scripts are stringified scripts.
    Array tests = read_json("tx_invalid.json");

    BOOST_FOREACH(Value& tv, tests)
    {
        Array test = tv.get_array();
        string strTest = write_string(tv, false);
        if (test[0].type() == array_type)
        {
            if((test.size() != 3) || (test[1].type() != str_type) || (test[2].type() != str_type)) {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            map<COutPoint, CScript> mapprevOutScriptPubKeys;
            Array inputs = test[0].get_array();
            bool fValid = true;
            BOOST_FOREACH(Value& input, inputs)
            {
                if (input.type() != array_type)
                {
                    fValid = false;
                    break;
                }
                Array vinput = input.get_array();
                if (vinput.size() != 3)
                {
                    fValid = false;
                    break;
                }

                CScript scriptPubKey = CScript();
                std::string scriptPubKeyString = vinput[2].get_str();
                if(!ParseScript(scriptPubKeyString, scriptPubKey))
                  BOOST_ERROR("scriptPubKey parse error: " << scriptPubKeyString);
                mapprevOutScriptPubKeys[COutPoint(uint256(vinput[0].get_str()),
                  vinput[1].get_int())] = scriptPubKey;
            }
            if (!fValid)
            {
                BOOST_ERROR("Bad test: " << strTest);
                continue;
            }

            string transaction = test[1].get_str();
            CDataStream stream(ParseHex(transaction), SER_NETWORK, PROTOCOL_VERSION);
            CTransaction tx;
            stream >> tx;

            fValid = tx.CheckTransaction();

            for (unsigned int i = 0; i < tx.vin.size() && fValid; i++)
            {
                if (!mapprevOutScriptPubKeys.count(tx.vin[i].prevout))
                {
                    BOOST_ERROR("Bad test: " << strTest);
                    break;
                }

                uint flags = ParseScriptFlags(test[2].get_str());
                fValid = VerifyScript(tx.vin[i].scriptSig,
                  mapprevOutScriptPubKeys[tx.vin[i].prevout], tx, i, flags, 0);
            }

            BOOST_CHECK_MESSAGE(!fValid, strTest);
        }
    }
}

BOOST_AUTO_TEST_CASE(basic_transaction_tests) {

    /* Random real transaction (coin base of block #1000):
     * 2a1f81d1ba3dd04aae07591d930e2f1bca689ca627031dbc3bd75924a008e761 */
    uchar ch[] = {
      0x02, 0x00, 0x00, 0x00, 0xbe, 0x56, 0xf9, 0x51, 0x01, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0xff, 0xff, 0xff, 0xff, 0x0d, 0x02, 0xe8, 0x03, 0x02,
      0x94, 0x00, 0x06, 0x2f, 0x50, 0x32, 0x53, 0x48, 0x2f, 0xff,
      0xff, 0xff, 0xff, 0x01, 0x90, 0xd0, 0x03, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x23, 0x21, 0x02, 0xbf, 0x1c, 0xe3, 0x94, 0x4f,
      0x0f, 0xe5, 0xd1, 0x56, 0x5f, 0xe8, 0x43, 0xd8, 0x46, 0x57,
      0xcb, 0x5f, 0x95, 0x2d, 0xc6, 0xf9, 0x3f, 0x72, 0x3a, 0xe5,
      0xce, 0xeb, 0x5c, 0x88, 0x95, 0x8f, 0x3e, 0xac, 0x00, 0x00,
      0x00, 0x00, 0x00 };
    vector<unsigned char> vch(ch, ch + sizeof(ch));
    CDataStream stream(vch, SER_DISK, CLIENT_VERSION);
    CTransaction tx;
    stream >> tx;
    BOOST_CHECK_MESSAGE(tx.CheckTransaction(), "Simple deserialized transaction should be valid.");

    // Check that duplicate txins fail
    tx.vin.push_back(tx.vin[0]);
    BOOST_CHECK_MESSAGE(!tx.CheckTransaction(), "Transaction with duplicate txins should be invalid.");
}

//
// Helper: create two dummy transactions, each with
// two outputs.  The first has 11 and 50 CENT outputs
// paid to a TX_PUBKEY, the second 21 and 22 CENT outputs
// paid to a TX_PUBKEYHASH.
//
static std::vector<CTransaction> SetupDummyInputs(CBasicKeyStore &keystoreRet, CCoinsView &coinsRet) {
    std::vector<CTransaction> dummyTransactions;
    dummyTransactions.resize(2);

    // Add some keys to the keystore:
    CKey key[4];
    for (int i = 0; i < 4; i++)
    {
        key[i].MakeNewKey(i % 2);
        keystoreRet.AddKey(key[i]);
    }

    // Create some dummy input transactions
    dummyTransactions[0].vout.resize(2);
    dummyTransactions[0].vout[0].nValue = 11*CENT;
    dummyTransactions[0].vout[0].scriptPubKey << key[0].GetPubKey() << OP_CHECKSIG;
    dummyTransactions[0].vout[1].nValue = 50*CENT;
    dummyTransactions[0].vout[1].scriptPubKey << key[1].GetPubKey() << OP_CHECKSIG;
    coinsRet.SetCoins(dummyTransactions[0].GetHash(), CCoins(dummyTransactions[0], 0, -1));

    dummyTransactions[1].vout.resize(2);
    dummyTransactions[1].vout[0].nValue = 21*CENT;
    dummyTransactions[1].vout[0].scriptPubKey.SetDestination(key[2].GetPubKey().GetID());
    dummyTransactions[1].vout[1].nValue = 22*CENT;
    dummyTransactions[1].vout[1].scriptPubKey.SetDestination(key[3].GetPubKey().GetID());
    coinsRet.SetCoins(dummyTransactions[1].GetHash(), CCoins(dummyTransactions[1], 0, -1));

    return dummyTransactions;
}

BOOST_AUTO_TEST_CASE(test_Get)
{
    CBasicKeyStore keystore;
    CCoinsView coinsDummy;
    CCoinsViewCache coins(coinsDummy);
    std::vector<CTransaction> dummyTransactions = SetupDummyInputs(keystore, coins);

    CTransaction t1;
    t1.vin.resize(3);
    t1.vin[0].prevout.hash = dummyTransactions[0].GetHash();
    t1.vin[0].prevout.n = 1;
    t1.vin[0].scriptSig << std::vector<unsigned char>(65, 0);
    t1.vin[1].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[1].prevout.n = 0;
    t1.vin[1].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vin[2].prevout.hash = dummyTransactions[1].GetHash();
    t1.vin[2].prevout.n = 1;
    t1.vin[2].scriptSig << std::vector<unsigned char>(65, 0) << std::vector<unsigned char>(33, 4);
    t1.vout.resize(2);
    t1.vout[0].nValue = 90*CENT;
    t1.vout[0].scriptPubKey << OP_1;

    BOOST_CHECK(t1.AreInputsStandard(coins));
    BOOST_CHECK_EQUAL(t1.GetValueIn(coins), (50 + 21 + 22) * CENT);

    // Adding extra junk to the scriptSig should make it non-standard:
    t1.vin[0].scriptSig << OP_11;
    BOOST_CHECK(!t1.AreInputsStandard(coins));

    // ... as should not having enough:
    t1.vin[0].scriptSig = CScript();
    BOOST_CHECK(!t1.AreInputsStandard(coins));
}

BOOST_AUTO_TEST_SUITE_END()
