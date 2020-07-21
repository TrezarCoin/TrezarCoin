// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "clientversion.h"
#include "init.h"
#include "main.h"
#include "net.h"
#include "netbase.h"
#include "rpc/server.h"
#include "timedata.h"
#include "util.h"
#include "utilstrencodings.h"
#include "checkpointsync.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif

#ifdef ENABLE_BITCORE_RPC
#include "consensus/consensus.h"
#include "txmempool.h"
#endif

#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include <boost/lexical_cast.hpp>

#include <univalue.h>

using namespace std;

/**
 * @note Do not add or change anything in the information returned by this
 * method. `getinfo` exists for backwards-compatibility only. It combines
 * information from wildly different sources in the program, which is a mess,
 * and is thus planned to be deprecated eventually.
 *
 * Based on the source of the information, new information should be added to:
 * - `getblockchaininfo`,
 * - `getnetworkinfo` or
 * - `getwalletinfo`
 *
 * Or alternatively, create a specific query method for the information.
 **/
UniValue getinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getinfo\n"
            "Returns an object containing various state info.\n"
            "\nResult:\n"
            "{\n"
            "  \"version\": xxxxx,           (numeric) the server version\n"
            "  \"protocolversion\": xxxxx,   (numeric) the protocol version\n"
            "  \"walletversion\": xxxxx,     (numeric) the wallet version\n"
            "  \"balance\": xxxxxxx,         (numeric) the total trezarcoin balance of the wallet\n"
            "  \"coldstaking_balance\": xxxxxxx, (numeric) cold staking balance of the wallet\n"
            "  \"blocks\": xxxxxx,           (numeric) the current number of blocks processed in the server\n"
            "  \"moneysupply\": xxxxxx,      (numeric) total number of coins in circulation\n"
            "  \"timeoffset\": xxxxx,        (numeric) the time offset\n"
            "  \"connections\": xxxxx,       (numeric) the number of connections\n"
            "  \"proxy\": \"host:port\",     (string, optional) the proxy used by the server\n"
            "  \"difficulty\": xxxxxx,       (numeric) the current difficulty\n"
            "  \"testnet\": true|false,      (boolean) if the server is using testnet or not\n"
            "  \"keypoololdest\": xxxxxx,    (numeric) the timestamp (seconds since Unix epoch) of the oldest pre-generated key in the key pool\n"
            "  \"keypoolsize\": xxxx,        (numeric) how many new keys are pre-generated\n"
            "  \"unlocked_until\": ttt,      (numeric) the timestamp in seconds since epoch (midnight Jan 1 1970 GMT) that the wallet is unlocked for transfers, or 0 if the wallet is locked\n"
            "  \"paytxfee\": x.xxxx,         (numeric) the transaction fee set in " + CURRENCY_UNIT + "/kB\n"
            "  \"relayfee\": x.xxxx,         (numeric) minimum relay fee for non-free transactions in " + CURRENCY_UNIT + "/kB\n"
            "  \"errors\": \"...\"           (string) any error messages\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getinfo", "")
            + HelpExampleRpc("getinfo", "")
        );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    proxyType proxy;
    GetProxy(NET_IPV4, proxy);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("version", CLIENT_VERSION));
    obj.push_back(Pair("protocolversion", PROTOCOL_VERSION));
#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.push_back(Pair("walletversion", pwalletMain->GetVersion()));
        obj.push_back(Pair("balance",       ValueFromAmount(pwalletMain->GetBalance())));
        obj.push_back(Pair("coldstaking_balance",       ValueFromAmount(pwalletMain->GetColdStakingBalance())));
        obj.push_back(Pair("newmint",       ValueFromAmount(pwalletMain->GetNewMint())));
        obj.push_back(Pair("stake",         ValueFromAmount(pwalletMain->GetStake())));
    }
#endif
    obj.push_back(Pair("blocks",        (int)chainActive.Height()));
    obj.push_back(Pair("moneysupply",   ValueFromAmount(chainActive.Tip()->nMoneySupply)));
    obj.push_back(Pair("timeoffset",    GetTimeOffset()));
    obj.push_back(Pair("connections",   (int)vNodes.size()));
    obj.push_back(Pair("proxy",         (proxy.IsValid() ? proxy.proxy.ToStringIPPort() : string())));
    UniValue diff(UniValue::VOBJ);
    diff.push_back(Pair("proof-of-work",        GetDifficulty()));
    diff.push_back(Pair("proof-of-stake",       GetDifficulty(GetLastBlockIndex(chainActive.Tip(), true))));
    obj.push_back(Pair("difficulty",    diff));
    obj.push_back(Pair("testnet",       Params().TestnetToBeDeprecatedFieldRPC()));
#ifdef ENABLE_WALLET
    if (pwalletMain) {
        obj.push_back(Pair("keypoololdest", pwalletMain->GetOldestKeyPoolTime()));
        obj.push_back(Pair("keypoolsize",   (int)pwalletMain->GetKeyPoolSize()));
    }
    if (pwalletMain && pwalletMain->IsCrypted())
        obj.push_back(Pair("unlocked_until", nWalletUnlockTime));
    obj.push_back(Pair("paytxfee",      ValueFromAmount(payTxFee.GetFeePerK())));
#endif
    obj.push_back(Pair("relayfee",      ValueFromAmount(::minRelayTxFee.GetFeePerK())));
    obj.push_back(Pair("errors",        GetWarnings("statusbar")));
    return obj;
}

#ifdef ENABLE_WALLET
class DescribeAddressVisitor : public boost::static_visitor<UniValue>
{
public:
    UniValue operator()(const CNoDestination &dest) const { return UniValue(UniValue::VOBJ); }

    UniValue operator()(const CKeyID &keyID) const {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("iscoldstaking", false));
        if (pwalletMain && pwalletMain->GetPubKey(keyID, vchPubKey)) {
            obj.push_back(Pair("pubkey", HexStr(vchPubKey)));
            obj.push_back(Pair("iscompressed", vchPubKey.IsCompressed()));
        }
        return obj;
    }

    UniValue operator()(const pair<CKeyID, CKeyID> &keyID) const {
        UniValue obj(UniValue::VOBJ);
        CPubKey vchPubKey;
        obj.push_back(Pair("isscript", false));
        obj.push_back(Pair("iscoldstaking", true));
        if (pwalletMain && pwalletMain->GetPubKey(keyID.first, vchPubKey)) {
            obj.push_back(Pair("stakingpubkey", HexStr(vchPubKey)));
        }
        if(pwalletMain->GetPubKey(keyID.second, vchPubKey)) {
            obj.push_back(Pair("spendingpubkey", HexStr(vchPubKey)));
        }
        return obj;
    }

    UniValue operator()(const CScriptID &scriptID) const {
        UniValue obj(UniValue::VOBJ);
        CScript subscript;
        obj.push_back(Pair("isscript", true));
        obj.push_back(Pair("iscoldstaking", false));
        if (pwalletMain && pwalletMain->GetCScript(scriptID, subscript)) {
            std::vector<CTxDestination> addresses;
            txnouttype whichType;
            int nRequired;
            ExtractDestinations(subscript, whichType, addresses, nRequired);
            obj.push_back(Pair("script", GetTxnOutputType(whichType)));
            obj.push_back(Pair("hex", HexStr(subscript.begin(), subscript.end())));
            UniValue a(UniValue::VARR);
            BOOST_FOREACH(const CTxDestination& addr, addresses)
                a.push_back(CBitcoinAddress(addr).ToString());
            obj.push_back(Pair("addresses", a));
            if (whichType == TX_MULTISIG)
                obj.push_back(Pair("sigsrequired", nRequired));
        }
        return obj;
    }
};
#endif

UniValue validateaddress(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "validateaddress \"trezarcoinaddress\"\n"
            "\nReturn information about the given trezarcoin address.\n"
            "\nArguments:\n"
            "1. \"trezarcoinaddress\"     (string, required) The trezarcoin address to validate\n"
            "\nResult:\n"
            "{\n"
            "  \"isvalid\" : true|false,       (boolean) If the address is valid or not. If not, this is the only property returned.\n"
            "  \"address\" : \"trezarcoinaddress\", (string) The trezarcoin address validated\n"
            "  \"scriptPubKey\" : \"hex\",       (string) The hex encoded scriptPubKey generated by the address\n"
            "  \"stakingaddress\" : \"trezarcoinaddress\", (string) The staking address part of a cold staking address\n"
            "  \"spendingaddress\" : \"trezarcoinaddress\", (string) The spending address part of a cold staking address\n"
            "  \"ismine\" : true|false,        (boolean) If the address is yours or not\n"
            "  \"iswatchonly\" : true|false,   (boolean) If the address is watchonly\n"
            "  \"isscript\" : true|false,      (boolean) If the key is a script\n"
            "  \"iscoldstaking\" : true|false,        (boolean) If the address is a cold staking address or not\n"
            "  \"pubkey\" : \"publickeyhex\",    (string) The hex value of the raw public key\n"
            "  \"iscompressed\" : true|false,  (boolean) If the address is compressed\n"
            "  \"account\" : \"account\"         (string) DEPRECATED. The account associated with the address, \"\" is the default account\n"
            "  \"hdkeypath\" : \"keypath\"       (string, optional) The HD keypath if the key is HD and available\n"
            "  \"hdmasterkeyid\" : \"<hash160>\" (string, optional) The Hash160 of the HD master pubkey\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("validateaddress", "\"TxMQBVc9Ekw7gSxEJgqut5wCLeaAUwj1dW\"")
            + HelpExampleRpc("validateaddress", "\"TxMQBVc9Ekw7gSxEJgqut5wCLeaAUwj1dW\"")
        );

#ifdef ENABLE_WALLET
    LOCK2(cs_main, pwalletMain ? &pwalletMain->cs_wallet : NULL);
#else
    LOCK(cs_main);
#endif

    CBitcoinAddress address(params[0].get_str());
    bool isValid = address.IsValid();

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("isvalid", isValid));
    if (isValid)
    {
        CTxDestination dest = address.Get();
        string currentAddress = address.ToString();
        ret.push_back(Pair("address", currentAddress));

        CScript scriptPubKey = GetScriptForDestination(dest);
        ret.push_back(Pair("scriptPubKey", HexStr(scriptPubKey.begin(), scriptPubKey.end())));

#ifdef ENABLE_WALLET
        isminetype mine = pwalletMain ? IsMine(*pwalletMain, dest) : ISMINE_NO;
        if (address.IsColdStakingAddress(Params())) {
            CBitcoinAddress stakingAddress;
            address.GetStakingAddress(stakingAddress);
            CBitcoinAddress spendingAddress;
            address.GetSpendingAddress(spendingAddress);
            ret.push_back(Pair("stakingaddress", stakingAddress.ToString()));
            ret.push_back(Pair("spendingaddress", spendingAddress.ToString()));
        }
        ret.push_back(Pair("ismine", (mine & ISMINE_SPENDABLE) ? true : false));
        ret.push_back(Pair("isstakable", (mine & ISMINE_STAKABLE || (mine & ISMINE_SPENDABLE &&
                     !address.IsColdStakingAddress(Params()))) ? true : false));
        ret.push_back(Pair("iswatchonly", (mine & ISMINE_WATCH_ONLY) ? true: false));
        UniValue detail = boost::apply_visitor(DescribeAddressVisitor(), dest);
        ret.pushKVs(detail);
        if (pwalletMain && pwalletMain->mapAddressBook.count(dest))
            ret.push_back(Pair("account", pwalletMain->mapAddressBook[dest].name));
        CKeyID keyID;
        if (pwalletMain && address.GetKeyID(keyID) && pwalletMain->mapKeyMetadata.count(keyID) && !pwalletMain->mapKeyMetadata[keyID].hdKeypath.empty())
        {
            ret.push_back(Pair("hdkeypath", pwalletMain->mapKeyMetadata[keyID].hdKeypath));
            ret.push_back(Pair("hdmasterkeyid", pwalletMain->mapKeyMetadata[keyID].hdMasterKeyID.GetHex()));
        }
#endif
    }
    return ret;
}

/**
 * Used by addmultisigaddress / createmultisig:
 */
CScript _createmultisig_redeemScript(const UniValue& params)
{
    int nRequired = params[0].get_int();
    const UniValue& keys = params[1].get_array();

    // Gather public keys
    if (nRequired < 1)
        throw runtime_error("a multisignature address must require at least one key to redeem");
    if ((int)keys.size() < nRequired)
        throw runtime_error(
            strprintf("not enough keys supplied "
                      "(got %u keys, but need at least %d to redeem)", keys.size(), nRequired));
    if (keys.size() > 16)
        throw runtime_error("Number of addresses involved in the multisignature address creation > 16\nReduce the number");
    std::vector<CPubKey> pubkeys;
    pubkeys.resize(keys.size());
    for (unsigned int i = 0; i < keys.size(); i++)
    {
        const std::string& ks = keys[i].get_str();
#ifdef ENABLE_WALLET
        // Case 1: Bitcoin address and we have full public key:
        CBitcoinAddress address(ks);
        if (pwalletMain && address.IsValid())
        {
            CKeyID keyID;
            if (!address.GetKeyID(keyID))
                throw runtime_error(
                    strprintf("%s does not refer to a key",ks));
            CPubKey vchPubKey;
            if (!pwalletMain->GetPubKey(keyID, vchPubKey))
                throw runtime_error(
                    strprintf("no full public key for address %s",ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }

        // Case 2: hex public key
        else
#endif
        if (IsHex(ks))
        {
            CPubKey vchPubKey(ParseHex(ks));
            if (!vchPubKey.IsFullyValid())
                throw runtime_error(" Invalid public key: "+ks);
            pubkeys[i] = vchPubKey;
        }
        else
        {
            throw runtime_error(" Invalid public key: "+ks);
        }
    }
    CScript result = GetScriptForMultisig(nRequired, pubkeys);

    if (result.size() > MAX_SCRIPT_ELEMENT_SIZE)
        throw runtime_error(
                strprintf("redeemScript exceeds size limit: %d > %d", result.size(), MAX_SCRIPT_ELEMENT_SIZE));

    return result;
}

#ifdef ENABLE_BITCORE_RPC
bool getAddressesFromParams(const UniValue& params, std::vector<std::pair<uint256, int> > &addresses)
{
    if (params[0].isStr()) {
        CBitcoinAddress address(params[0].get_str());
        uint256 hashBytes;
        int type = 0;
        if (!address.GetIndexKey(hashBytes, type)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
        }
        addresses.push_back(std::make_pair(hashBytes, type));
    } else if (params[0].isObject()) {

        UniValue addressValues = find_value(params[0].get_obj(), "addresses");
        if (!addressValues.isArray()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Addresses is expected to be an array");
        }

        std::vector<UniValue> values = addressValues.getValues();

        for (std::vector<UniValue>::iterator it = values.begin(); it != values.end(); ++it) {

            CBitcoinAddress address(it->get_str());
            uint256 hashBytes;
            int type = 0;
            if (!address.GetIndexKey(hashBytes, type)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
            }
            addresses.push_back(std::make_pair(hashBytes, type));
        }
    } else {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    return true;
}

bool heightSort(std::pair<CAddressUnspentKey, CAddressUnspentValue> a,
                std::pair<CAddressUnspentKey, CAddressUnspentValue> b) {
    return a.second.blockHeight < b.second.blockHeight;
}

bool timestampSort(std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> a,
                   std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> b) {
    return a.second.time < b.second.time;
}

bool getAddressFromIndex(const int &type, const uint256 &hash, std::string &address)
{
    if (type == 2) {
        std::vector<unsigned char> addressBytes(hash.begin(), hash.begin() + 20);
        address = CBitcoinAddress(CScriptID(uint160(addressBytes))).ToString();
    } else if (type == 1) {
        std::vector<unsigned char> addressBytes(hash.begin(), hash.begin() + 20);
        address = CBitcoinAddress(CKeyID(uint160(addressBytes))).ToString();
    } else {
        return false;
    }
    return true;
}


UniValue getaddressdeltas(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1 || !params[0].isObject())
        throw runtime_error(
            "getaddressdeltas\n"
            "\nReturns all changes for an address (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "  \"start\" (number) The start block height\n"
            "  \"end\" (number) The end block height\n"
            "  \"chainInfo\" (boolean) Include chain info in results, only applies if start and end specified\n"
            "}\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"satoshis\"  (number) The difference of satoshis\n"
            "    \"txid\"  (string) The related txid\n"
            "    \"index\"  (number) The related input or output index\n"
            "    \"height\"  (number) The block height\n"
            "    \"address\"  (string) The base58check encoded address\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressdeltas", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleRpc("getaddressdeltas", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
        );


    UniValue startValue = find_value(params[0].get_obj(), "start");
    UniValue endValue = find_value(params[0].get_obj(), "end");

    UniValue chainInfo = find_value(params[0].get_obj(), "chainInfo");
    bool includeChainInfo = false;
    if (chainInfo.isBool()) {
        includeChainInfo = chainInfo.get_bool();
    }

    int start = 0;
    int end = 0;

    if (startValue.isNum() && endValue.isNum()) {
        start = startValue.get_int();
        end = endValue.get_int();
        if (start <= 0 || end <= 0) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Start and end is expected to be greater than zero");
        }
        if (end < start) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "End value is expected to be greater than start");
        }
    }

    std::vector<std::pair<uint256, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint256, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (start > 0 && end > 0) {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex, start, end)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        } else {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }
    }

    UniValue deltas(UniValue::VARR);

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        UniValue delta(UniValue::VOBJ);
        delta.push_back(Pair("satoshis", it->second));
        delta.push_back(Pair("txid", it->first.txhash.GetHex()));
        delta.push_back(Pair("index", (int)it->first.index));
        delta.push_back(Pair("blockindex", (int)it->first.txindex));
        delta.push_back(Pair("height", it->first.blockHeight));
        delta.push_back(Pair("address", address));
        deltas.push_back(delta);
    }

    UniValue result(UniValue::VOBJ);

    if (includeChainInfo && start > 0 && end > 0) {
        LOCK(cs_main);

        if (start > chainActive.Height() || end > chainActive.Height()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Start or end is outside chain range");
        }

        CBlockIndex* startIndex = chainActive[start];
        CBlockIndex* endIndex = chainActive[end];

        UniValue startInfo(UniValue::VOBJ);
        UniValue endInfo(UniValue::VOBJ);

        startInfo.push_back(Pair("hash", startIndex->GetBlockHash().GetHex()));
        startInfo.push_back(Pair("height", start));

        endInfo.push_back(Pair("hash", endIndex->GetBlockHash().GetHex()));
        endInfo.push_back(Pair("height", end));

        result.push_back(Pair("deltas", deltas));
        result.push_back(Pair("start", startInfo));
        result.push_back(Pair("end", endInfo));

        return result;
    } else {
        return deltas;
    }
}

UniValue getaddressbalance(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressbalance\n"
            "\nReturns the balance for an address(es) (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "}\n"
            "\nResult:\n"
            "{\n"
            "  \"balance\"  (string) The current balance in satoshis\n"
            "  \"received\"  (string) The total number of satoshis received (including change)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressbalance", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleRpc("getaddressbalance", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
        );

    std::vector<std::pair<uint256, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint256, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
        }
    }

    CAmount balance = 0;
    CAmount received = 0;
    CAmount immature = 0;

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        if (it->second > 0) {
            received += it->second;
        }
        balance += it->second;
        if (it->first.txindex == 1 && ((chainActive.Height() - it->first.blockHeight) < COINBASE_MATURITY))
            immature += it->second; //immature stake outputs
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("balance", balance));
    result.push_back(Pair("received", received));
    result.push_back(Pair("immature", immature));

    return result;
}

UniValue getaddressutxos(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressutxos\n"
            "\nReturns all unspent outputs for an address (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ],\n"
            "  \"chainInfo\"  (boolean) Include chain info with results\n"
            "}\n"
            "\nResult\n"
            "[\n"
            "  {\n"
            "    \"address\"  (string) The address base58check encoded\n"
            "    \"txid\"  (string) The output txid\n"
            "    \"height\"  (number) The block height\n"
            "    \"outputIndex\"  (number) The output index\n"
            "    \"script\"  (strin) The script hex encoded\n"
            "    \"satoshis\"  (number) The number of satoshis of the output\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressutxos", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleRpc("getaddressutxos", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
            );

    bool includeChainInfo = false;
    if (params[0].isObject()) {
        UniValue chainInfo = find_value(params[0].get_obj(), "chainInfo");
        if (chainInfo.isBool()) {
            includeChainInfo = chainInfo.get_bool();
        }
    }

    std::vector<std::pair<uint256, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > unspentOutputs;

    for (std::vector<std::pair<uint256, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (!GetAddressUnspent((*it).first, (*it).second, unspentOutputs)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
        }
    }

    std::sort(unspentOutputs.begin(), unspentOutputs.end(), heightSort);

    UniValue utxos(UniValue::VARR);

    for (std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> >::const_iterator it=unspentOutputs.begin(); it!=unspentOutputs.end(); it++) {
        UniValue output(UniValue::VOBJ);
        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.hashBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        output.push_back(Pair("address", address));
        output.push_back(Pair("txid", it->first.txhash.GetHex()));
        output.push_back(Pair("outputIndex", (int)it->first.index));
        output.push_back(Pair("script", HexStr(it->second.script.begin(), it->second.script.end())));
        output.push_back(Pair("satoshis", it->second.satoshis));
        output.push_back(Pair("height", it->second.blockHeight));
        output.push_back(Pair("isStake", it->second.coinStake));
        utxos.push_back(output);
    }

    if (includeChainInfo) {
        UniValue result(UniValue::VOBJ);
        result.push_back(Pair("utxos", utxos));

        LOCK(cs_main);
        result.push_back(Pair("hash", chainActive.Tip()->GetBlockHash().GetHex()));
        result.push_back(Pair("height", (int)chainActive.Height()));
        return result;
    } else {
        return utxos;
    }
}

UniValue getaddressmempool(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddressmempool\n"
            "\nReturns all mempool deltas for an address (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "}\n"
            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"address\"  (string) The base58check encoded address\n"
            "    \"txid\"  (string) The related txid\n"
            "    \"index\"  (number) The related input or output index\n"
            "    \"satoshis\"  (number) The difference of satoshis\n"
            "    \"timestamp\"  (number) The time the transaction entered the mempool (seconds)\n"
            "    \"prevtxid\"  (string) The previous txid (if spending)\n"
            "    \"prevout\"  (string) The previous transaction output index (if spending)\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddressmempool", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleRpc("getaddressmempool", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
        );

    std::vector<std::pair<uint256, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> > indexes;

    if (!mempool.getAddressIndex(addresses, indexes)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
    }

    std::sort(indexes.begin(), indexes.end(), timestampSort);

    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<CMempoolAddressDeltaKey, CMempoolAddressDelta> >::iterator it = indexes.begin();
         it != indexes.end(); it++) {

        std::string address;
        if (!getAddressFromIndex(it->first.type, it->first.addressBytes, address)) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unknown address type");
        }

        UniValue delta(UniValue::VOBJ);
        delta.push_back(Pair("address", address));
        delta.push_back(Pair("txid", it->first.txhash.GetHex()));
        delta.push_back(Pair("index", (int)it->first.index));
        delta.push_back(Pair("satoshis", it->second.amount));
        delta.push_back(Pair("timestamp", it->second.time));
        if (it->second.amount < 0) {
            delta.push_back(Pair("prevtxid", it->second.prevhash.GetHex()));
            delta.push_back(Pair("prevout", (int)it->second.prevout));
        }
        result.push_back(delta);
    }

    return result;
}

UniValue getblockhashes(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2)
        throw runtime_error(
            "getblockhashes timestamp\n"
            "\nReturns array of hashes of blocks within the timestamp range provided.\n"
            "\nArguments:\n"
            "1. high         (numeric, required) The newer block timestamp\n"
            "2. low          (numeric, required) The older block timestamp\n"
            "3. options      (string, required) A json object\n"
            "    {\n"
            "      \"noOrphans\":true   (boolean) will only include blocks on the main chain\n"
            "      \"logicalTimes\":true   (boolean) will include logical timestamps with hashes\n"
            "    }\n"
            "\nResult:\n"
            "[\n"
            "  \"hash\"         (string) The block hash\n"
            "]\n"
            "[\n"
            "  {\n"
            "    \"blockhash\": (string) The block hash\n"
            "    \"logicalts\": (numeric) The logical timestamp\n"
            "  }\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getblockhashes", "1231614698 1231024505")
            + HelpExampleRpc("getblockhashes", "1231614698, 1231024505")
            + HelpExampleCli("getblockhashes", "1231614698 1231024505 '{\"noOrphans\":false, \"logicalTimes\":true}'")
            );

    unsigned int high = params[0].get_int();
    unsigned int low = params[1].get_int();
    bool fActiveOnly = false;
    bool fLogicalTS = false;

    if (params.size() > 2) {
        if (params[2].isObject()) {
            UniValue noOrphans = find_value(params[2].get_obj(), "noOrphans");
            UniValue returnLogical = find_value(params[2].get_obj(), "logicalTimes");

            if (noOrphans.isBool())
                fActiveOnly = noOrphans.get_bool();

            if (returnLogical.isBool())
                fLogicalTS = returnLogical.get_bool();
        }
    }

    std::vector<std::pair<uint256, unsigned int> > blockHashes;

    if (fActiveOnly)
        LOCK(cs_main);

    if (!GetTimestampIndex(high, low, fActiveOnly, blockHashes)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for block hashes");
    }

    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<uint256, unsigned int> >::const_iterator it=blockHashes.begin(); it!=blockHashes.end(); it++) {
        if (fLogicalTS) {
            UniValue item(UniValue::VOBJ);
            item.push_back(Pair("blockhash", it->first.GetHex()));
            item.push_back(Pair("logicalts", (int)it->second));
            result.push_back(item);
        } else {
            result.push_back(it->first.GetHex());
        }
    }

    return result;
}

UniValue getspentinfo(const UniValue& params, bool fHelp)
{

    if (fHelp || params.size() != 1 || !params[0].isObject())
        throw runtime_error(
            "getspentinfo\n"
            "\nReturns the txid and index where an output is spent.\n"
            "\nArguments:\n"
            "{\n"
            "  \"txid\" (string) The hex string of the txid\n"
            "  \"index\" (number) The start block height\n"
            "}\n"
            "\nResult:\n"
            "{\n"
            "  \"txid\"  (string) The transaction id\n"
            "  \"index\"  (number) The spending input index\n"
            "  ,...\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getspentinfo", "'{\"txid\": \"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9\", \"index\": 0}'")
            + HelpExampleRpc("getspentinfo", "{\"txid\": \"0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9\", \"index\": 0}")
        );

    UniValue txidValue = find_value(params[0].get_obj(), "txid");
    UniValue indexValue = find_value(params[0].get_obj(), "index");

    if (!txidValue.isStr() || !indexValue.isNum()) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid txid or index");
    }

    uint256 txid = ParseHashV(txidValue, "txid");
    int outputIndex = indexValue.get_int();

    CSpentIndexKey key(txid, outputIndex);
    CSpentIndexValue value;

    if (!GetSpentIndex(key, value)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Unable to get spent info");
    }

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("txid", value.txid.GetHex()));
    obj.push_back(Pair("index", (int)value.inputIndex));
    obj.push_back(Pair("height", value.blockHeight));

    return obj;
}

UniValue getaddresstxids(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "getaddresstxids\n"
            "\nReturns the txids for an address(es) (requires addressindex to be enabled).\n"
            "\nArguments:\n"
            "{\n"
            "  \"addresses\"\n"
            "    [\n"
            "      \"address\"  (string) The base58check encoded address\n"
            "      ,...\n"
            "    ]\n"
            "  \"start\" (number) The start block height\n"
            "  \"end\" (number) The end block height\n"
            "}\n"
            "\nResult:\n"
            "[\n"
            "  \"transactionid\"  (string) The transaction id\n"
            "  ,...\n"
            "]\n"
            "\nExamples:\n"
            + HelpExampleCli("getaddresstxids", "'{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}'")
            + HelpExampleRpc("getaddresstxids", "{\"addresses\": [\"12c6DSiU4Rq3P4ZxziKxzrL5LmMBrzjrJX\"]}")
        );

    std::vector<std::pair<uint256, int> > addresses;

    if (!getAddressesFromParams(params, addresses)) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid address");
    }

    int start = 0;
    int end = 0;
    if (params[0].isObject()) {
        UniValue startValue = find_value(params[0].get_obj(), "start");
        UniValue endValue = find_value(params[0].get_obj(), "end");
        if (startValue.isNum() && endValue.isNum()) {
            start = startValue.get_int();
            end = endValue.get_int();
        }
    }

    std::vector<std::pair<CAddressIndexKey, CAmount> > addressIndex;

    for (std::vector<std::pair<uint256, int> >::iterator it = addresses.begin(); it != addresses.end(); it++) {
        if (start > 0 && end > 0) {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex, start, end)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        } else {
            if (!GetAddressIndex((*it).first, (*it).second, addressIndex)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available for address");
            }
        }
    }

    std::set<std::pair<int, std::string> > txids;
    UniValue result(UniValue::VARR);

    for (std::vector<std::pair<CAddressIndexKey, CAmount> >::const_iterator it=addressIndex.begin(); it!=addressIndex.end(); it++) {
        int height = it->first.blockHeight;
        std::string txid = it->first.txhash.GetHex();

        if (addresses.size() > 1) {
            txids.insert(std::make_pair(height, txid));
        } else {
            if (txids.insert(std::make_pair(height, txid)).second) {
                result.push_back(txid);
            }
        }
    }

    if (addresses.size() > 1) {
        for (std::set<std::pair<int, std::string> >::const_iterator it=txids.begin(); it!=txids.end(); it++) {
            result.push_back(it->second);
        }
    }

    return result;
}
#endif

UniValue createmultisig(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 2)
    {
        string msg = "createmultisig nrequired [\"key\",...]\n"
            "\nCreates a multi-signature address with n signature of m keys required.\n"
            "It returns a json object with the address and redeemScript.\n"

            "\nArguments:\n"
            "1. nrequired      (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "2. \"keys\"       (string, required) A json array of keys which are trezarcoin addresses or hex-encoded public keys\n"
            "     [\n"
            "       \"key\"    (string) trezarcoin address or hex-encoded public key\n"
            "       ,...\n"
            "     ]\n"

            "\nResult:\n"
            "{\n"
            "  \"address\":\"multisigaddress\",  (string) The value of the new multisig address.\n"
            "  \"redeemScript\":\"script\"       (string) The string value of the hex-encoded redemption script.\n"
            "}\n"

            "\nExamples:\n"
            "\nCreate a multisig address from 2 addresses\n"
            + HelpExampleCli("createmultisig", "2 \"[\\\"TxMQBVc9Ekw7gSxEJgqut5wCLeaAUwj1dW\\\",\\\"Tpm5gUWmJMaaiETC2KkshCwTvZ1FwLZ3se\\\"]\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("createmultisig", "2, \"[\\\"TxMQBVc9Ekw7gSxEJgqut5wCLeaAUwj1dW\\\",\\\"Tpm5gUWmJMaaiETC2KkshCwTvZ1FwLZ3se\\\"]\"")
        ;
        throw runtime_error(msg);
    }

    // Construct using pay-to-script-hash:
    CScript inner = _createmultisig_redeemScript(params);
    CScriptID innerID(inner);
    CBitcoinAddress address(innerID);

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("address", address.ToString()));
    result.push_back(Pair("redeemScript", HexStr(inner.begin(), inner.end())));

    return result;
}

UniValue verifymessage(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "verifymessage \"trezarcoinaddress\" \"signature\" \"message\"\n"
            "\nVerify a signed message\n"
            "\nArguments:\n"
            "1. \"trezarcoinaddress\"  (string, required) The trezarcoin address to use for the signature.\n"
            "2. \"signature\"       (string, required) The signature provided by the signer in base 64 encoding (see signmessage).\n"
            "3. \"message\"         (string, required) The message that was signed.\n"
            "\nResult:\n"
            "true|false   (boolean) If the signature is verified or not.\n"
            "\nExamples:\n"
            "\nUnlock the wallet for 30 seconds\n"
            + HelpExampleCli("walletpassphrase", "\"mypassphrase\" 30") +
            "\nCreate the signature\n"
            + HelpExampleCli("signmessage", "\"Tpm5gUWmJMaaiETC2KkshCwTvZ1FwLZ3se\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"Tpm5gUWmJMaaiETC2KkshCwTvZ1FwLZ3se\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("verifymessage", "\"Tpm5gUWmJMaaiETC2KkshCwTvZ1FwLZ3se\", \"signature\", \"my message\"")
        );

    LOCK(cs_main);

    string strAddress  = params[0].get_str();
    string strSign     = params[1].get_str();
    string strMessage  = params[2].get_str();

    CBitcoinAddress addr(strAddress);
    if (!addr.IsValid())
        throw JSONRPCError(RPC_TYPE_ERROR, "Invalid address");

    CKeyID keyID;
    if (!addr.GetKeyID(keyID))
        throw JSONRPCError(RPC_TYPE_ERROR, "Address does not refer to key");

    bool fInvalid = false;
    vector<unsigned char> vchSig = DecodeBase64(strSign.c_str(), &fInvalid);

    if (fInvalid)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Malformed base64 encoding");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    CPubKey pubkey;
    if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        return false;

    return (pubkey.GetID() == keyID);
}

UniValue signmessagewithprivkey(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "signmessagewithprivkey \"privkey\" \"message\"\n"
            "\nSign a message with the private key of an address\n"
            "\nArguments:\n"
            "1. \"privkey\"         (string, required) The private key to sign the message with.\n"
            "2. \"message\"         (string, required) The message to create a signature of.\n"
            "\nResult:\n"
            "\"signature\"          (string) The signature of the message encoded in base 64\n"
            "\nExamples:\n"
            "\nCreate the signature\n"
            + HelpExampleCli("signmessagewithprivkey", "\"privkey\" \"my message\"") +
            "\nVerify the signature\n"
            + HelpExampleCli("verifymessage", "\"Tpm5gUWmJMaaiETC2KkshCwTvZ1FwLZ3se\" \"signature\" \"my message\"") +
            "\nAs json rpc\n"
            + HelpExampleRpc("signmessagewithprivkey", "\"privkey\", \"my message\"")
        );

    string strPrivkey = params[0].get_str();
    string strMessage = params[1].get_str();

    CBitcoinSecret vchSecret;
    bool fGood = vchSecret.SetString(strPrivkey);
    if (!fGood)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
    CKey key = vchSecret.GetKey();
    if (!key.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Private key outside allowed range");

    CHashWriter ss(SER_GETHASH, 0);
    ss << strMessageMagic;
    ss << strMessage;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(ss.GetHash(), vchSig))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Sign failed");

    return EncodeBase64(&vchSig[0], vchSig.size());
}

UniValue setmocktime(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "setmocktime timestamp\n"
            "\nSet the local time to given timestamp (-regtest only)\n"
            "\nArguments:\n"
            "1. timestamp  (integer, required) Unix seconds-since-epoch timestamp\n"
            "   Pass 0 to go back to using the system time."
        );

    if (!Params().MineBlocksOnDemand())
        throw runtime_error("setmocktime for regression testing (-regtest mode) only");

    // cs_vNodes is locked and node send/receive times are updated
    // atomically with the time change to prevent peers from being
    // disconnected because we think we haven't communicated with them
    // in a long time.
    LOCK2(cs_main, cs_vNodes);

    RPCTypeCheck(params, boost::assign::list_of(UniValue::VNUM));
    SetMockTime(params[0].get_int64());

    uint64_t t = GetTime();
    BOOST_FOREACH(CNode* pnode, vNodes) {
        pnode->nLastSend = pnode->nLastRecv = t;
    }

    return NullUniValue;
}

// RPC commands related to sync checkpoints
// get information of sync-checkpoint (first introduced in ppcoin)
UniValue getcheckpoint(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getcheckpoint\n"
            "Show info of synchronized checkpoint.\n");

    UniValue result(UniValue::VARR);
    UniValue entry(UniValue::VOBJ);
    CBlockIndex* pindexCheckpoint;

    entry.push_back(Pair("synccheckpoint", hashSyncCheckpoint.ToString().c_str()));
    if (mapBlockIndex.count(hashSyncCheckpoint))
    {
        pindexCheckpoint = mapBlockIndex[hashSyncCheckpoint];
        entry.push_back(Pair("height", pindexCheckpoint->nHeight));
        entry.push_back(Pair("timestamp", (boost::int64_t) pindexCheckpoint->GetBlockTime()));
    }
    if (mapArgs.count("-checkpointkey"))
        entry.push_back(Pair("checkpointmaster", true));
    result.push_back(entry);

    return result;
}

UniValue sendcheckpoint(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "sendcheckpoint <blockhash>\n"
            "Send a synchronized checkpoint.\n");

    if (!mapArgs.count("-checkpointkey") || CSyncCheckpoint::strMasterPrivKey.empty())
        throw runtime_error("Not a checkpointmaster node, first set checkpointkey in configuration and restart client. ");

    string strHash = params[0].get_str();
    uint256 hash = uint256S(strHash);

    if (!SendSyncCheckpoint(hash))
        throw runtime_error("Failed to send checkpoint, check log. ");

    UniValue result(UniValue::VARR);
    UniValue entry(UniValue::VOBJ);
    CBlockIndex* pindexCheckpoint;

    entry.push_back(Pair("synccheckpoint", hashSyncCheckpoint.ToString().c_str()));
    if (mapBlockIndex.count(hashSyncCheckpoint))
    {
        pindexCheckpoint = mapBlockIndex[hashSyncCheckpoint];
        entry.push_back(Pair("height", pindexCheckpoint->nHeight));
        entry.push_back(Pair("timestamp", (boost::int64_t) pindexCheckpoint->GetBlockTime()));
    }
    if (mapArgs.count("-checkpointkey"))
        entry.push_back(Pair("checkpointmaster", true));
    result.push_back(entry);

    return result;
}

#ifdef ENABLE_SMESSAGE
UniValue smsgenable(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "smsgenable \n"
            "Enable secure messaging.");

    if (fSecMsgEnabled)
        throw runtime_error("Secure messaging is already enabled.");

    UniValue result(UniValue::VOBJ);
    if (!SecureMsgEnable()) {
        result.push_back(Pair("result", "Failed to enable secure messaging."));
    } else {
        result.push_back(Pair("result", "Enabled secure messaging."));
    }
    return result;
}

UniValue smsgdisable(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "smsgdisable \n"
            "Disable secure messaging.");
    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is already disabled.");

    UniValue result(UniValue::VOBJ);
    if (!SecureMsgDisable()) {
        result.push_back(Pair("result", "Failed to disable secure messaging."));
    } else {
        result.push_back(Pair("result", "Disabled secure messaging."));
    }
    return result;
}

UniValue smsgoptions(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "smsgoptions [list|set <optname> <value>]\n"
            "List and manage options.");

    std::string mode = "list";
    if (params.size() > 0) {
        mode = params[0].get_str();
    }

    UniValue result(UniValue::VOBJ);

    if (mode == "list")
    {
        result.push_back(Pair("option", std::string("newAddressRecv = ") + (smsgOptions.fNewAddressRecv ? "true" : "false")));
        result.push_back(Pair("option", std::string("newAddressAnon = ") + (smsgOptions.fNewAddressAnon ? "true" : "false")));

        result.push_back(Pair("result", "Success."));
    } else if (mode == "set") {
        if (params.size() < 3) {
            result.push_back(Pair("result", "Too few parameters."));
            result.push_back(Pair("expected", "set <optname> <value>"));
            return result;
        }

        std::string optname = params[1].get_str();
        std::string value   = params[2].get_str();

        if (optname == "newAddressRecv") {
            if (value == "+" || value == "on"  || value == "true"  || value == "1") {
                smsgOptions.fNewAddressRecv = true;
            } else if (value == "-" || value == "off" || value == "false" || value == "0") {
                smsgOptions.fNewAddressRecv = false;
            } else {
                result.push_back(Pair("result", "Unknown value."));
                return result;
            }
            result.push_back(Pair("set option", std::string("newAddressRecv = ") + (smsgOptions.fNewAddressRecv ? "true" : "false")));
        } else
        if (optname == "newAddressAnon") {
            if (value == "+" || value == "on"  || value == "true"  || value == "1") {
                smsgOptions.fNewAddressAnon = true;
            } else if (value == "-" || value == "off" || value == "false" || value == "0") {
                smsgOptions.fNewAddressAnon = false;
            } else {
                result.push_back(Pair("result", "Unknown value."));
                return result;
            }
            result.push_back(Pair("set option", std::string("newAddressAnon = ") + (smsgOptions.fNewAddressAnon ? "true" : "false")));
        } else {
            result.push_back(Pair("result", "Option not found."));
            return result;
        }
    } else {
        result.push_back(Pair("result", "Unknown Mode."));
        result.push_back(Pair("expected", "smsgoption [list|set <optname> <value>]"));
    }
    return result;
}

UniValue smsglocalkeys(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
            "smsglocalkeys [whitelist|all|wallet|recv <+/-> <address>|anon <+/-> <address>]\n"
            "List and manage keys.");

    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");

    UniValue result(UniValue::VOBJ);

    std::string mode = "whitelist";
    if (params.size() > 0)
        mode = params[0].get_str();

    char cbuf[256];

    if (mode == "whitelist" || mode == "all")
    {
        uint32_t nKeys = 0;
        int all = mode == "all" ? 1 : 0;
        for (std::vector<SecMsgAddress>::iterator it = smsgAddresses.begin(); it != smsgAddresses.end(); ++it)
        {
            if (!all
                && !it->fReceiveEnabled)
                continue;

            CBitcoinAddress coinAddress(it->sAddress);
            if (!coinAddress.IsValid())
                continue;

            std::string sPublicKey;

            CKeyID keyID;
            if (!coinAddress.GetKeyID(keyID))
                continue;

            CPubKey pubKey;
            if (!pwalletMain->GetPubKey(keyID, pubKey))
                continue;
            if (!pubKey.IsValid() || !pubKey.IsCompressed())
                continue;

            sPublicKey = EncodeBase58(pubKey.begin(), pubKey.end());

            std::string sLabel = pwalletMain->mapAddressBook[keyID].name;
            std::string sInfo;
            if (all)
                sInfo = std::string("Receive ") + (it->fReceiveEnabled ? "on,  " : "off, ");
            sInfo += std::string("Anon ") + (it->fReceiveAnon ? "on" : "off");
            result.push_back(Pair("key", it->sAddress + " - " + sPublicKey + " " + sInfo + " - " + sLabel));

            nKeys++;
        }

        snprintf(cbuf, sizeof(cbuf), "%u keys listed.", nKeys);
        result.push_back(Pair("result", std::string(cbuf)));

    } else if (mode == "recv") {
        if (params.size() < 3)
        {
            result.push_back(Pair("result", "Too few parameters."));
            result.push_back(Pair("expected", "recv <+/-> <address>"));
            return result;
        }

        std::string op      = params[1].get_str();
        std::string addr    = params[2].get_str();

        std::vector<SecMsgAddress>::iterator it;
        for (it = smsgAddresses.begin(); it != smsgAddresses.end(); ++it)
        {
            if (addr != it->sAddress)
                continue;
            break;
        }

        if (it == smsgAddresses.end())
        {
            result.push_back(Pair("result", "Address not found."));
            return result;
        }

        if (op == "+" || op == "on"  || op == "add" || op == "a") {
            it->fReceiveEnabled = true;
        } else if (op == "-" || op == "off" || op == "rem" || op == "r") {
            it->fReceiveEnabled = false;
        } else {
            result.push_back(Pair("result", "Unknown operation."));
            return result;
        }

        std::string sInfo;
        sInfo = std::string("Receive ") + (it->fReceiveEnabled ? "on, " : "off,");
        sInfo += std::string("Anon ") + (it->fReceiveAnon ? "on" : "off");
        result.push_back(Pair("result", "Success."));
        result.push_back(Pair("key", it->sAddress + " " + sInfo));
        return result;

    } else if (mode == "anon") {
        if (params.size() < 3) {
            result.push_back(Pair("result", "Too few parameters."));
            result.push_back(Pair("expected", "anon <+/-> <address>"));
            return result;
        }

        std::string op      = params[1].get_str();
        std::string addr    = params[2].get_str();

        std::vector<SecMsgAddress>::iterator it;
        for (it = smsgAddresses.begin(); it != smsgAddresses.end(); ++it) {
            if (addr != it->sAddress)
                continue;
            break;
        }

        if (it == smsgAddresses.end()) {
            result.push_back(Pair("result", "Address not found."));
            return result;
        }

        if (op == "+" || op == "on"  || op == "add" || op == "a") {
            it->fReceiveAnon = true;
        } else if (op == "-" || op == "off" || op == "rem" || op == "r") {
            it->fReceiveAnon = false;
        } else {
            result.push_back(Pair("result", "Unknown operation."));
            return result;
        }

        std::string sInfo;
        sInfo = std::string("Receive ") + (it->fReceiveEnabled ? "on, " : "off,");
        sInfo += std::string("Anon ") + (it->fReceiveAnon ? "on" : "off");
        result.push_back(Pair("result", "Success."));
        result.push_back(Pair("key", it->sAddress + " " + sInfo));
        return result;

    } else
    if (mode == "wallet")
    {
        uint32_t nKeys = 0;
        BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& entry, pwalletMain->mapAddressBook)
        {
            if (!IsMine(*pwalletMain, entry.first))
                continue;

            CBitcoinAddress coinAddress(entry.first);
            if (!coinAddress.IsValid())
                continue;

            std::string address;
            std::string sPublicKey;
            address = coinAddress.ToString();

            CKeyID keyID;
            if (!coinAddress.GetKeyID(keyID))
                continue;

            CPubKey pubKey;
            if (!pwalletMain->GetPubKey(keyID, pubKey))
                continue;
            if (!pubKey.IsValid() || !pubKey.IsCompressed())
                continue;

            sPublicKey = EncodeBase58(pubKey.begin(), pubKey.end());

            result.push_back(Pair("key", address + " - " + sPublicKey + " - " + entry.second.name));
            nKeys++;
        }

        snprintf(cbuf, sizeof(cbuf), "%u keys listed from wallet.", nKeys);
        result.push_back(Pair("result", std::string(cbuf)));
    } else {
        result.push_back(Pair("result", "Unknown Mode."));
        result.push_back(Pair("expected", "smsglocalkeys [whitelist|all|wallet|recv <+/-> <address>|anon <+/-> <address>]"));
    }

    return result;
}

UniValue smsgscanchain(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "smsgscanchain \n"
            "Look for public keys in the block chain.");

    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");

    UniValue result(UniValue::VOBJ);
    if (!SecureMsgScanBlockChain()) {
        result.push_back(Pair("result", "Scan Chain Failed."));
    } else {
        result.push_back(Pair("result", "Scan Chain Completed."));
    }
    return result;
}

UniValue smsgscanbuckets(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "smsgscanbuckets \n"
            "Force rescan of all messages in the bucket store.");

    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");

    if (pwalletMain->IsLocked())
        throw runtime_error("Wallet is locked.");

    UniValue result(UniValue::VOBJ);
    if (!SecureMsgScanBuckets()) {
        result.push_back(Pair("result", "Scan Buckets Failed."));
    } else {
        result.push_back(Pair("result", "Scan Buckets Completed."));
    }
    return result;
}

UniValue smsgaddkey(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "smsgaddkey <address> <pubkey>\n"
            "Add address, pubkey pair to database.");

    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");

    std::string addr = params[0].get_str();
    std::string pubk = params[1].get_str();

    UniValue result(UniValue::VOBJ);
    int rv = SecureMsgAddAddress(addr, pubk);
    if (rv != 0)
    {
        result.push_back(Pair("result", "Public key not added to db."));
        switch (rv)
        {
            case 2:     result.push_back(Pair("reason", "publicKey is invalid."));                  break;
            case 3:     result.push_back(Pair("reason", "publicKey does not match address."));      break;
            case 4:     result.push_back(Pair("reason", "address is already in db."));              break;
            case 5:     result.push_back(Pair("reason", "address is invalid."));                    break;
            default:    result.push_back(Pair("reason", "error."));                                 break;
        }
    } else {
        result.push_back(Pair("result", "Added public key to db."));
    }

    return result;
}

UniValue smsggetpubkey(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "smsggetpubkey <address>\n"
            "Return the base58 encoded compressed public key for an address.\n"
            "Tests localkeys first, then looks in public key db.\n");

    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");


    std::string address   = params[0].get_str();
    std::string publicKey;

    UniValue result(UniValue::VOBJ);
    int rv = SecureMsgGetLocalPublicKey(address, publicKey);
    switch (rv)
    {
        case 0:
            result.push_back(Pair("result", "Success."));
            result.push_back(Pair("address in wallet", address));
            result.push_back(Pair("compressed public key", publicKey));
            return result; // success, don't check db
        case 2:
        case 3:
            result.push_back(Pair("result", "Failed."));
            result.push_back(Pair("message", "Invalid address."));
            return result;
        case 4:
            break; // check db
        //case 1:
        default:
            result.push_back(Pair("result", "Failed."));
            result.push_back(Pair("message", "Error."));
            return result;
    }

    CBitcoinAddress coinAddress(address);

    CKeyID keyID;
    if (!coinAddress.GetKeyID(keyID)) {
        result.push_back(Pair("result", "Failed."));
        result.push_back(Pair("message", "Invalid address."));
        return result;
    }

    CPubKey cpkFromDB;
    rv = SecureMsgGetStoredKey(keyID, cpkFromDB);

    switch (rv)
    {
        case 0:
            if (!cpkFromDB.IsValid() || !cpkFromDB.IsCompressed()) {
                result.push_back(Pair("result", "Failed."));
                result.push_back(Pair("message", "Invalid address."));
            } else {
                publicKey = EncodeBase58(cpkFromDB.begin(), cpkFromDB.end());

                result.push_back(Pair("result", "Success."));
                result.push_back(Pair("peer address in DB", address));
                result.push_back(Pair("compressed public key", publicKey));
            }
            break;
        case 2:
            result.push_back(Pair("result", "Failed."));
            result.push_back(Pair("message", "Address not found in wallet or db."));
            return result;
        default:
            result.push_back(Pair("result", "Failed."));
            result.push_back(Pair("message", "Error, GetStoredKey()."));
            return result;
    }

    return result;
}

UniValue smsgsend(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
            "smsgsend <addrFrom> <addrTo> <message>\n"
            "Send an encrypted message from addrFrom to addrTo.");

    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");

    std::string addrFrom  = params[0].get_str();
    std::string addrTo    = params[1].get_str();
    std::string msg       = params[2].get_str();

    UniValue result(UniValue::VOBJ);

    std::string sError;
    if (SecureMsgSend(addrFrom, addrTo, msg, sError) != 0) {
        result.push_back(Pair("result", "Send failed."));
        result.push_back(Pair("error", sError));
    } else {
        result.push_back(Pair("result", "Sent."));
    }

    return result;
}

UniValue smsgsendanon(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "smsgsendanon <addrTo> <message>\n"
            "Send an anonymous encrypted message to addrTo.");

    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");

    std::string addrFrom  = "anon";
    std::string addrTo    = params[0].get_str();
    std::string msg       = params[1].get_str();

    UniValue result(UniValue::VOBJ);
    std::string sError;
    if (SecureMsgSend(addrFrom, addrTo, msg, sError) != 0) {
        result.push_back(Pair("result", "Send failed."));
        result.push_back(Pair("error", sError));
    } else {
        result.push_back(Pair("result", "Sent."));
    }

    return result;
}

UniValue smsginbox(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1) // defaults to read
        throw runtime_error(
            "smsginbox [all|unread]\n"
            "Decrypt and display all received messages.");

    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");

    if (pwalletMain->IsLocked())
        throw runtime_error("Wallet is locked.");

    std::string mode = "unread";
    if (params.size() > 0)
        mode = params[0].get_str();

    UniValue result(UniValue::VOBJ);

    std::vector<unsigned char> vchKey;
    vchKey.resize(16);
    memset(&vchKey[0], 0, 16);

    {
        LOCK(cs_smsgDB);

        SecMsgDB dbInbox;

        if (!dbInbox.Open("cr+"))
            throw runtime_error("Could not open DB.");

        uint32_t nMessages = 0;
        char cbuf[256];

        std::string sPrefix("im");
        unsigned char chKey[18];

        if (mode == "all" || mode == "unread") {
            int fCheckReadStatus = mode == "unread" ? 1 : 0;

            SecMsgStored smsgStored;
            MessageData msg;

            dbInbox.TxnBegin();

            leveldb::Iterator* it = dbInbox.pdb->NewIterator(leveldb::ReadOptions());
            while (dbInbox.NextSmesg(it, sPrefix, chKey, smsgStored))
            {
                if (fCheckReadStatus
                    && !(smsgStored.status & SMSG_MASK_UNREAD))
                    continue;

                uint32_t nPayload = smsgStored.vchMessage.size() - SMSG_HDR_LEN;
                if (SecureMsgDecrypt(false, smsgStored.sAddrTo, &smsgStored.vchMessage[0], &smsgStored.vchMessage[SMSG_HDR_LEN], nPayload, msg) == 0)
                {
                    UniValue objM(UniValue::VOBJ);
                    objM.push_back(Pair("received", getTimeString(smsgStored.timeReceived, cbuf, sizeof(cbuf))));
                    objM.push_back(Pair("sent", getTimeString(msg.timestamp, cbuf, sizeof(cbuf))));
                    objM.push_back(Pair("from", msg.sFromAddress));
                    objM.push_back(Pair("to", smsgStored.sAddrTo));
                    objM.push_back(Pair("text", std::string((char*)&msg.vchMessage[0]))); // ugh

                    result.push_back(Pair("message", objM));
                } else
                {
                    result.push_back(Pair("message", "Could not decrypt."));
                };

                if (fCheckReadStatus)
                {
                    smsgStored.status &= ~SMSG_MASK_UNREAD;
                    dbInbox.WriteSmesg(chKey, smsgStored);
                };
                nMessages++;
            };
            delete it;
            dbInbox.TxnCommit();

            snprintf(cbuf, sizeof(cbuf), "%u messages shown.", nMessages);
            result.push_back(Pair("result", std::string(cbuf)));

        } else {
            result.push_back(Pair("result", "Unknown Mode."));
            result.push_back(Pair("expected", "[all|unread|clear]."));
        }
    }

    return result;
}

UniValue smsgoutbox(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1) // defaults to read
        throw runtime_error(
            "smsgoutbox [all]\n"
            "Decrypt and display all sent messages.");

    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");

    if (pwalletMain->IsLocked())
        throw runtime_error("Wallet is locked.");

    std::string mode = "all";
    if (params.size() > 0)
        mode = params[0].get_str();

    UniValue result(UniValue::VOBJ);

    std::string sPrefix("sm");
    unsigned char chKey[18];
    memset(&chKey[0], 0, 18);

    {
        LOCK(cs_smsgDB);

        SecMsgDB dbOutbox;

        if (!dbOutbox.Open("cr+"))
            throw runtime_error("Could not open DB.");

        uint32_t nMessages = 0;
        char cbuf[256];

        if (mode == "all") {
            SecMsgStored smsgStored;
            MessageData msg;
            leveldb::Iterator* it = dbOutbox.pdb->NewIterator(leveldb::ReadOptions());
            while (dbOutbox.NextSmesg(it, sPrefix, chKey, smsgStored))
            {
                uint32_t nPayload = smsgStored.vchMessage.size() - SMSG_HDR_LEN;

                if (SecureMsgDecrypt(false, smsgStored.sAddrOutbox, &smsgStored.vchMessage[0], &smsgStored.vchMessage[SMSG_HDR_LEN], nPayload, msg) == 0) {
                    UniValue objM(UniValue::VOBJ);
                    objM.push_back(Pair("sent", getTimeString(msg.timestamp, cbuf, sizeof(cbuf))));
                    objM.push_back(Pair("from", msg.sFromAddress));
                    objM.push_back(Pair("to", smsgStored.sAddrTo));
                    objM.push_back(Pair("text", std::string((char*)&msg.vchMessage[0]))); // ugh

                    result.push_back(Pair("message", objM));
                } else {
                    result.push_back(Pair("message", "Could not decrypt."));
                }
                nMessages++;
            }
            delete it;

            snprintf(cbuf, sizeof(cbuf), "%u sent messages shown.", nMessages);
            result.push_back(Pair("result", std::string(cbuf)));
        } else {
            result.push_back(Pair("result", "Unknown Mode."));
            result.push_back(Pair("expected", "[all|clear]."));
        }
    }

    return result;
}


UniValue smsgbuckets(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
            "smsgbuckets [stats|dump]\n"
            "Display some statistics.");

    if (!fSecMsgEnabled)
        throw runtime_error("Secure messaging is disabled.");

    std::string mode = "stats";
    if (params.size() > 0)
        mode = params[0].get_str();

    UniValue result(UniValue::VOBJ);

    char cbuf[256];
    if (mode == "stats") {
        uint32_t nBuckets = 0;
        uint32_t nMessages = 0;
        uint64_t nBytes = 0;
        {
            LOCK(cs_smsg);
            std::map<int64_t, SecMsgBucket>::iterator it;
            it = smsgBuckets.begin();

            for (it = smsgBuckets.begin(); it != smsgBuckets.end(); ++it) {
                std::set<SecMsgToken>& tokenSet = it->second.setTokens;

                std::string sBucket = boost::lexical_cast<std::string>(it->first);
                std::string sFile = sBucket + "_01.dat";

                snprintf(cbuf, sizeof(cbuf), "%zu", tokenSet.size());
                std::string snContents(cbuf);

                std::string sHash = boost::lexical_cast<std::string>(it->second.hash);

                nBuckets++;
                nMessages += tokenSet.size();

                UniValue objM(UniValue::VOBJ);
                objM.push_back(Pair("bucket", sBucket));
                objM.push_back(Pair("time", getTimeString(it->first, cbuf, sizeof(cbuf))));
                objM.push_back(Pair("no. messages", snContents));
                objM.push_back(Pair("hash", sHash));
                objM.push_back(Pair("last changed", getTimeString(it->second.timeChanged, cbuf, sizeof(cbuf))));

                boost::filesystem::path fullPath = GetDataDir() / "smsgStore" / sFile;


                if (!boost::filesystem::exists(fullPath)) {
                    // -- If there is a file for an empty bucket something is wrong.
                    if (tokenSet.size() == 0)
                        objM.push_back(Pair("file size", "Empty bucket."));
                    else
                        objM.push_back(Pair("file size, error", "File not found."));
                } else {
                    try {

                        uint64_t nFBytes = 0;
                        nFBytes = boost::filesystem::file_size(fullPath);
                        nBytes += nFBytes;
                        objM.push_back(Pair("file size", fsReadable(nFBytes)));
                    } catch (const boost::filesystem::filesystem_error& ex) {
                        objM.push_back(Pair("file size, error", ex.what()));
                    }
                }

                result.push_back(Pair("bucket", objM));
            }
        }

        std::string snBuckets = boost::lexical_cast<std::string>(nBuckets);
        std::string snMessages = boost::lexical_cast<std::string>(nMessages);

        UniValue objM(UniValue::VOBJ);
        objM.push_back(Pair("buckets", snBuckets));
        objM.push_back(Pair("messages", snMessages));
        objM.push_back(Pair("size", fsReadable(nBytes)));
        result.push_back(Pair("total", objM));

    } else if (mode == "dump") {
        {
            LOCK(cs_smsg);
            std::map<int64_t, SecMsgBucket>::iterator it;
            it = smsgBuckets.begin();

            for (it = smsgBuckets.begin(); it != smsgBuckets.end(); ++it)
            {
                std::string sFile = boost::lexical_cast<std::string>(it->first) + "_01.dat";

                try {
                    boost::filesystem::path fullPath = GetDataDir() / "smsgStore" / sFile;
                    boost::filesystem::remove(fullPath);
                } catch (const boost::filesystem::filesystem_error& ex) {
                    //objM.push_back(Pair("file size, error", ex.what()));
                    printf("Error removing bucket file %s.\n", ex.what());
                }
            }
            smsgBuckets.clear();
        }

        result.push_back(Pair("result", "Removed all buckets."));

    } else {
        result.push_back(Pair("result", "Unknown Mode."));
        result.push_back(Pair("expected", "[stats|dump]."));
    }

    return result;
}
#endif

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
  //  --------------------- ------------------------  -----------------------  ----------
    { "control",            "getinfo",                &getinfo,                true  }, /* uses wallet if enabled */
    { "util",               "validateaddress",        &validateaddress,        true  }, /* uses wallet if enabled */
    { "util",               "createmultisig",         &createmultisig,         true  },
    { "util",               "verifymessage",          &verifymessage,          true  },
    { "util",               "signmessagewithprivkey", &signmessagewithprivkey, true  },
#ifdef ENABLE_SMESSAGE
    { "smessage",           "smsgenable",             &smsgenable,             false },
    { "smessage",           "smsgdisable",            &smsgdisable,            false },
    { "smessage",           "smsglocalkeys",          &smsglocalkeys,          false },
    { "smessage",           "smsgoptions",            &smsgoptions,            false },
    { "smessage",           "smsgscanchain",          &smsgscanchain,          false },
    { "smessage",           "smsgscanbuckets",        &smsgscanbuckets,        false },
    { "smessage",           "smsgaddkey",             &smsgaddkey,             false },
    { "smessage",           "smsggetpubkey",          &smsggetpubkey,          false },
    { "smessage",           "smsgsend",               &smsgsend,               false },
    { "smessage",           "smsgsendanon",           &smsgsendanon,           false },
    { "smessage",           "smsginbox",              &smsginbox,              false },
    { "smessage",           "smsgoutbox",             &smsgoutbox,             false },
    { "smessage",           "smsgbuckets",            &smsgbuckets,            false },
#endif

    /* Not shown in help */
    { "hidden",             "setmocktime",            &setmocktime,            true  },

#ifdef ENABLE_BITCORE_RPC
    { "util",               "getaddresstxids",        &getaddresstxids,        false },
    { "util",               "getaddressdeltas",       &getaddressdeltas,       false },
    { "util",               "getaddressbalance",      &getaddressbalance,      false },
    { "util",               "getaddressutxos",        &getaddressutxos,        false },
    { "util",               "getaddressmempool",      &getaddressmempool,      false },
    { "util",               "getblockhashes",         &getblockhashes,         false },
    { "util",               "getspentinfo",           &getspentinfo,           false },
#endif
};

void RegisterMiscRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
