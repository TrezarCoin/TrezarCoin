/*
 * Copyright (c) 2016 John Doering <ghostlander@orbitcoin.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "blockexplorer.h"
#include "ui_blockexplorer.h"
#include "clientmodel.h"
#include "base58.h"
#include "uint256.h"
#include "main.h"

#include <QByteArray>
#include <QString>

double GetDifficulty(const CBlockIndex *pindex);

using namespace std;

/* Byte reverser for display purposes */
static void bytes_reverse(uchar *output, const uchar *input, uint size) {
    uint i;

    for(i = 0; i < size; i++)
      output[i] = input[size - 1 - i];
}

static CBlockIndex *getBlockIndex(int nHeight) {
    uint256 hash;

    if((nHeight < 0) || (nHeight > pindexBest->nHeight))
      return(0);

    CBlockIndex *pindex = mapBlockIndex[hashBestChain];
    while(pindex->nHeight > nHeight)
      pindex = pindex->pprev;

    hash = pindex->GetBlockHash();

    if(!mapBlockIndex.count(hash))
      return(0);

    return(mapBlockIndex[hash]);
}

static void setBlockError(Ui::BlockExplorer *ui) {
    QString err = "ERROR!";

    ui->blockTimeData->setText(err);
    ui->hashData->setText(err);
    ui->merkleData->setText(err);
    ui->baseData->setText(err);
}

static void setTxError(Ui::BlockExplorer *ui) {
    QString err = "ERROR!";

    ui->txData->setText(err);
    ui->txTimeData->setText(err);
    ui->valueData->setText(err);
    ui->feeData->setText(err);
    ui->inputData->setText(err);
    ui->outputData->setText(err);
}

BlockExplorer::BlockExplorer(QWidget *parent) :
  QDialog(parent, (Qt::WindowMinMaxButtonsHint | Qt::WindowCloseButtonHint)),
  ui(new Ui::BlockExplorer) {

    ui->setupUi(this);

    setBaseSize(760, 470);

#if (QT_VERSION >= 0x040700)
    ui->txLine->setPlaceholderText(tr("Payment ID"));
#endif

    connect(ui->blockButton, SIGNAL(pressed()), this, SLOT(blockClicked()));
    connect(ui->txButton, SIGNAL(pressed()), this, SLOT(txClicked()));
}

void BlockExplorer::updateExplorer(bool block) {
    uchar data[32];
    uint256 hash;
    uint i, j;

    if(block) {

        int nHeight = ui->numberBox->value();
        if(nHeight > pindexBest->nHeight) {
            ui->numberBox->setValue(pindexBest->nHeight);
            nHeight = pindexBest->nHeight;
        }

        const CBlockIndex *pindex = getBlockIndex(nHeight);
        CBlock block;

        if(!pindex || !block.ReadFromDisk(pindex, true)) {
            setBlockError(ui);
            return;
        }

        ui->blockTimeData->setText(QString("v%1  (%2)  #%3  %4") \
          .arg(QString::number(block.nVersion)) \
          .arg(QString::fromUtf8(DateTimeStrFormat(pindex->nTime).c_str())) \
          .arg(QString::number(nHeight)) \
          .arg(pindex->IsProofOfWork() ? QString("Proof-of-Work") : QString("Proof-of-Stake")));

        hash = pindex->GetBlockHash();
        bytes_reverse((uchar *) &data[0], (uchar *) &hash, 32);
        ui->hashData->setText(QString::fromUtf8(QByteArray((char *) &data[0], 32).toHex()));

        hash = pindex->hashMerkleRoot;
        bytes_reverse((uchar *) &data[0], (uchar *) &hash, 32);
        ui->merkleData->setText(QString::fromUtf8(QByteArray((char *) &data[0], 32).toHex()));

        if(pindex->IsProofOfWork()) {
            hash = block.vtx[0].GetHash();
            ui->baseText->setText(tr("Coin base:"));
            ui->diffText->setText(tr("Difficulty, target, nonce:"));
            ui->diffData->setText(QString("%1  0x%2  0x%3") \
              .arg(QString::number(GetDifficulty(pindex), 'f', 6)) \
              .arg(block.nBits, 8, 16, QLatin1Char('0')) \
              .arg(block.nNonce, 8, 16, QLatin1Char('0')));
        } else {
            hash = block.vtx[1].GetHash();
            ui->baseText->setText(tr("Coin stake:"));
            ui->diffText->setText(tr("Difficulty, target:"));
            ui->diffData->setText(QString("%1  0x%2") \
              .arg(QString::number(GetDifficulty(pindex), 'f', 6)) \
              .arg(block.nBits, 8, 16, QLatin1Char('0')));
        }
        bytes_reverse((uchar *) &data[0], (uchar *) &hash, 32);
        ui->baseData->setText(QString::fromUtf8(QByteArray((char *) &data[0], 32).toHex()));

        ui->coinSupplyData->setText(QString::number((double)pindex->nMoneySupply / (double)COIN, 'f', 6) + " TZC");

        /* List of payments */
        std::string strTx = "";
        for(i = (pindex->IsProofOfStake() ? 1 : 0); i < block.vtx.size(); i++) {
            hash = block.vtx[i].GetHash();

            strTx.append(hash.ToString());
            strTx.append("\n");

            for(j = (block.vtx[i].IsCoinStake() ? 1 : 0); j < block.vtx[i].vout.size(); j++) {
                const CTxOut &txout = block.vtx[i].vout[j];

                CTxDestination address;
                if(!ExtractDestination(txout.scriptPubKey, address))
                  address = CNoDestination();

                strTx.append(CBitcoinAddress(address).ToString());
                strTx.append("  ");
                strTx.append(boost::to_string((double)txout.nValue / (double)COIN));
                strTx.append(" TZC\n");
            }
            strTx.append("\n");
        }
        ui->blockTxData->setText(QString::fromUtf8(strTx.c_str()));

    } else {

        std::string TxID = ui->txLine->text().toUtf8().constData();
        ui->txData->setText(QString::fromUtf8(TxID.c_str()));

        int nHeight = 0;
        int64 nValueIn = 0, nValueOut = 0, nFees = 0;
        uint256 hash;
        hash.SetHex(TxID);

        CTransaction tx;
        uint256 hashBlock = 0;
        if(!GetTransaction(hash, tx, hashBlock, true)) {
            setTxError(ui);
            return;
        }

        CCoinsViewCache &view = *pcoinsTip;
        CCoins coins;

        if(view.GetCoins(hash, coins)) {
            nHeight = coins.nHeight;
            ui->txTimeData->setText(QString("v%1  (%2)  in block #%3") \
              .arg(QString::number(tx.nVersion)) \
              .arg(QString::fromUtf8(DateTimeStrFormat(tx.nTime).c_str()))
              .arg(QString::number(nHeight)));
        } else {
            ui->txTimeData->setText(QString("v%1  (%2)") \
              .arg(QString::number(tx.nVersion)) \
              .arg(QString::fromUtf8(DateTimeStrFormat(tx.nTime).c_str())));
        }

        /* List of inputs */
        std::string strIn = "";
        for(i = 0; i < tx.vin.size(); i++) {
            int64 nCurrentValueIn = 0;
            uint256 hash_in, hashBlock_in = 0;
            const CTxIn &vin = tx.vin[i];

            hash_in = vin.prevout.hash;
            CTransaction txPrev;
            if(!GetTransaction(hash_in, txPrev, hashBlock_in, true))
              continue;

            CTxDestination address;
            if(!ExtractDestination(txPrev.vout[vin.prevout.n].scriptPubKey, address))
              address = CNoDestination();

            nCurrentValueIn = txPrev.vout[vin.prevout.n].nValue;
            nValueIn += nCurrentValueIn;

            strIn.append(hash_in.ToString());
            strIn.append("-");
            strIn.append(boost::to_string(vin.prevout.n));
            strIn.append("\n");
            strIn.append(CBitcoinAddress(address).ToString());
            strIn.append("  ");
            strIn.append(boost::to_string((double)nCurrentValueIn / (double)COIN));
            strIn.append(" TZC\n\n");
        }
        if(!strIn.size()) strIn.append("N/A");
        ui->inputData->setText(QString::fromUtf8(strIn.c_str()));

        /* List of outputs */
        std::string strOut = "";
        for(i = (tx.IsCoinStake() ? 1 : 0); i < tx.vout.size(); i++) {
            int64 nCurrentValueOut = 0;
            const CTxOut &txout = tx.vout[i];

            CTxDestination address;
            if(!ExtractDestination(txout.scriptPubKey, address))
              address = CNoDestination();

            nCurrentValueOut = txout.nValue;
            nValueOut += nCurrentValueOut;

            strOut.append(CBitcoinAddress(address).ToString());
            strOut.append("  ");
            strOut.append(boost::to_string((double)nCurrentValueOut / (double)COIN));
            strOut.append(" TZC\n");
        }
        ui->outputData->setText(QString::fromUtf8(strOut.c_str()));

        ui->valueData->setText(QString::number((double)nValueOut / (double)COIN, 'f', 6) + " TZC");

        if(tx.IsCoinBase() || tx.IsCoinStake()) {
            int64 nSubsidy = 0;

            if(tx.IsCoinBase())
              nSubsidy = GetProofOfWorkReward(nHeight, 0LL);
            else
              nSubsidy = GetProofOfStakeReward(nHeight, 0LL);

            nFees = nValueOut - nValueIn - nSubsidy;
            ui->feeText->setText(QString(tr("Reward + fees:")));
            ui->feeData->setText(QString("%1 + %2 TZC") \
              .arg(QString::number((double)nSubsidy / (double)COIN, 'f', 6)) \
              .arg(QString::number((double)nFees / (double)COIN, 'f', 6)));
        } else {
            nFees = nValueIn - nValueOut;
            ui->feeText->setText(QString(tr("Fee paid:")));
            ui->feeData->setText(QString::number((double)nFees / (double)COIN, 'f', 6) + " TZC");
        }

    }
}

void BlockExplorer::setTxID(const QString &TxID) {
    ui->txLine->setText(TxID);
    ui->txLine->setFocus();
    updateExplorer(false);

    uint256 hash;
    hash.SetHex(TxID.toStdString());

    CTransaction tx;
    uint256 hashBlock = 0;
    if(GetTransaction(hash, tx, hashBlock, true)) {
        CBlockIndex *pindex = mapBlockIndex[hashBlock];
        if(!pindex)
          ui->numberBox->setValue(nBestHeight);
        else
          ui->numberBox->setValue(pindex->nHeight);
        updateExplorer(true);
    }
}

void BlockExplorer::txClicked() {
    updateExplorer(false);
}

void BlockExplorer::blockClicked() {
    updateExplorer(true);
}

void BlockExplorer::setClientModel(ClientModel *model) {
    this->clientModel = model;
}

BlockExplorer::~BlockExplorer() {
    delete(ui);
}

void BlockExplorer::gotoBlockExplorer(QString TxID) {

    if(!TxID.isEmpty()) setTxID(TxID);

    show();
}
