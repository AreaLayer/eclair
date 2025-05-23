/*
 * Copyright 2019 ACINQ SAS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package fr.acinq.eclair.transactions

import fr.acinq.bitcoin.SigHash._
import fr.acinq.bitcoin.scalacompat.Crypto._
import fr.acinq.bitcoin.scalacompat.{Btc, ByteVector32, Crypto, MilliBtc, MilliBtcDouble, Musig2, OP_2, OP_CHECKMULTISIG, OP_PUSHDATA, OP_RETURN, OutPoint, Protocol, Satoshi, SatoshiLong, Script, ScriptWitness, Transaction, TxId, TxIn, TxOut, millibtc2satoshi}
import fr.acinq.bitcoin.{ScriptFlags, ScriptTree, SigHash, SigVersion}
import fr.acinq.eclair.TestUtils.randomTxId
import fr.acinq.eclair._
import fr.acinq.eclair.blockchain.fee.{ConfirmationTarget, FeeratePerKw}
import fr.acinq.eclair.channel.Helpers.Funding
import fr.acinq.eclair.crypto.keymanager.{LocalCommitmentKeys, RemoteCommitmentKeys}
import fr.acinq.eclair.transactions.CommitmentOutput.OutHtlc
import fr.acinq.eclair.transactions.Scripts._
import fr.acinq.eclair.transactions.Transactions.AnchorOutputsCommitmentFormat.anchorAmount
import fr.acinq.eclair.transactions.Transactions._
import fr.acinq.eclair.wire.protocol.UpdateAddHtlc
import grizzled.slf4j.Logging
import org.scalatest.funsuite.AnyFunSuite
import scodec.bits._

import java.nio.ByteOrder
import scala.io.Source
import scala.util.{Random, Try}

/**
 * Created by PM on 16/12/2016.
 */

class TransactionsSpec extends AnyFunSuite with Logging {
  private val localFundingPriv = randomKey()
  private val remoteFundingPriv = randomKey()
  private val localRevocationPriv = randomKey()
  private val localPaymentPriv = randomKey()
  private val localPaymentBasePoint = randomKey().publicKey
  private val localDelayedPaymentPriv = randomKey()
  private val remotePaymentPriv = randomKey()
  private val localHtlcPriv = randomKey()
  private val remoteHtlcPriv = randomKey()
  // Keys used by the local node to spend outputs of its local commitment.
  private val localKeys = LocalCommitmentKeys(
    ourDelayedPaymentKey = localDelayedPaymentPriv,
    theirPaymentPublicKey = remotePaymentPriv.publicKey,
    ourPaymentBasePoint = localPaymentBasePoint,
    ourHtlcKey = localHtlcPriv,
    theirHtlcPublicKey = remoteHtlcPriv.publicKey,
    revocationPublicKey = localRevocationPriv.publicKey,
  )
  // Keys used by the remote node to spend outputs of our local commitment.
  private val remoteKeys = RemoteCommitmentKeys(
    ourPaymentKey = Right(remotePaymentPriv),
    theirDelayedPaymentPublicKey = localDelayedPaymentPriv.publicKey,
    ourPaymentBasePoint = localPaymentBasePoint,
    ourHtlcKey = remoteHtlcPriv,
    theirHtlcPublicKey = localHtlcPriv.publicKey,
    revocationPublicKey = localRevocationPriv.publicKey,
  )
  private val toLocalDelay = CltvExpiryDelta(144)
  private val localDustLimit = Satoshi(546)
  private val feeratePerKw = FeeratePerKw(22000 sat)

  test("extract csv and cltv timeouts") {
    val parentTxId1 = randomTxId()
    val parentTxId2 = randomTxId()
    val parentTxId3 = randomTxId()
    val txIn = Seq(
      TxIn(OutPoint(parentTxId1, 3), Nil, 3),
      TxIn(OutPoint(parentTxId2, 1), Nil, 4),
      TxIn(OutPoint(parentTxId3, 0), Nil, 5),
      TxIn(OutPoint(randomTxId(), 4), Nil, 0),
      TxIn(OutPoint(parentTxId1, 2), Nil, 5),
    )
    val tx = Transaction(2, txIn, Nil, 10)
    val expected = Map(
      parentTxId1 -> 5,
      parentTxId2 -> 4,
      parentTxId3 -> 5,
    )
    assert(expected == Scripts.csvTimeouts(tx))
    assert(BlockHeight(10) == Scripts.cltvTimeout(tx))
  }

  test("encode/decode sequence and lockTime (one example)") {
    val txnumber = 0x11F71FB268DL

    val (sequence, locktime) = encodeTxNumber(txnumber)
    assert(sequence == 0x80011F71L)
    assert(locktime == 0x20FB268DL)

    val txnumber1 = decodeTxNumber(sequence, locktime)
    assert(txnumber == txnumber1)
  }

  test("reconstruct txNumber from sequence and lockTime") {
    for (_ <- 0 until 1000) {
      val txnumber = Random.nextLong() & 0xffffffffffffL
      val (sequence, locktime) = encodeTxNumber(txnumber)
      val txnumber1 = decodeTxNumber(sequence, locktime)
      assert(txnumber == txnumber1)
    }
  }

  test("compute fees") {
    // see BOLT #3 specs
    val htlcs = Set[DirectedHtlc](
      OutgoingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 0, 5000000 msat, ByteVector32.Zeroes, CltvExpiry(552), TestConstants.emptyOnionPacket, None, 1.0, None)),
      OutgoingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 0, 1000000 msat, ByteVector32.Zeroes, CltvExpiry(553), TestConstants.emptyOnionPacket, None, 1.0, None)),
      IncomingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 0, 7000000 msat, ByteVector32.Zeroes, CltvExpiry(550), TestConstants.emptyOnionPacket, None, 1.0, None)),
      IncomingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 0, 800000 msat, ByteVector32.Zeroes, CltvExpiry(551), TestConstants.emptyOnionPacket, None, 1.0, None))
    )
    val spec = CommitmentSpec(htlcs, FeeratePerKw(5000 sat), toLocal = 0 msat, toRemote = 0 msat)
    val fee = commitTxFeeMsat(546 sat, spec, DefaultCommitmentFormat)
    assert(fee == 5340000.msat)
  }

  test("pre-compute p2wpkh transaction weight") {
    // ECDSA signatures are usually between at 71 and 73 bytes.
    val dummySig = ByteVector.fill(73)(0)
    val dummyTx = Transaction(
      version = 2,
      txIn = Seq(TxIn(OutPoint(randomTxId(), 5), ByteVector.empty, 0, Script.witnessPay2wpkh(randomKey().publicKey, dummySig))),
      txOut = Seq(TxOut(250_000 sat, Script.pay2wpkh(randomKey().publicKey))),
      lockTime = 0
    )
    assert(dummyTx.weight() == 439)
    val p2wpkhInput = TxIn(OutPoint(randomTxId(), 1), ByteVector.empty, 0, Script.witnessPay2wpkh(randomKey().publicKey, dummySig))
    assert(dummyTx.copy(txIn = dummyTx.txIn ++ Seq(p2wpkhInput)).weight() - dummyTx.weight() == p2wpkhInputWeight)
    val p2wpkhOutput = TxOut(100_000 sat, Script.pay2wpkh(randomKey().publicKey))
    assert(dummyTx.copy(txOut = dummyTx.txOut ++ Seq(p2wpkhOutput)).weight() - dummyTx.weight() == p2wpkhOutputWeight)
  }

  private def checkExpectedWeight(actual: Int, expected: Int): Unit = {
    // ECDSA signatures are der-encoded, which creates some variability in signature size compared to the baseline.
    assert(actual <= expected + 2)
    assert(actual >= expected - 2)
  }

  test("generate valid commitment with some outputs that don't materialize (default commitment format)") {
    val spec = CommitmentSpec(htlcs = Set.empty, commitTxFeerate = feeratePerKw, toLocal = 400.millibtc.toMilliSatoshi, toRemote = 300.millibtc.toMilliSatoshi)
    val commitFee = commitTxTotalCost(localDustLimit, spec, DefaultCommitmentFormat)
    val belowDust = (localDustLimit * 0.9).toMilliSatoshi
    val belowDustWithFee = (localDustLimit + commitFee * 0.9).toMilliSatoshi

    {
      val toRemoteFundeeBelowDust = spec.copy(toRemote = belowDust)
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = true, localDustLimit, toLocalDelay, toRemoteFundeeBelowDust, DefaultCommitmentFormat)
      assert(outputs.forall(_.isInstanceOf[CommitmentOutput.ToLocal]))
      assert(outputs.head.txOut.amount.toMilliSatoshi == toRemoteFundeeBelowDust.toLocal - commitFee)
    }
    {
      val toLocalFunderBelowDust = spec.copy(toLocal = belowDustWithFee)
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = true, localDustLimit, toLocalDelay, toLocalFunderBelowDust, DefaultCommitmentFormat)
      assert(outputs.forall(_.isInstanceOf[CommitmentOutput.ToRemote]))
      assert(outputs.head.txOut.amount.toMilliSatoshi == toLocalFunderBelowDust.toRemote)
    }
    {
      val toRemoteFunderBelowDust = spec.copy(toRemote = belowDustWithFee)
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = false, localDustLimit, toLocalDelay, toRemoteFunderBelowDust, DefaultCommitmentFormat)
      assert(outputs.forall(_.isInstanceOf[CommitmentOutput.ToLocal]))
      assert(outputs.head.txOut.amount.toMilliSatoshi == toRemoteFunderBelowDust.toLocal)
    }
    {
      val toLocalFundeeBelowDust = spec.copy(toLocal = belowDust)
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = false, localDustLimit, toLocalDelay, toLocalFundeeBelowDust, DefaultCommitmentFormat)
      assert(outputs.forall(_.isInstanceOf[CommitmentOutput.ToRemote]))
      assert(outputs.head.txOut.amount.toMilliSatoshi == toLocalFundeeBelowDust.toRemote - commitFee)
    }
    {
      val allBelowDust = spec.copy(toLocal = belowDust, toRemote = belowDust)
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = true, localDustLimit, toLocalDelay, allBelowDust, DefaultCommitmentFormat)
      assert(outputs.isEmpty)
    }
  }

  test("generate valid commitment and htlc transactions (default commitment format)") {
    val finalPubKeyScript = Script.write(Script.pay2wpkh(PrivateKey(randomBytes32()).publicKey))
    val commitInput = Funding.makeFundingInputInfo(randomTxId(), 0, Btc(1), localFundingPriv.publicKey, remoteFundingPriv.publicKey, DefaultCommitmentFormat)

    // htlc1 and htlc2 are regular IN/OUT htlcs
    val paymentPreimage1 = randomBytes32()
    val htlc1 = UpdateAddHtlc(ByteVector32.Zeroes, 0, MilliBtc(100).toMilliSatoshi, sha256(paymentPreimage1), CltvExpiry(300), TestConstants.emptyOnionPacket, None, 1.0, None)
    val paymentPreimage2 = randomBytes32()
    val htlc2 = UpdateAddHtlc(ByteVector32.Zeroes, 1, MilliBtc(200).toMilliSatoshi, sha256(paymentPreimage2), CltvExpiry(310), TestConstants.emptyOnionPacket, None, 1.0, None)
    // htlc3 and htlc4 are dust IN/OUT htlcs, with an amount large enough to be included in the commit tx, but too small to be claimed at 2nd stage
    val paymentPreimage3 = randomBytes32()
    val htlc3 = UpdateAddHtlc(ByteVector32.Zeroes, 2, (localDustLimit + weight2fee(feeratePerKw, DefaultCommitmentFormat.htlcTimeoutWeight)).toMilliSatoshi, sha256(paymentPreimage3), CltvExpiry(295), TestConstants.emptyOnionPacket, None, 1.0, None)
    val paymentPreimage4 = randomBytes32()
    val htlc4 = UpdateAddHtlc(ByteVector32.Zeroes, 3, (localDustLimit + weight2fee(feeratePerKw, DefaultCommitmentFormat.htlcSuccessWeight)).toMilliSatoshi, sha256(paymentPreimage4), CltvExpiry(300), TestConstants.emptyOnionPacket, None, 1.0, None)
    // htlc5 and htlc6 are dust IN/OUT htlcs
    val htlc5 = UpdateAddHtlc(ByteVector32.Zeroes, 4, (localDustLimit * 0.9).toMilliSatoshi, sha256(randomBytes32()), CltvExpiry(295), TestConstants.emptyOnionPacket, None, 1.0, None)
    val htlc6 = UpdateAddHtlc(ByteVector32.Zeroes, 5, (localDustLimit * 0.9).toMilliSatoshi, sha256(randomBytes32()), CltvExpiry(305), TestConstants.emptyOnionPacket, None, 1.0, None)
    val spec = CommitmentSpec(
      htlcs = Set(
        OutgoingHtlc(htlc1),
        IncomingHtlc(htlc2),
        OutgoingHtlc(htlc3),
        IncomingHtlc(htlc4),
        OutgoingHtlc(htlc5),
        IncomingHtlc(htlc6)
      ),
      commitTxFeerate = feeratePerKw,
      toLocal = 400.millibtc.toMilliSatoshi,
      toRemote = 300.millibtc.toMilliSatoshi)

    val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = true, localDustLimit, toLocalDelay, spec, DefaultCommitmentFormat)

    val commitTxNumber = 0x404142434445L
    val commitTx = {
      val txInfo = makeCommitTx(commitInput, commitTxNumber, localPaymentPriv.publicKey, remotePaymentPriv.publicKey, localIsChannelOpener = true, outputs)
      val localSig = txInfo.sign(localFundingPriv, remoteFundingPriv.publicKey)
      val remoteSig = txInfo.sign(remoteFundingPriv, localFundingPriv.publicKey)
      txInfo.aggregateSigs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localSig, remoteSig)
    }

    {
      assert(getCommitTxNumber(commitTx, localIsChannelOpener = true, localPaymentPriv.publicKey, remotePaymentPriv.publicKey) == commitTxNumber)
      val hash = Crypto.sha256(localPaymentPriv.publicKey.value ++ remotePaymentPriv.publicKey.value)
      val num = Protocol.uint64(hash.takeRight(8).toArray, ByteOrder.BIG_ENDIAN) & 0xffffffffffffL
      val check = ((commitTx.txIn.head.sequence & 0xffffff) << 24) | (commitTx.lockTime & 0xffffff)
      assert((check ^ num) == commitTxNumber)
    }

    val htlcTxs = makeHtlcTxs(commitTx, outputs, DefaultCommitmentFormat)
    assert(htlcTxs.length == 4)
    val expiries = htlcTxs.map(tx => tx.htlcId -> tx.htlcExpiry.toLong).toMap
    assert(expiries == Map(0 -> 300, 1 -> 310, 2 -> 295, 3 -> 300))
    val htlcSuccessTxs = htlcTxs.collect { case tx: HtlcSuccessTx => tx }
    val htlcTimeoutTxs = htlcTxs.collect { case tx: HtlcTimeoutTx => tx }
    assert(htlcTimeoutTxs.size == 2) // htlc1 and htlc3
    assert(htlcTimeoutTxs.map(_.htlcId).toSet == Set(0, 2))
    assert(htlcSuccessTxs.size == 2) // htlc2 and htlc4
    assert(htlcSuccessTxs.map(_.htlcId).toSet == Set(1, 3))

    {
      // either party spends local->remote htlc output with htlc timeout tx
      for (htlcTimeoutTx <- htlcTimeoutTxs) {
        val localSig = htlcTimeoutTx.sign(localKeys, DefaultCommitmentFormat, Map.empty)
        val remoteSig = htlcTimeoutTx.sign(remoteKeys, DefaultCommitmentFormat)
        val signed = htlcTimeoutTx.addSigs(localKeys, localSig, remoteSig, DefaultCommitmentFormat)
        assert(signed.validate(Map.empty))
      }
    }
    {
      // local spends delayed output of htlc1 timeout tx
      val Right(htlcDelayed) = HtlcDelayedTx.createSignedTx(localKeys, htlcTimeoutTxs(1).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, DefaultCommitmentFormat)
      checkExpectedWeight(htlcDelayed.tx.weight(), DefaultCommitmentFormat.htlcDelayedWeight)
      assert(htlcDelayed.validate(Map.empty))
      // local can't claim delayed output of htlc3 timeout tx because it is below the dust limit
      val htlcDelayed1 = HtlcDelayedTx.createSignedTx(localKeys, htlcTimeoutTxs(0).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, DefaultCommitmentFormat)
      assert(htlcDelayed1 == Left(AmountBelowDustLimit))
    }
    {
      // remote spends local->remote htlc1/htlc3 output directly in case of success
      for ((htlc, paymentPreimage) <- (htlc1, paymentPreimage1) :: (htlc3, paymentPreimage3) :: Nil) {
        val Right(claimHtlcSuccessTx) = ClaimHtlcSuccessTx.createSignedTx(remoteKeys, commitTx, localDustLimit, outputs, finalPubKeyScript, htlc, paymentPreimage, feeratePerKw, DefaultCommitmentFormat)
        checkExpectedWeight(claimHtlcSuccessTx.tx.weight(), DefaultCommitmentFormat.claimHtlcSuccessWeight)
        assert(claimHtlcSuccessTx.validate(Map.empty))
      }
    }
    {
      // local spends remote->local htlc2/htlc4 output with htlc success tx using payment preimage
      for ((htlcSuccessTx, paymentPreimage) <- (htlcSuccessTxs(1), paymentPreimage2) :: (htlcSuccessTxs(0), paymentPreimage4) :: Nil) {
        val localSig = htlcSuccessTx.sign(localKeys, DefaultCommitmentFormat, Map.empty)
        val remoteSig = htlcSuccessTx.sign(remoteKeys, DefaultCommitmentFormat)
        val signedTx = htlcSuccessTx.addSigs(localKeys, localSig, remoteSig, paymentPreimage, DefaultCommitmentFormat)
        assert(signedTx.validate(Map.empty))
        // check remote sig
        assert(htlcSuccessTx.checkRemoteSig(localKeys, remoteSig, DefaultCommitmentFormat))
      }
    }
    {
      // local spends delayed output of htlc2 success tx
      val Right(htlcDelayed) = HtlcDelayedTx.createSignedTx(localKeys, htlcSuccessTxs(1).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, DefaultCommitmentFormat)
      checkExpectedWeight(htlcDelayed.tx.weight(), DefaultCommitmentFormat.htlcDelayedWeight)
      assert(htlcDelayed.validate(Map.empty))
      // local can't claim delayed output of htlc4 success tx because it is below the dust limit
      val htlcDelayed1 = HtlcDelayedTx.createSignedTx(localKeys, htlcSuccessTxs(0).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, DefaultCommitmentFormat)
      assert(htlcDelayed1 == Left(AmountBelowDustLimit))
    }
    {
      // local spends main delayed output
      val Right(claimMainOutputTx) = ClaimLocalDelayedOutputTx.createSignedTx(localKeys, commitTx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, DefaultCommitmentFormat)
      checkExpectedWeight(claimMainOutputTx.tx.weight(), DefaultCommitmentFormat.toLocalDelayedWeight)
      assert(claimMainOutputTx.validate(Map.empty))
    }
    {
      // remote spends main output
      val Right(claimP2WPKHOutputTx) = ClaimP2WPKHOutputTx.createSignedTx(remoteKeys, commitTx, localDustLimit, finalPubKeyScript, feeratePerKw, DefaultCommitmentFormat)
      checkExpectedWeight(claimP2WPKHOutputTx.tx.weight(), DefaultCommitmentFormat.toRemoteWeight)
      assert(claimP2WPKHOutputTx.validate(Map.empty))
    }
    {
      // remote spends remote->local htlc output directly in case of timeout
      val Right(claimHtlcTimeoutTx) = ClaimHtlcTimeoutTx.createSignedTx(remoteKeys, commitTx, localDustLimit, outputs, finalPubKeyScript, htlc2, feeratePerKw, DefaultCommitmentFormat)
      checkExpectedWeight(claimHtlcTimeoutTx.tx.weight(), DefaultCommitmentFormat.claimHtlcTimeoutWeight)
      assert(claimHtlcTimeoutTx.validate(Map.empty))
    }
    {
      // remote spends local main delayed output with revocation key
      val Right(mainPenaltyTx) = MainPenaltyTx.createSignedTx(remoteKeys, localRevocationPriv, commitTx, localDustLimit, finalPubKeyScript, toLocalDelay, feeratePerKw, DefaultCommitmentFormat)
      checkExpectedWeight(mainPenaltyTx.tx.weight(), DefaultCommitmentFormat.mainPenaltyWeight)
      assert(mainPenaltyTx.validate(Map.empty))
    }
    {
      // remote spends HTLC outputs with revocation key
      val htlcs = spec.htlcs.map(_.add).map(add => (add.paymentHash, add.cltvExpiry)).toSeq
      val htlcPenaltyTxs = HtlcPenaltyTx.createSignedTxs(remoteKeys, localRevocationPriv, commitTx, htlcs, localDustLimit, finalPubKeyScript, feeratePerKw, DefaultCommitmentFormat)
      assert(htlcPenaltyTxs.collect { case Right(htlcPenaltyTx) => htlcPenaltyTx.paymentHash }.toSet == Set(htlc1, htlc2, htlc3, htlc4).map(_.paymentHash)) // the first 4 htlcs are above the dust limit
      htlcPenaltyTxs.collect {
        case Right(htlcPenaltyTx) =>
          val expectedWeight = if (Set(htlc1, htlc3).map(_.paymentHash).contains(htlcPenaltyTx.paymentHash)) {
            DefaultCommitmentFormat.htlcOfferedPenaltyWeight
          } else {
            DefaultCommitmentFormat.htlcReceivedPenaltyWeight
          }
          checkExpectedWeight(htlcPenaltyTx.tx.weight(), expectedWeight)
          assert(htlcPenaltyTx.validate(Map.empty))
      }
    }
    {
      // remote spends htlc1's htlc-timeout tx with revocation key
      val Seq(Right(claimHtlcDelayedPenaltyTx)) = ClaimHtlcDelayedOutputPenaltyTx.createSignedTxs(remoteKeys, localRevocationPriv, htlcTimeoutTxs(1).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, DefaultCommitmentFormat)
      checkExpectedWeight(claimHtlcDelayedPenaltyTx.tx.weight(), DefaultCommitmentFormat.claimHtlcPenaltyWeight)
      assert(claimHtlcDelayedPenaltyTx.validate(Map.empty))
      // remote can't claim revoked output of htlc3's htlc-timeout tx because it is below the dust limit
      val claimHtlcDelayedPenaltyTx1 = ClaimHtlcDelayedOutputPenaltyTx.createSignedTxs(remoteKeys, localRevocationPriv, htlcTimeoutTxs(0).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, DefaultCommitmentFormat)
      assert(claimHtlcDelayedPenaltyTx1 == Seq(Left(AmountBelowDustLimit)))
    }
    {
      // remote spends htlc2's htlc-success tx with revocation key
      val Seq(Right(claimHtlcDelayedPenaltyTx)) = ClaimHtlcDelayedOutputPenaltyTx.createSignedTxs(remoteKeys, localRevocationPriv, htlcSuccessTxs(1).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, DefaultCommitmentFormat)
      checkExpectedWeight(claimHtlcDelayedPenaltyTx.tx.weight(), DefaultCommitmentFormat.claimHtlcPenaltyWeight)
      assert(claimHtlcDelayedPenaltyTx.validate(Map.empty))
      // remote can't claim revoked output of htlc4's htlc-success tx because it is below the dust limit
      val claimHtlcDelayedPenaltyTx1 = ClaimHtlcDelayedOutputPenaltyTx.createSignedTxs(remoteKeys, localRevocationPriv, htlcSuccessTxs(0).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, DefaultCommitmentFormat)
      assert(claimHtlcDelayedPenaltyTx1 == Seq(Left(AmountBelowDustLimit)))
    }
  }

  test("generate valid commitment with some outputs that don't materialize (anchor outputs)") {
    val spec = CommitmentSpec(htlcs = Set.empty, commitTxFeerate = feeratePerKw, toLocal = 400.millibtc.toMilliSatoshi, toRemote = 300.millibtc.toMilliSatoshi)
    val commitFeeAndAnchorCost = commitTxTotalCost(localDustLimit, spec, UnsafeLegacyAnchorOutputsCommitmentFormat)
    val belowDust = (localDustLimit * 0.9).toMilliSatoshi
    val belowDustWithFeeAndAnchors = (localDustLimit + commitFeeAndAnchorCost * 0.9).toMilliSatoshi

    {
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = true, localDustLimit, toLocalDelay, spec, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(outputs.size == 4)
      assert(outputs.find(_.isInstanceOf[CommitmentOutput.ToLocalAnchor]).get.txOut.amount == anchorAmount)
      assert(outputs.find(_.isInstanceOf[CommitmentOutput.ToRemoteAnchor]).get.txOut.amount == anchorAmount)
      assert(outputs.find(_.isInstanceOf[CommitmentOutput.ToLocal]).get.txOut.amount.toMilliSatoshi == spec.toLocal - commitFeeAndAnchorCost)
      assert(outputs.find(_.isInstanceOf[CommitmentOutput.ToRemote]).get.txOut.amount.toMilliSatoshi == spec.toRemote)
    }
    {
      val toRemoteFundeeBelowDust = spec.copy(toRemote = belowDust)
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = true, localDustLimit, toLocalDelay, toRemoteFundeeBelowDust, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(outputs.size == 2)
      assert(outputs.find(_.isInstanceOf[CommitmentOutput.ToLocalAnchor]).get.txOut.amount == anchorAmount)
      assert(outputs.find(_.isInstanceOf[CommitmentOutput.ToLocal]).get.txOut.amount.toMilliSatoshi == spec.toLocal - commitFeeAndAnchorCost)
    }
    {
      val toLocalFunderBelowDust = spec.copy(toLocal = belowDustWithFeeAndAnchors)
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = true, localDustLimit, toLocalDelay, toLocalFunderBelowDust, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(outputs.size == 2)
      assert(outputs.find(_.isInstanceOf[CommitmentOutput.ToRemoteAnchor]).get.txOut.amount == anchorAmount)
      assert(outputs.find(_.isInstanceOf[CommitmentOutput.ToRemote]).get.txOut.amount.toMilliSatoshi == spec.toRemote)
    }
    {
      val toRemoteFunderBelowDust = spec.copy(toRemote = belowDustWithFeeAndAnchors)
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = false, localDustLimit, toLocalDelay, toRemoteFunderBelowDust, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(outputs.size == 2)
      assert(outputs.find(_.isInstanceOf[CommitmentOutput.ToLocalAnchor]).get.txOut.amount == anchorAmount)
      assert(outputs.find(_.isInstanceOf[CommitmentOutput.ToLocal]).get.txOut.amount.toMilliSatoshi == spec.toLocal)
    }
    {
      val toLocalFundeeBelowDust = spec.copy(toLocal = belowDust)
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = false, localDustLimit, toLocalDelay, toLocalFundeeBelowDust, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(outputs.size == 2)
      assert(outputs.find(_.isInstanceOf[CommitmentOutput.ToRemoteAnchor]).get.txOut.amount == anchorAmount)
      assert(outputs.find(_.isInstanceOf[CommitmentOutput.ToRemote]).get.txOut.amount.toMilliSatoshi == spec.toRemote - commitFeeAndAnchorCost)
    }
    {
      val allBelowDust = spec.copy(toLocal = belowDust, toRemote = belowDust)
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = true, localDustLimit, toLocalDelay, allBelowDust, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(outputs.isEmpty)
    }
  }

  test("generate valid commitment and htlc transactions (anchor outputs)") {
    val walletPriv = randomKey()
    val walletPub = walletPriv.publicKey
    val finalPubKeyScript = Script.write(Script.pay2wpkh(walletPub))
    val commitInput = Funding.makeFundingInputInfo(randomTxId(), 0, Btc(1), localFundingPriv.publicKey, remoteFundingPriv.publicKey, UnsafeLegacyAnchorOutputsCommitmentFormat)

    // htlc1, htlc2a and htlc2b are regular IN/OUT htlcs
    val paymentPreimage1 = randomBytes32()
    val htlc1 = UpdateAddHtlc(ByteVector32.Zeroes, 0, MilliBtc(100).toMilliSatoshi, sha256(paymentPreimage1), CltvExpiry(300), TestConstants.emptyOnionPacket, None, 1.0, None)
    val paymentPreimage2 = randomBytes32()
    val htlc2a = UpdateAddHtlc(ByteVector32.Zeroes, 1, MilliBtc(50).toMilliSatoshi, sha256(paymentPreimage2), CltvExpiry(310), TestConstants.emptyOnionPacket, None, 1.0, None)
    val htlc2b = UpdateAddHtlc(ByteVector32.Zeroes, 2, MilliBtc(150).toMilliSatoshi, sha256(paymentPreimage2), CltvExpiry(310), TestConstants.emptyOnionPacket, None, 1.0, None)
    // htlc3 and htlc4 are dust IN/OUT htlcs, with an amount large enough to be included in the commit tx, but too small to be claimed at 2nd stage
    val paymentPreimage3 = randomBytes32()
    val htlc3 = UpdateAddHtlc(ByteVector32.Zeroes, 3, (localDustLimit + weight2fee(feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat.htlcTimeoutWeight)).toMilliSatoshi, sha256(paymentPreimage3), CltvExpiry(295), TestConstants.emptyOnionPacket, None, 1.0, None)
    val paymentPreimage4 = randomBytes32()
    val htlc4 = UpdateAddHtlc(ByteVector32.Zeroes, 4, (localDustLimit + weight2fee(feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat.htlcSuccessWeight)).toMilliSatoshi, sha256(paymentPreimage4), CltvExpiry(300), TestConstants.emptyOnionPacket, None, 1.0, None)
    // htlc5 and htlc6 are dust IN/OUT htlcs
    val htlc5 = UpdateAddHtlc(ByteVector32.Zeroes, 5, (localDustLimit * 0.9).toMilliSatoshi, sha256(randomBytes32()), CltvExpiry(295), TestConstants.emptyOnionPacket, None, 1.0, None)
    val htlc6 = UpdateAddHtlc(ByteVector32.Zeroes, 6, (localDustLimit * 0.9).toMilliSatoshi, sha256(randomBytes32()), CltvExpiry(305), TestConstants.emptyOnionPacket, None, 1.0, None)
    // htlc7 and htlc8 are at the dust limit when we ignore 2nd-stage tx fees
    val htlc7 = UpdateAddHtlc(ByteVector32.Zeroes, 7, localDustLimit.toMilliSatoshi, sha256(randomBytes32()), CltvExpiry(300), TestConstants.emptyOnionPacket, None, 1.0, None)
    val htlc8 = UpdateAddHtlc(ByteVector32.Zeroes, 8, localDustLimit.toMilliSatoshi, sha256(randomBytes32()), CltvExpiry(302), TestConstants.emptyOnionPacket, None, 1.0, None)
    val spec = CommitmentSpec(
      htlcs = Set(
        OutgoingHtlc(htlc1),
        IncomingHtlc(htlc2a),
        IncomingHtlc(htlc2b),
        OutgoingHtlc(htlc3),
        IncomingHtlc(htlc4),
        OutgoingHtlc(htlc5),
        IncomingHtlc(htlc6),
        OutgoingHtlc(htlc7),
        IncomingHtlc(htlc8),
      ),
      commitTxFeerate = feeratePerKw,
      toLocal = 400.millibtc.toMilliSatoshi,
      toRemote = 300.millibtc.toMilliSatoshi)

    val (commitTx, commitTxOutputs, htlcTimeoutTxs, htlcSuccessTxs) = {
      val commitTxNumber = 0x404142434445L
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = true, localDustLimit, toLocalDelay, spec, UnsafeLegacyAnchorOutputsCommitmentFormat)
      val txInfo = makeCommitTx(commitInput, commitTxNumber, localPaymentPriv.publicKey, remotePaymentPriv.publicKey, localIsChannelOpener = true, outputs)
      val localSig = txInfo.sign(localFundingPriv, remoteFundingPriv.publicKey)
      val remoteSig = txInfo.sign(remotePaymentPriv, localFundingPriv.publicKey)
      val commitTx = txInfo.aggregateSigs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localSig, remoteSig)

      val htlcTxs = makeHtlcTxs(commitTx, outputs, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(htlcTxs.length == 5)
      val expiries = htlcTxs.map(tx => tx.htlcId -> tx.htlcExpiry.toLong).toMap
      assert(expiries == Map(0 -> 300, 1 -> 310, 2 -> 310, 3 -> 295, 4 -> 300))
      val htlcSuccessTxs = htlcTxs.collect { case tx: HtlcSuccessTx => tx }
      val htlcTimeoutTxs = htlcTxs.collect { case tx: HtlcTimeoutTx => tx }
      assert(htlcTimeoutTxs.size == 2) // htlc1 and htlc3
      assert(htlcTimeoutTxs.map(_.htlcId).toSet == Set(0, 3))
      assert(htlcSuccessTxs.size == 3) // htlc2a, htlc2b and htlc4
      assert(htlcSuccessTxs.map(_.htlcId).toSet == Set(1, 2, 4))

      val zeroFeeOutputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = true, localDustLimit, toLocalDelay, spec, ZeroFeeHtlcTxAnchorOutputsCommitmentFormat)
      val zeroFeeCommitTx = makeCommitTx(commitInput, commitTxNumber, localPaymentPriv.publicKey, remotePaymentPriv.publicKey, localIsChannelOpener = true, zeroFeeOutputs)
      val zeroFeeHtlcTxs = makeHtlcTxs(zeroFeeCommitTx.tx, zeroFeeOutputs, ZeroFeeHtlcTxAnchorOutputsCommitmentFormat)
      assert(zeroFeeHtlcTxs.length == 7)
      val zeroFeeExpiries = zeroFeeHtlcTxs.map(tx => tx.htlcId -> tx.htlcExpiry.toLong).toMap
      assert(zeroFeeExpiries == Map(0 -> 300, 1 -> 310, 2 -> 310, 3 -> 295, 4 -> 300, 7 -> 300, 8 -> 302))
      val zeroFeeHtlcSuccessTxs = zeroFeeHtlcTxs.collect { case tx: HtlcSuccessTx => tx }
      val zeroFeeHtlcTimeoutTxs = zeroFeeHtlcTxs.collect { case tx: HtlcTimeoutTx => tx }
      zeroFeeHtlcSuccessTxs.foreach(tx => assert(tx.fee == 0.sat))
      zeroFeeHtlcTimeoutTxs.foreach(tx => assert(tx.fee == 0.sat))
      assert(zeroFeeHtlcTimeoutTxs.size == 3) // htlc1, htlc3 and htlc7
      assert(zeroFeeHtlcTimeoutTxs.map(_.htlcId).toSet == Set(0, 3, 7))
      assert(zeroFeeHtlcSuccessTxs.size == 4) // htlc2a, htlc2b, htlc4 and htlc8
      assert(zeroFeeHtlcSuccessTxs.map(_.htlcId).toSet == Set(1, 2, 4, 8))

      (commitTx, outputs, htlcTimeoutTxs, htlcSuccessTxs)
    }

    {
      // local spends main delayed output
      val Right(claimMainOutputTx) = ClaimLocalDelayedOutputTx.createSignedTx(localKeys, commitTx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      checkExpectedWeight(claimMainOutputTx.tx.weight(), UnsafeLegacyAnchorOutputsCommitmentFormat.toLocalDelayedWeight)
      assert(claimMainOutputTx.validate(Map.empty))
    }
    {
      // remote cannot spend main output with default commitment format
      val Left(failure) = ClaimP2WPKHOutputTx.createSignedTx(remoteKeys, commitTx, localDustLimit, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(failure == OutputNotFound)
    }
    {
      // remote spends main delayed output
      val Right(claimRemoteDelayedOutputTx) = ClaimRemoteDelayedOutputTx.createSignedTx(remoteKeys, commitTx, localDustLimit, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      checkExpectedWeight(claimRemoteDelayedOutputTx.tx.weight(), UnsafeLegacyAnchorOutputsCommitmentFormat.toRemoteWeight)
      assert(claimRemoteDelayedOutputTx.validate(Map.empty))
    }
    {
      // local spends local anchor with additional wallet inputs
      val walletAmount = 50_000 sat
      val walletInputs = Map(
        OutPoint(randomTxId(), 3) -> TxOut(walletAmount, Script.pay2wpkh(walletPub)),
        OutPoint(randomTxId(), 0) -> TxOut(walletAmount, Script.pay2wpkh(walletPub)),
      )
      val Right(claimAnchorOutputTx) = ClaimAnchorOutputTx.createUnsignedTx(localFundingPriv, localKeys.publicKeys, commitTx, UnsafeLegacyAnchorOutputsCommitmentFormat).map(anchorTx => {
        val walletTxIn = walletInputs.map { case (outpoint, _) => TxIn(outpoint, ByteVector.empty, 0) }
        val unsignedTx = anchorTx.tx.copy(txIn = anchorTx.tx.txIn ++ walletTxIn)
        val sig1 = unsignedTx.signInput(1, Script.pay2pkh(walletPub), SIGHASH_ALL, walletAmount, SigVersion.SIGVERSION_WITNESS_V0, walletPriv)
        val sig2 = unsignedTx.signInput(2, Script.pay2pkh(walletPub), SIGHASH_ALL, walletAmount, SigVersion.SIGVERSION_WITNESS_V0, walletPriv)
        val walletSignedTx = unsignedTx
          .updateWitness(1, Script.witnessPay2wpkh(walletPub, sig1))
          .updateWitness(2, Script.witnessPay2wpkh(walletPub, sig2))
        anchorTx.copy(tx = walletSignedTx)
      })
      val allInputs = walletInputs + (claimAnchorOutputTx.input.outPoint -> claimAnchorOutputTx.input.txOut)
      assert(Try(Transaction.correctlySpends(claimAnchorOutputTx.tx, allInputs, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)).isFailure)
      // All wallet inputs must be provided when signing.
      assert(Try(claimAnchorOutputTx.sign(localFundingPriv, localKeys, UnsafeLegacyAnchorOutputsCommitmentFormat, Map.empty)).isFailure)
      assert(Try(claimAnchorOutputTx.sign(localFundingPriv, localKeys, UnsafeLegacyAnchorOutputsCommitmentFormat, walletInputs.take(1))).isFailure)
      val signedTx = claimAnchorOutputTx.sign(localFundingPriv, localKeys, UnsafeLegacyAnchorOutputsCommitmentFormat, walletInputs)
      val anchorInputWeight = signedTx.tx.weight() - signedTx.tx.copy(txIn = signedTx.tx.txIn.tail).weight()
      checkExpectedWeight(anchorInputWeight, UnsafeLegacyAnchorOutputsCommitmentFormat.anchorInputWeight)
      Transaction.correctlySpends(signedTx.tx, allInputs, ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
    }
    {
      // remote spends remote anchor
      val Right(claimAnchorOutputTx) = ClaimAnchorOutputTx.createUnsignedTx(remoteFundingPriv, remoteKeys.publicKeys, commitTx, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(!claimAnchorOutputTx.validate(Map.empty))
      val signedTx = claimAnchorOutputTx.sign(remoteFundingPriv, remoteKeys, UnsafeLegacyAnchorOutputsCommitmentFormat, Map.empty)
      assert(signedTx.validate(Map.empty))
    }
    {
      // remote spends local main delayed output with revocation key
      val Right(mainPenaltyTx) = MainPenaltyTx.createSignedTx(remoteKeys, localRevocationPriv, commitTx, localDustLimit, finalPubKeyScript, toLocalDelay, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      checkExpectedWeight(mainPenaltyTx.tx.weight(), UnsafeLegacyAnchorOutputsCommitmentFormat.mainPenaltyWeight)
      assert(mainPenaltyTx.validate(Map.empty))
    }
    {
      // local spends received htlc with HTLC-timeout tx
      for (htlcTimeoutTx <- htlcTimeoutTxs) {
        val localSig = htlcTimeoutTx.sign(localKeys, UnsafeLegacyAnchorOutputsCommitmentFormat, Map.empty)
        val remoteSig = htlcTimeoutTx.sign(remoteKeys, UnsafeLegacyAnchorOutputsCommitmentFormat)
        val signedTx = htlcTimeoutTx.addSigs(localKeys, localSig, remoteSig, UnsafeLegacyAnchorOutputsCommitmentFormat)
        assert(signedTx.validate(Map.empty))
        // local detects when remote doesn't use the right sighash flags
        val invalidSighash = Seq(SIGHASH_ALL, SIGHASH_ALL | SIGHASH_ANYONECANPAY, SIGHASH_SINGLE, SIGHASH_NONE)
        for (sighash <- invalidSighash) {
          val invalidRemoteSig = htlcTimeoutTx.signWithInvalidSighash(remoteKeys, UnsafeLegacyAnchorOutputsCommitmentFormat, sighash)
          val invalidTx = htlcTimeoutTx.addSigs(localKeys, localSig, invalidRemoteSig, UnsafeLegacyAnchorOutputsCommitmentFormat)
          assert(!invalidTx.validate(Map.empty))
        }
      }
    }
    {
      // local spends delayed output of htlc1 timeout tx
      val Right(htlcDelayed) = HtlcDelayedTx.createSignedTx(localKeys, htlcTimeoutTxs(1).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      checkExpectedWeight(htlcDelayed.tx.weight(), UnsafeLegacyAnchorOutputsCommitmentFormat.htlcDelayedWeight)
      assert(htlcDelayed.validate(Map.empty))
      // local can't claim delayed output of htlc3 timeout tx because it is below the dust limit
      val htlcDelayed1 = HtlcDelayedTx.createSignedTx(localKeys, htlcTimeoutTxs(0).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(htlcDelayed1 == Left(AmountBelowDustLimit))
    }
    {
      // local spends offered htlc with HTLC-success tx
      for ((htlcSuccessTx, paymentPreimage) <- (htlcSuccessTxs(0), paymentPreimage4) :: (htlcSuccessTxs(1), paymentPreimage2) :: (htlcSuccessTxs(2), paymentPreimage2) :: Nil) {
        val localSig = htlcSuccessTx.sign(localKeys, UnsafeLegacyAnchorOutputsCommitmentFormat, Map.empty)
        val remoteSig = htlcSuccessTx.sign(remoteKeys, UnsafeLegacyAnchorOutputsCommitmentFormat)
        val signedTx = htlcSuccessTx.addSigs(localKeys, localSig, remoteSig, paymentPreimage, UnsafeLegacyAnchorOutputsCommitmentFormat)
        assert(signedTx.validate(Map.empty))
        // check remote sig
        assert(htlcSuccessTx.checkRemoteSig(localKeys, remoteSig, UnsafeLegacyAnchorOutputsCommitmentFormat))
        // local detects when remote doesn't use the right sighash flags
        val invalidSighash = Seq(SIGHASH_ALL, SIGHASH_ALL | SIGHASH_ANYONECANPAY, SIGHASH_SINGLE, SIGHASH_NONE)
        for (sighash <- invalidSighash) {
          val invalidRemoteSig = htlcSuccessTx.signWithInvalidSighash(remoteKeys, UnsafeLegacyAnchorOutputsCommitmentFormat, sighash)
          val invalidTx = htlcSuccessTx.addSigs(localKeys, localSig, invalidRemoteSig, paymentPreimage, UnsafeLegacyAnchorOutputsCommitmentFormat)
          assert(!invalidTx.validate(Map.empty))
          assert(!invalidTx.checkRemoteSig(localKeys, invalidRemoteSig, UnsafeLegacyAnchorOutputsCommitmentFormat))
        }
      }
    }
    {
      // local spends delayed output of htlc2a and htlc2b success txs
      val Right(htlcDelayedA) = HtlcDelayedTx.createSignedTx(localKeys, htlcSuccessTxs(1).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      val Right(htlcDelayedB) = HtlcDelayedTx.createSignedTx(localKeys, htlcSuccessTxs(2).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      Seq(htlcDelayedA, htlcDelayedB).foreach(htlcDelayed => checkExpectedWeight(htlcDelayed.tx.weight(), UnsafeLegacyAnchorOutputsCommitmentFormat.htlcDelayedWeight))
      Seq(htlcDelayedA, htlcDelayedB).foreach(htlcDelayed => assert(htlcDelayed.validate(Map.empty)))
      // local can't claim delayed output of htlc4 success tx because it is below the dust limit
      val htlcDelayedC = HtlcDelayedTx.createSignedTx(localKeys, htlcSuccessTxs(0).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(htlcDelayedC == Left(AmountBelowDustLimit))
    }
    {
      // remote spends local->remote htlc outputs directly in case of success
      for ((htlc, paymentPreimage) <- (htlc1, paymentPreimage1) :: (htlc3, paymentPreimage3) :: Nil) {
        val Right(claimHtlcSuccessTx) = ClaimHtlcSuccessTx.createSignedTx(remoteKeys, commitTx, localDustLimit, commitTxOutputs, finalPubKeyScript, htlc, paymentPreimage, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
        checkExpectedWeight(claimHtlcSuccessTx.tx.weight(), UnsafeLegacyAnchorOutputsCommitmentFormat.claimHtlcSuccessWeight)
        assert(claimHtlcSuccessTx.validate(Map.empty))
      }
    }
    {
      // remote spends htlc1's htlc-timeout tx with revocation key
      val Seq(Right(claimHtlcDelayedPenaltyTx)) = ClaimHtlcDelayedOutputPenaltyTx.createSignedTxs(remoteKeys, localRevocationPriv, htlcTimeoutTxs(1).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      checkExpectedWeight(claimHtlcDelayedPenaltyTx.tx.weight(), UnsafeLegacyAnchorOutputsCommitmentFormat.claimHtlcPenaltyWeight)
      assert(claimHtlcDelayedPenaltyTx.validate(Map.empty))
      // remote can't claim revoked output of htlc3's htlc-timeout tx because it is below the dust limit
      val claimHtlcDelayedPenaltyTx1 = ClaimHtlcDelayedOutputPenaltyTx.createSignedTxs(remoteKeys, localRevocationPriv, htlcTimeoutTxs(0).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(claimHtlcDelayedPenaltyTx1 == Seq(Left(AmountBelowDustLimit)))
    }
    {
      // remote spends remote->local htlc output directly in case of timeout
      for (htlc <- Seq(htlc2a, htlc2b)) {
        val Right(claimHtlcTimeoutTx) = ClaimHtlcTimeoutTx.createSignedTx(remoteKeys, commitTx, localDustLimit, commitTxOutputs, finalPubKeyScript, htlc, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
        checkExpectedWeight(claimHtlcTimeoutTx.tx.weight(), UnsafeLegacyAnchorOutputsCommitmentFormat.claimHtlcTimeoutWeight)
        assert(claimHtlcTimeoutTx.validate(Map.empty))
      }
    }
    {
      // remote spends htlc2a/htlc2b's htlc-success tx with revocation key
      val Seq(Right(claimHtlcDelayedPenaltyTxA)) = ClaimHtlcDelayedOutputPenaltyTx.createSignedTxs(remoteKeys, localRevocationPriv, htlcSuccessTxs(1).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      val Seq(Right(claimHtlcDelayedPenaltyTxB)) = ClaimHtlcDelayedOutputPenaltyTx.createSignedTxs(remoteKeys, localRevocationPriv, htlcSuccessTxs(2).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      Seq(claimHtlcDelayedPenaltyTxA, claimHtlcDelayedPenaltyTxB).foreach(claimHtlcSuccessPenaltyTx => checkExpectedWeight(claimHtlcSuccessPenaltyTx.tx.weight(), UnsafeLegacyAnchorOutputsCommitmentFormat.claimHtlcPenaltyWeight))
      Seq(claimHtlcDelayedPenaltyTxA, claimHtlcDelayedPenaltyTxB).foreach(claimHtlcSuccessPenaltyTx => assert(claimHtlcSuccessPenaltyTx.validate(Map.empty)))
      // remote can't claim revoked output of htlc4's htlc-success tx because it is below the dust limit
      val claimHtlcDelayedPenaltyTx1 = ClaimHtlcDelayedOutputPenaltyTx.createSignedTxs(remoteKeys, localRevocationPriv, htlcSuccessTxs(0).tx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(claimHtlcDelayedPenaltyTx1 == Seq(Left(AmountBelowDustLimit)))
    }
    {
      // remote spends all htlc txs aggregated in a single tx
      val txIn = htlcTimeoutTxs.flatMap(_.tx.txIn) ++ htlcSuccessTxs.flatMap(_.tx.txIn)
      val txOut = htlcTimeoutTxs.flatMap(_.tx.txOut) ++ htlcSuccessTxs.flatMap(_.tx.txOut)
      val aggregatedHtlcTx = Transaction(2, txIn, txOut, 0)
      val claimHtlcDelayedPenaltyTxs = ClaimHtlcDelayedOutputPenaltyTx.createSignedTxs(remoteKeys, localRevocationPriv, aggregatedHtlcTx, localDustLimit, toLocalDelay, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(claimHtlcDelayedPenaltyTxs.size == 5)
      val skipped = claimHtlcDelayedPenaltyTxs.collect { case Left(reason) => reason }
      assert(skipped.size == 2)
      assert(skipped.toSet == Set(AmountBelowDustLimit))
      val claimed = claimHtlcDelayedPenaltyTxs.collect { case Right(tx) => tx }
      assert(claimed.size == 3)
      assert(claimed.map(_.input.outPoint).toSet.size == 3)
      claimed.foreach { htlcPenaltyTx =>
        checkExpectedWeight(htlcPenaltyTx.tx.weight(), UnsafeLegacyAnchorOutputsCommitmentFormat.claimHtlcPenaltyWeight)
        assert(htlcPenaltyTx.validate(Map.empty))
      }
    }
    {
      // remote spends htlc outputs with revocation key
      val htlcs = spec.htlcs.map(_.add).map(add => (add.paymentHash, add.cltvExpiry)).toSeq
      val htlcPenaltyTxs = HtlcPenaltyTx.createSignedTxs(remoteKeys, localRevocationPriv, commitTx, htlcs, localDustLimit, finalPubKeyScript, feeratePerKw, UnsafeLegacyAnchorOutputsCommitmentFormat)
      assert(htlcPenaltyTxs.collect { case Right(htlcPenaltyTx) => htlcPenaltyTx.paymentHash }.toSet == Set(htlc1, htlc2a, htlc2b, htlc3, htlc4).map(_.paymentHash)) // the first 5 htlcs are above the dust limit
      htlcPenaltyTxs.collect { case Right(htlcPenaltyTx) => htlcPenaltyTx }.foreach { htlcPenaltyTx =>
        val expectedWeight = if (htlcTimeoutTxs.map(_.input.outPoint).toSet.contains(htlcPenaltyTx.input.outPoint)) {
          UnsafeLegacyAnchorOutputsCommitmentFormat.htlcOfferedPenaltyWeight
        } else {
          UnsafeLegacyAnchorOutputsCommitmentFormat.htlcReceivedPenaltyWeight
        }
        checkExpectedWeight(htlcPenaltyTx.tx.weight(), expectedWeight)
        assert(htlcPenaltyTx.validate(Map.empty))
      }
    }
  }

  test("generate valid commitment and htlc transactions (taproot)") {
    import fr.acinq.bitcoin.scalacompat.KotlinUtils._
    import fr.acinq.eclair.transactions.Scripts.Taproot

    // funding tx sends to musig2 aggregate of local and remote funding keys
    val fundingTxOutpoint = OutPoint(randomTxId(), 0)
    val fundingOutput = TxOut(Btc(1), Script.pay2tr(Taproot.musig2Aggregate(localFundingPriv.publicKey, remoteFundingPriv.publicKey), None))

    // offered HTLC
    val preimage = ByteVector32.fromValidHex("01" * 32)
    val paymentHash = Crypto.sha256(preimage)

    val txNumber = 0x404142434445L
    val (sequence, lockTime) = encodeTxNumber(txNumber)
    val commitTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(fundingTxOutpoint, Nil, sequence) :: Nil,
        txOut = Seq(
          TxOut(300.millibtc, Taproot.toLocal(localKeys.publicKeys, toLocalDelay)),
          TxOut(400.millibtc, Taproot.toRemote(localKeys.publicKeys)),
          TxOut(330.sat, Taproot.anchor(localKeys.publicKeys.localDelayedPaymentPublicKey)),
          TxOut(330.sat, Taproot.anchor(localKeys.publicKeys.remotePaymentPublicKey)),
          TxOut(25_000.sat, Taproot.offeredHtlc(localKeys.publicKeys, paymentHash)),
          TxOut(15_000.sat, Taproot.receivedHtlc(localKeys.publicKeys, paymentHash, CltvExpiry(300)))
        ),
        lockTime
      )

      val (secretLocalNonce, publicLocalNonce) = Musig2.generateNonce(randomBytes32(), localFundingPriv, Seq(localFundingPriv.publicKey))
      val (secretRemoteNonce, publicRemoteNonce) = Musig2.generateNonce(randomBytes32(), remoteFundingPriv, Seq(remoteFundingPriv.publicKey))
      val publicKeys = Scripts.sort(Seq(localFundingPriv.publicKey, remoteFundingPriv.publicKey))
      val publicNonces = Seq(publicLocalNonce, publicRemoteNonce)
      val Right(sig) = for {
        localPartialSig <- Musig2.signTaprootInput(localFundingPriv, tx, 0, Seq(fundingOutput), publicKeys, secretLocalNonce, publicNonces, None)
        remotePartialSig <- Musig2.signTaprootInput(remoteFundingPriv, tx, 0, Seq(fundingOutput), publicKeys, secretRemoteNonce, publicNonces, None)
        sig <- Musig2.aggregateTaprootSignatures(Seq(localPartialSig, remotePartialSig), tx, 0, Seq(fundingOutput), publicKeys, publicNonces, None)
      } yield sig

      tx.updateWitness(0, Script.witnessKeyPathPay2tr(sig))
    }
    Transaction.correctlySpends(commitTx, Map(fundingTxOutpoint -> fundingOutput), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val finalPubKeyScript = Script.write(Script.pay2wpkh(PrivateKey(randomBytes32()).publicKey))

    val spendToLocalOutputTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(commitTx, 0), Seq(), sequence = toLocalDelay.toInt) :: Nil,
        txOut = TxOut(300.millibtc, finalPubKeyScript) :: Nil,
        lockTime = 0)
      val scriptTree = Taproot.toLocalScriptTree(localKeys.publicKeys, toLocalDelay)
      val sig = Transaction.signInputTaprootScriptPath(localDelayedPaymentPriv, tx, 0, Seq(commitTx.txOut(0)), SigHash.SIGHASH_DEFAULT, scriptTree.getLeft.hash())
      val witness = Script.witnessScriptPathPay2tr(Taproot.NUMS_POINT.xOnly, scriptTree.getLeft.asInstanceOf[ScriptTree.Leaf], ScriptWitness(Seq(sig)), scriptTree)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(spendToLocalOutputTx, Seq(commitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val mainPenaltyTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(commitTx, 0), Nil, sequence = TxIn.SEQUENCE_FINAL) :: Nil,
        txOut = TxOut(300.millibtc, finalPubKeyScript) :: Nil,
        lockTime = 0)
      val scriptTree = Taproot.toLocalScriptTree(remoteKeys.publicKeys, toLocalDelay)
      val sig = Transaction.signInputTaprootScriptPath(localRevocationPriv, tx, 0, Seq(commitTx.txOut(0)), SigHash.SIGHASH_DEFAULT, scriptTree.getRight.hash())
      val witness = Script.witnessScriptPathPay2tr(XonlyPublicKey(Taproot.NUMS_POINT), scriptTree.getRight.asInstanceOf[ScriptTree.Leaf], ScriptWitness(Seq(sig)), scriptTree)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(mainPenaltyTx, Seq(commitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val spendToRemoteOutputTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(commitTx, 1), Nil, sequence = 1) :: Nil,
        txOut = TxOut(400.millibtc, finalPubKeyScript) :: Nil,
        lockTime = 0)
      val scriptTree = Taproot.toRemoteScriptTree(remoteKeys.publicKeys)
      val sig = Transaction.signInputTaprootScriptPath(remotePaymentPriv, tx, 0, Seq(commitTx.txOut(1)), SigHash.SIGHASH_DEFAULT, scriptTree.hash())
      val witness = Script.witnessScriptPathPay2tr(Taproot.NUMS_POINT.xOnly, scriptTree, ScriptWitness(Seq(sig)), scriptTree)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(spendToRemoteOutputTx, Seq(commitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val spendLocalAnchorTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(commitTx, 2), Nil, sequence = TxIn.SEQUENCE_FINAL) :: Nil,
        txOut = TxOut(330.sat, finalPubKeyScript) :: Nil,
        lockTime = 0)
      val sig = Transaction.signInputTaprootKeyPath(localDelayedPaymentPriv, tx, 0, Seq(commitTx.txOut(2)), SigHash.SIGHASH_DEFAULT, Some(Scripts.Taproot.anchorScriptTree))
      val witness = Script.witnessKeyPathPay2tr(sig)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(spendLocalAnchorTx, Seq(commitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val spendLocalAnchorAfterDelayTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(commitTx, 2), Nil, sequence = 16) :: Nil,
        txOut = TxOut(330.sat, finalPubKeyScript) :: Nil,
        lockTime = 0)
      // after 16 blocks, anchor outputs can be spent without a signature BUT spenders still need to know the local/remote payment public key
      val witness = Script.witnessScriptPathPay2tr(localDelayedPaymentPriv.xOnlyPublicKey(), Scripts.Taproot.anchorScriptTree, ScriptWitness.empty, Scripts.Taproot.anchorScriptTree)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(spendLocalAnchorAfterDelayTx, Seq(commitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val spendRemoteAnchorTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(commitTx, 3), Nil, sequence = TxIn.SEQUENCE_FINAL) :: Nil,
        txOut = TxOut(330.sat, finalPubKeyScript) :: Nil,
        lockTime = 0)
      val sig = Transaction.signInputTaprootKeyPath(remotePaymentPriv, tx, 0, Seq(commitTx.txOut(3)), SigHash.SIGHASH_DEFAULT, Some(Scripts.Taproot.anchorScriptTree))
      val witness = Script.witnessKeyPathPay2tr(sig)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(spendRemoteAnchorTx, Seq(commitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val spendRemoteAnchorAfterDelayTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(commitTx, 3), Nil, sequence = 16) :: Nil,
        txOut = TxOut(330.sat, finalPubKeyScript) :: Nil,
        lockTime = 0)
      val witness = Script.witnessScriptPathPay2tr(remotePaymentPriv.xOnlyPublicKey(), Scripts.Taproot.anchorScriptTree, ScriptWitness.empty, Scripts.Taproot.anchorScriptTree)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(spendRemoteAnchorAfterDelayTx, Seq(commitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // Spend offered HTLC with HTLC-Timeout tx.
    val htlcTimeoutTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(commitTx, 4), Nil, sequence = TxIn.SEQUENCE_FINAL) :: Nil,
        txOut = TxOut(25_000.sat, Taproot.htlcDelayed(localKeys.publicKeys, toLocalDelay)) :: Nil,
        lockTime = 300)
      val scriptTree = Taproot.offeredHtlcScriptTree(localKeys.publicKeys, paymentHash)
      val sigHash = SigHash.SIGHASH_SINGLE | SigHash.SIGHASH_ANYONECANPAY
      val localSig = Taproot.encodeSig(Transaction.signInputTaprootScriptPath(localHtlcPriv, tx, 0, Seq(commitTx.txOut(4)), sigHash, scriptTree.getLeft.hash()), sigHash)
      val remoteSig = Taproot.encodeSig(Transaction.signInputTaprootScriptPath(remoteHtlcPriv, tx, 0, Seq(commitTx.txOut(4)), sigHash, scriptTree.getLeft.hash()), sigHash)
      val witness = Script.witnessScriptPathPay2tr(localRevocationPriv.xOnlyPublicKey(), scriptTree.getLeft.asInstanceOf[ScriptTree.Leaf], ScriptWitness(Seq(remoteSig, localSig)), scriptTree)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(htlcTimeoutTx, Seq(commitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val offeredHtlcPenaltyTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(commitTx, 4), Nil, sequence = TxIn.SEQUENCE_FINAL) :: Nil,
        txOut = TxOut(25_000.sat, finalPubKeyScript) :: Nil,
        lockTime = 0)
      val scriptTree = Taproot.offeredHtlcScriptTree(remoteKeys.publicKeys, paymentHash)
      val sig = Transaction.signInputTaprootKeyPath(localRevocationPriv, tx, 0, Seq(commitTx.txOut(4)), SigHash.SIGHASH_DEFAULT, Some(scriptTree))
      val witness = Script.witnessKeyPathPay2tr(sig)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(offeredHtlcPenaltyTx, Seq(commitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val spendHtlcTimeoutTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(htlcTimeoutTx, 0), Nil, sequence = toLocalDelay.toInt) :: Nil,
        txOut = TxOut(25_000.sat, finalPubKeyScript) :: Nil,
        lockTime = 0)
      val scriptTree = Taproot.htlcDelayedScriptTree(localKeys.publicKeys, toLocalDelay)
      val localSig = Transaction.signInputTaprootScriptPath(localDelayedPaymentPriv, tx, 0, Seq(htlcTimeoutTx.txOut(0)), SigHash.SIGHASH_DEFAULT, scriptTree.hash())
      val witness = Script.witnessScriptPathPay2tr(localRevocationPriv.xOnlyPublicKey(), scriptTree, ScriptWitness(Seq(localSig)), scriptTree)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(spendHtlcTimeoutTx, Seq(htlcTimeoutTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val htlcTimeoutPenaltyTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(htlcTimeoutTx, 0), Nil, sequence = TxIn.SEQUENCE_FINAL) :: Nil,
        txOut = TxOut(25_000.sat, finalPubKeyScript) :: Nil,
        lockTime = 0)
      val scriptTree = Taproot.htlcDelayedScriptTree(remoteKeys.publicKeys, toLocalDelay)
      val sig = Transaction.signInputTaprootKeyPath(localRevocationPriv, tx, 0, Seq(htlcTimeoutTx.txOut(0)), SigHash.SIGHASH_DEFAULT, Some(scriptTree))
      val witness = Script.witnessKeyPathPay2tr(sig)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(htlcTimeoutPenaltyTx, Seq(htlcTimeoutTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    // Spend received HTLC with HTLC-Success tx.
    val htlcSuccessTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(commitTx, 5), Nil, sequence = 1) :: Nil,
        txOut = TxOut(15_000.sat, Taproot.htlcDelayed(localKeys.publicKeys, toLocalDelay)) :: Nil,
        lockTime = 0)
      val scriptTree = Taproot.receivedHtlcScriptTree(localKeys.publicKeys, paymentHash, CltvExpiry(300))
      val sigHash = SigHash.SIGHASH_SINGLE | SigHash.SIGHASH_ANYONECANPAY
      val localSig = Taproot.encodeSig(Transaction.signInputTaprootScriptPath(localHtlcPriv, tx, 0, Seq(commitTx.txOut(5)), sigHash, scriptTree.getRight.hash()), sigHash)
      val remoteSig = Taproot.encodeSig(Transaction.signInputTaprootScriptPath(remoteHtlcPriv, tx, 0, Seq(commitTx.txOut(5)), sigHash, scriptTree.getRight.hash()), sigHash)
      val witness = Script.witnessScriptPathPay2tr(localRevocationPriv.xOnlyPublicKey(), scriptTree.getRight.asInstanceOf[ScriptTree.Leaf], ScriptWitness(Seq(remoteSig, localSig, preimage)), scriptTree)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(htlcSuccessTx, Seq(commitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val receivedHtlcPenaltyTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(commitTx, 5), Nil, sequence = 1) :: Nil,
        txOut = TxOut(15_000.sat, finalPubKeyScript) :: Nil,
        lockTime = 0)
      val scriptTree = Taproot.receivedHtlcScriptTree(remoteKeys.publicKeys, paymentHash, CltvExpiry(300))
      val sig = Transaction.signInputTaprootKeyPath(localRevocationPriv, tx, 0, Seq(commitTx.txOut(5)), SigHash.SIGHASH_DEFAULT, Some(scriptTree))
      val witness = Script.witnessKeyPathPay2tr(sig)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(receivedHtlcPenaltyTx, Seq(commitTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val spendHtlcSuccessTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(htlcSuccessTx, 0), Nil, sequence = toLocalDelay.toInt) :: Nil,
        txOut = TxOut(15_000.sat, finalPubKeyScript) :: Nil,
        lockTime = 0)
      val scriptTree = Taproot.htlcDelayedScriptTree(localKeys.publicKeys, toLocalDelay)
      val localSig = Transaction.signInputTaprootScriptPath(localDelayedPaymentPriv, tx, 0, Seq(htlcSuccessTx.txOut(0)), SigHash.SIGHASH_DEFAULT, scriptTree.hash())
      val witness = Script.witnessScriptPathPay2tr(localRevocationPriv.xOnlyPublicKey(), scriptTree, ScriptWitness(Seq(localSig)), scriptTree)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(spendHtlcSuccessTx, Seq(htlcSuccessTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)

    val htlcSuccessPenaltyTx = {
      val tx = Transaction(
        version = 2,
        txIn = TxIn(OutPoint(htlcSuccessTx, 0), Nil, sequence = TxIn.SEQUENCE_FINAL) :: Nil,
        txOut = TxOut(15_000.sat, finalPubKeyScript) :: Nil,
        lockTime = 0)
      val scriptTree = Taproot.htlcDelayedScriptTree(remoteKeys.publicKeys, toLocalDelay)
      val sig = Transaction.signInputTaprootKeyPath(localRevocationPriv, tx, 0, Seq(htlcSuccessTx.txOut(0)), SigHash.SIGHASH_DEFAULT, Some(scriptTree))
      val witness = Script.witnessKeyPathPay2tr(sig)
      tx.updateWitness(0, witness)
    }
    Transaction.correctlySpends(htlcSuccessPenaltyTx, Seq(htlcSuccessTx), ScriptFlags.STANDARD_SCRIPT_VERIFY_FLAGS)
  }

  test("generate taproot NUMS point") {
    val bin = 2.toByte +: Crypto.sha256(ByteVector.fromValidHex("0000000000000002") ++ ByteVector.view("Lightning Simple Taproot".getBytes))
    val pub = PublicKey(bin)
    assert(pub == Taproot.NUMS_POINT)
  }

  test("sort public keys using lexicographic ordering") {
    val pubkey1 = PublicKey(hex"0277174bdb8e0003a03334f0f5d0be2b9f4c0812ee4097b0c23d29f505b8e9d9f8")
    val pubkey2 = PublicKey(hex"03e27a9ca7c8d6348868f8b4a3974e9eb91f7df7d6532f9b0a50f0314cb28c8d31")
    assert(Seq(pubkey1, pubkey2) == Scripts.sort(Seq(pubkey1, pubkey2)))
    assert(Seq(pubkey1, pubkey2) == Scripts.sort(Seq(pubkey2, pubkey1)))
    assert(multiSig2of2(pubkey1, pubkey2) == multiSig2of2(pubkey2, pubkey1))
    assert(multiSig2of2(pubkey2, pubkey1) == Seq(OP_2, OP_PUSHDATA(pubkey1.value), OP_PUSHDATA(pubkey2.value), OP_2, OP_CHECKMULTISIG))
    assert(Taproot.musig2Aggregate(pubkey1, pubkey2) == Taproot.musig2Aggregate(pubkey2, pubkey1))
    assert(Taproot.musig2Aggregate(pubkey2, pubkey1) == Musig2.aggregateKeys(Seq(pubkey1, pubkey2)))
  }

  test("sort the htlc outputs using BIP69 and cltv expiry") {
    val localFundingPriv = PrivateKey(hex"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1")
    val remoteFundingPriv = PrivateKey(hex"a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2")
    val localRevocationPriv = PrivateKey(hex"a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3")
    val localPaymentPriv = PrivateKey(hex"a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4a4")
    val localDelayedPaymentPriv = PrivateKey(hex"a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5")
    val remotePaymentPriv = PrivateKey(hex"a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6")
    val localHtlcPriv = PrivateKey(hex"a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7")
    val remoteHtlcPriv = PrivateKey(hex"a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8")
    val localKeys = LocalCommitmentKeys(
      ourDelayedPaymentKey = localDelayedPaymentPriv,
      theirPaymentPublicKey = remotePaymentPriv.publicKey,
      ourPaymentBasePoint = localPaymentBasePoint,
      ourHtlcKey = localHtlcPriv,
      theirHtlcPublicKey = remoteHtlcPriv.publicKey,
      revocationPublicKey = localRevocationPriv.publicKey,
    )
    val commitInput = Funding.makeFundingInputInfo(TxId.fromValidHex("a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0"), 0, Btc(1), localFundingPriv.publicKey, remoteFundingPriv.publicKey, DefaultCommitmentFormat)

    // htlc1 and htlc2 are two regular incoming HTLCs with different amounts.
    // htlc2 and htlc3 have the same amounts and should be sorted according to their scriptPubKey
    // htlc4 is identical to htlc3 and htlc5 has same payment_hash/amount but different CLTV
    val paymentPreimage1 = ByteVector32(hex"1111111111111111111111111111111111111111111111111111111111111111")
    val paymentPreimage2 = ByteVector32(hex"2222222222222222222222222222222222222222222222222222222222222222")
    val paymentPreimage3 = ByteVector32(hex"3333333333333333333333333333333333333333333333333333333333333333")
    val htlc1 = UpdateAddHtlc(randomBytes32(), 1, millibtc2satoshi(MilliBtc(100)).toMilliSatoshi, sha256(paymentPreimage1), CltvExpiry(300), TestConstants.emptyOnionPacket, None, 1.0, None)
    val htlc2 = UpdateAddHtlc(randomBytes32(), 2, millibtc2satoshi(MilliBtc(200)).toMilliSatoshi, sha256(paymentPreimage2), CltvExpiry(300), TestConstants.emptyOnionPacket, None, 1.0, None)
    val htlc3 = UpdateAddHtlc(randomBytes32(), 3, millibtc2satoshi(MilliBtc(200)).toMilliSatoshi, sha256(paymentPreimage3), CltvExpiry(300), TestConstants.emptyOnionPacket, None, 1.0, None)
    val htlc4 = UpdateAddHtlc(randomBytes32(), 4, millibtc2satoshi(MilliBtc(200)).toMilliSatoshi, sha256(paymentPreimage3), CltvExpiry(300), TestConstants.emptyOnionPacket, None, 1.0, None)
    val htlc5 = UpdateAddHtlc(randomBytes32(), 5, millibtc2satoshi(MilliBtc(200)).toMilliSatoshi, sha256(paymentPreimage3), CltvExpiry(301), TestConstants.emptyOnionPacket, None, 1.0, None)

    val spec = CommitmentSpec(
      htlcs = Set(
        OutgoingHtlc(htlc1),
        OutgoingHtlc(htlc2),
        OutgoingHtlc(htlc3),
        OutgoingHtlc(htlc4),
        OutgoingHtlc(htlc5)
      ),
      commitTxFeerate = feeratePerKw,
      toLocal = millibtc2satoshi(MilliBtc(400)).toMilliSatoshi,
      toRemote = millibtc2satoshi(MilliBtc(300)).toMilliSatoshi)

    val commitTxNumber = 0x404142434446L
    val (commitTx, outputs, htlcTxs) = {
      val outputs = makeCommitTxOutputs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localKeys.publicKeys, payCommitTxFees = true, localDustLimit, toLocalDelay, spec, DefaultCommitmentFormat)
      val txInfo = makeCommitTx(commitInput, commitTxNumber, localPaymentPriv.publicKey, remotePaymentPriv.publicKey, localIsChannelOpener = true, outputs)
      val localSig = txInfo.sign(localFundingPriv, remoteFundingPriv.publicKey)
      val remoteSig = txInfo.sign(remotePaymentPriv, localFundingPriv.publicKey)
      val commitTx = txInfo.aggregateSigs(localFundingPriv.publicKey, remoteFundingPriv.publicKey, localSig, remoteSig)
      val htlcTxs = makeHtlcTxs(commitTx, outputs, DefaultCommitmentFormat)
      (commitTx, outputs, htlcTxs)
    }

    // htlc1 comes before htlc2 because of the smaller amount (BIP69)
    // htlc2 and htlc3 have the same amount but htlc2 comes first because its pubKeyScript is lexicographically smaller than htlc3's
    // htlc5 comes after htlc3 and htlc4 because of the higher CLTV
    val htlcOut1 :: htlcOut2 :: htlcOut3 :: htlcOut4 :: htlcOut5 :: _ = commitTx.txOut.toList
    assert(htlcOut1.amount == 10000000.sat)
    for (htlcOut <- Seq(htlcOut2, htlcOut3, htlcOut4, htlcOut5)) {
      assert(htlcOut.amount == 20000000.sat)
    }

    // htlc3 and htlc4 are completely identical, their relative order can't be enforced.
    assert(htlcTxs.length == 5)
    htlcTxs.foreach(tx => assert(tx.isInstanceOf[HtlcTimeoutTx]))
    val htlcIds = htlcTxs.sortBy(_.input.outPoint.index).map(_.htlcId)
    assert(htlcIds == Seq(1, 2, 3, 4, 5) || htlcIds == Seq(1, 2, 4, 3, 5))

    assert(htlcOut2.publicKeyScript.toHex < htlcOut3.publicKeyScript.toHex)
    assert(outputs.collectFirst { case o: OutHtlc if o.htlc.add == htlc2 => o.txOut.publicKeyScript }.contains(htlcOut2.publicKeyScript))
    assert(outputs.collectFirst { case o: OutHtlc if o.htlc.add == htlc3 => o.txOut.publicKeyScript }.contains(htlcOut3.publicKeyScript))
    assert(outputs.collectFirst { case o: OutHtlc if o.htlc.add == htlc4 => o.txOut.publicKeyScript }.contains(htlcOut4.publicKeyScript))
    assert(outputs.collectFirst { case o: OutHtlc if o.htlc.add == htlc5 => o.txOut.publicKeyScript }.contains(htlcOut5.publicKeyScript))
  }

  test("find our output in closing tx") {
    val commitInput = Funding.makeFundingInputInfo(randomTxId(), 0, Btc(1), localFundingPriv.publicKey, remoteFundingPriv.publicKey, ZeroFeeHtlcTxAnchorOutputsCommitmentFormat)
    val localPubKeyScript = Script.write(Script.pay2wpkh(PrivateKey(randomBytes32()).publicKey))
    val remotePubKeyScript = Script.write(Script.pay2wpkh(PrivateKey(randomBytes32()).publicKey))

    {
      // Different amounts, both outputs untrimmed, local is funder:
      val spec = CommitmentSpec(Set.empty, feeratePerKw, 150_000_000 msat, 250_000_000 msat)
      val closingTx = ClosingTx.createUnsignedTx(commitInput, localPubKeyScript, remotePubKeyScript, localPaysClosingFees = true, localDustLimit, 1000 sat, spec)
      assert(closingTx.tx.txOut.length == 2)
      assert(closingTx.toLocalOutput_opt.nonEmpty)
      val toLocal = closingTx.toLocalOutput_opt.get
      assert(toLocal.publicKeyScript == localPubKeyScript)
      assert(toLocal.amount == 149_000.sat) // funder pays the fee
      val toRemoteIndex = (closingTx.toLocalOutputIndex_opt.get + 1) % 2
      assert(closingTx.tx.txOut(toRemoteIndex.toInt).amount == 250_000.sat)
    }
    {
      // Different amounts, both outputs untrimmed, local is closer (option_simple_close):
      val spec = CommitmentSpec(Set.empty, feeratePerKw, 150_000_000 msat, 250_000_000 msat)
      val closingTxs = makeSimpleClosingTxs(commitInput, spec, SimpleClosingTxFee.PaidByUs(5_000 sat), 0, localPubKeyScript, remotePubKeyScript)
      assert(closingTxs.localAndRemote_opt.nonEmpty)
      assert(closingTxs.localOnly_opt.nonEmpty)
      assert(closingTxs.remoteOnly_opt.isEmpty)
      val localAndRemote = closingTxs.localAndRemote_opt.flatMap(_.toLocalOutput_opt).get
      assert(localAndRemote.publicKeyScript == localPubKeyScript)
      assert(localAndRemote.amount == 145_000.sat)
      val localOnly = closingTxs.localOnly_opt.flatMap(_.toLocalOutput_opt).get
      assert(localOnly.publicKeyScript == localPubKeyScript)
      assert(localOnly.amount == 145_000.sat)
    }
    {
      // Remote is using OP_RETURN (option_simple_close): we set their output amount to 0 sat.
      val spec = CommitmentSpec(Set.empty, feeratePerKw, 150_000_000 msat, 1_500_000 msat)
      val remotePubKeyScript = Script.write(OP_RETURN :: OP_PUSHDATA(hex"deadbeef") :: Nil)
      val closingTxs = makeSimpleClosingTxs(commitInput, spec, SimpleClosingTxFee.PaidByUs(5_000 sat), 0, localPubKeyScript, remotePubKeyScript)
      assert(closingTxs.localAndRemote_opt.nonEmpty)
      assert(closingTxs.localOnly_opt.nonEmpty)
      assert(closingTxs.remoteOnly_opt.isEmpty)
      val localAndRemoteIndex = closingTxs.localAndRemote_opt.flatMap(_.toLocalOutputIndex_opt).get
      val localAndRemote = closingTxs.localAndRemote_opt.flatMap(_.toLocalOutput_opt).get
      assert(localAndRemote.publicKeyScript == localPubKeyScript)
      assert(localAndRemote.amount == 145_000.sat)
      val remoteOutput = closingTxs.localAndRemote_opt.get.tx.txOut((localAndRemoteIndex.toInt + 1) % 2)
      assert(remoteOutput.amount == 0.sat)
      assert(remoteOutput.publicKeyScript == remotePubKeyScript)
      val localOnly = closingTxs.localOnly_opt.flatMap(_.toLocalOutput_opt).get
      assert(localOnly.publicKeyScript == localPubKeyScript)
      assert(localOnly.amount == 145_000.sat)
    }
    {
      // Remote is using OP_RETURN (option_simple_close) and paying the fees: we set their output amount to 0 sat.
      val spec = CommitmentSpec(Set.empty, feeratePerKw, 150_000_000 msat, 10_000_000 msat)
      val remotePubKeyScript = Script.write(OP_RETURN :: OP_PUSHDATA(hex"deadbeef") :: Nil)
      val closingTxs = makeSimpleClosingTxs(commitInput, spec, SimpleClosingTxFee.PaidByThem(5_000 sat), 0, localPubKeyScript, remotePubKeyScript)
      assert(closingTxs.localAndRemote_opt.nonEmpty)
      assert(closingTxs.localOnly_opt.nonEmpty)
      assert(closingTxs.remoteOnly_opt.isEmpty)
      val localAndRemoteIndex = closingTxs.localAndRemote_opt.flatMap(_.toLocalOutputIndex_opt).get
      val localAndRemote = closingTxs.localAndRemote_opt.flatMap(_.toLocalOutput_opt).get
      assert(localAndRemote.publicKeyScript == localPubKeyScript)
      assert(localAndRemote.amount == 150_000.sat)
      val remoteOutput = closingTxs.localAndRemote_opt.get.tx.txOut((localAndRemoteIndex.toInt + 1) % 2)
      assert(remoteOutput.amount == 0.sat)
      assert(remoteOutput.publicKeyScript == remotePubKeyScript)
      val localOnly = closingTxs.localOnly_opt.flatMap(_.toLocalOutput_opt).get
      assert(localOnly.publicKeyScript == localPubKeyScript)
      assert(localOnly.amount == 150_000.sat)
    }
    {
      // Same amounts, both outputs untrimmed, local is fundee:
      val spec = CommitmentSpec(Set.empty, feeratePerKw, 150_000_000 msat, 150_000_000 msat)
      val closingTx = ClosingTx.createUnsignedTx(commitInput, localPubKeyScript, remotePubKeyScript, localPaysClosingFees = false, localDustLimit, 1000 sat, spec)
      assert(closingTx.tx.txOut.length == 2)
      assert(closingTx.toLocalOutput_opt.nonEmpty)
      val toLocal = closingTx.toLocalOutput_opt.get
      assert(toLocal.publicKeyScript == localPubKeyScript)
      assert(toLocal.amount == 150_000.sat)
      val toRemoteIndex = (closingTx.toLocalOutputIndex_opt.get + 1) % 2
      assert(closingTx.tx.txOut(toRemoteIndex.toInt).amount < 150_000.sat)
    }
    {
      // Their output is trimmed:
      val spec = CommitmentSpec(Set.empty, feeratePerKw, 150_000_000 msat, 1_000 msat)
      val closingTx = ClosingTx.createUnsignedTx(commitInput, localPubKeyScript, remotePubKeyScript, localPaysClosingFees = false, localDustLimit, 1000 sat, spec)
      assert(closingTx.tx.txOut.length == 1)
      assert(closingTx.toLocalOutputIndex_opt.contains(0))
      assert(closingTx.toLocalOutput_opt.nonEmpty)
      val toLocal = closingTx.toLocalOutput_opt.get
      assert(toLocal.publicKeyScript == localPubKeyScript)
      assert(toLocal.amount == 150_000.sat)
    }
    {
      // Their output is trimmed (option_simple_close):
      val spec = CommitmentSpec(Set.empty, feeratePerKw, 150_000_000 msat, 1_000_000 msat)
      val closingTxs = makeSimpleClosingTxs(commitInput, spec, SimpleClosingTxFee.PaidByThem(800 sat), 0, localPubKeyScript, remotePubKeyScript)
      assert(closingTxs.all.size == 1)
      assert(closingTxs.localOnly_opt.nonEmpty)
      val toLocal = closingTxs.localOnly_opt.flatMap(_.toLocalOutput_opt).get
      assert(toLocal.publicKeyScript == localPubKeyScript)
      assert(toLocal.amount == 150_000.sat)
      assert(closingTxs.localOnly_opt.flatMap(_.toLocalOutputIndex_opt).contains(0))
    }
    {
      // Their OP_RETURN output is trimmed (option_simple_close):
      val spec = CommitmentSpec(Set.empty, feeratePerKw, 150_000_000 msat, 1_000_000 msat)
      val remotePubKeyScript = Script.write(OP_RETURN :: OP_PUSHDATA(hex"deadbeef") :: Nil)
      val closingTxs = makeSimpleClosingTxs(commitInput, spec, SimpleClosingTxFee.PaidByThem(1_001 sat), 0, localPubKeyScript, remotePubKeyScript)
      assert(closingTxs.all.size == 1)
      assert(closingTxs.localOnly_opt.nonEmpty)
      val toLocal = closingTxs.localOnly_opt.flatMap(_.toLocalOutput_opt).get
      assert(toLocal.publicKeyScript == localPubKeyScript)
      assert(toLocal.amount == 150_000.sat)
      assert(closingTxs.localOnly_opt.flatMap(_.toLocalOutputIndex_opt).contains(0))
    }
    {
      // Our output is trimmed:
      val spec = CommitmentSpec(Set.empty, feeratePerKw, 50_000 msat, 150_000_000 msat)
      val closingTx = ClosingTx.createUnsignedTx(commitInput, localPubKeyScript, remotePubKeyScript, localPaysClosingFees = true, localDustLimit, 1000 sat, spec)
      assert(closingTx.tx.txOut.length == 1)
      assert(closingTx.toLocalOutput_opt.isEmpty)
    }
    {
      // Our output is trimmed (option_simple_close):
      val spec = CommitmentSpec(Set.empty, feeratePerKw, 1_000_000 msat, 150_000_000 msat)
      val closingTxs = makeSimpleClosingTxs(commitInput, spec, SimpleClosingTxFee.PaidByUs(800 sat), 0, localPubKeyScript, remotePubKeyScript)
      assert(closingTxs.all.size == 1)
      assert(closingTxs.remoteOnly_opt.nonEmpty)
      assert(closingTxs.remoteOnly_opt.flatMap(_.toLocalOutput_opt).isEmpty)
    }
    {
      // Both outputs are trimmed:
      val spec = CommitmentSpec(Set.empty, feeratePerKw, 50_000 msat, 10_000 msat)
      val closingTx = ClosingTx.createUnsignedTx(commitInput, localPubKeyScript, remotePubKeyScript, localPaysClosingFees = true, localDustLimit, 1000 sat, spec)
      assert(closingTx.tx.txOut.isEmpty)
      assert(closingTx.toLocalOutput_opt.isEmpty)
    }
  }

  test("BOLT 3 fee tests") {
    val dustLimit = 546 sat
    val bolt3 = {
      val fetch = Source.fromURL("https://raw.githubusercontent.com/lightning/bolts/master/03-transactions.md")
      // We'll use character '$' to separate tests:
      val formatted = fetch.mkString.replace("    name:", "$   name:")
      fetch.close()
      formatted
    }

    def htlcIn(amount: Satoshi): DirectedHtlc = IncomingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 0, amount.toMilliSatoshi, ByteVector32.Zeroes, CltvExpiry(144), TestConstants.emptyOnionPacket, None, 1.0, None))

    def htlcOut(amount: Satoshi): DirectedHtlc = OutgoingHtlc(UpdateAddHtlc(ByteVector32.Zeroes, 0, amount.toMilliSatoshi, ByteVector32.Zeroes, CltvExpiry(144), TestConstants.emptyOnionPacket, None, 1.0, None))

    case class TestVector(name: String, spec: CommitmentSpec, expectedFee: Satoshi)

    // this regex extract params from a given test
    val testRegex = ("""name: (.*)\n""" +
      """.*to_local_msat: ([0-9]+)\n""" +
      """.*to_remote_msat: ([0-9]+)\n""" +
      """.*feerate_per_kw: ([0-9]+)\n""" +
      """.*base commitment transaction fee = ([0-9]+)\n""" +
      """[^$]+""").r
    // this regex extracts htlc direction and amounts
    val htlcRegex = """.*HTLC #[0-9] ([a-z]+) amount ([0-9]+).*""".r
    val tests = testRegex.findAllIn(bolt3).map(s => {
      val testRegex(name, to_local_msat, to_remote_msat, feerate_per_kw, fee) = s
      val htlcs = htlcRegex.findAllIn(s).map(l => {
        val htlcRegex(direction, amount) = l
        direction match {
          case "offered" => htlcOut(Satoshi(amount.toLong))
          case "received" => htlcIn(Satoshi(amount.toLong))
        }
      }).toSet
      TestVector(name, CommitmentSpec(htlcs, FeeratePerKw(feerate_per_kw.toLong.sat), MilliSatoshi(to_local_msat.toLong), MilliSatoshi(to_remote_msat.toLong)), Satoshi(fee.toLong))
    }).toSeq

    assert(tests.size == 15, "there were 15 tests at e042c615efb5139a0bfdca0c6391c3c13df70418") // simple non-reg to make sure we are not missing tests
    tests.foreach(test => {
      logger.info(s"running BOLT 3 test: '${test.name}'")
      val fee = commitTxTotalCost(dustLimit, test.spec, DefaultCommitmentFormat)
      assert(fee == test.expectedFee)
    })
  }

}