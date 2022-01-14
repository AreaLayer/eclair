/*
 * Copyright 2021 ACINQ SAS
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

package fr.acinq.eclair.channel.publish

import akka.actor.typed.scaladsl.{ActorContext, Behaviors, TimerScheduler}
import akka.actor.typed.{ActorRef, Behavior}
import fr.acinq.bitcoin.{OutPoint, Transaction}
import fr.acinq.eclair.blockchain.bitcoind.ZmqWatcher
import fr.acinq.eclair.blockchain.bitcoind.rpc.BitcoinCoreClient
import fr.acinq.eclair.blockchain.fee.{FeeEstimator, FeeratePerKw}
import fr.acinq.eclair.channel.publish.ReplaceableTxFunder.FundedTx
import fr.acinq.eclair.channel.publish.ReplaceableTxPrePublisher.{ClaimLocalAnchorWithWitnessData, ReplaceableTxWithWitnessData}
import fr.acinq.eclair.channel.publish.TxPublisher.TxPublishLogContext
import fr.acinq.eclair.{BlockHeight, NodeParams}

import scala.concurrent.duration.{DurationInt, DurationLong}
import scala.concurrent.{ExecutionContext, Future}
import scala.util.Random

/**
 * Created by t-bast on 10/06/2021.
 */

/**
 * This actor sets the fees, signs and publishes a transaction that can be RBF-ed.
 * It regularly RBFs the transaction as we get closer to its confirmation target.
 * It waits for confirmation or failure before reporting back to the requesting actor.
 */
object ReplaceableTxPublisher {

  // @formatter:off
  sealed trait Command
  case class Publish(replyTo: ActorRef[TxPublisher.PublishTxResult], cmd: TxPublisher.PublishReplaceableTx) extends Command
  case object Stop extends Command

  private case class WrappedPreconditionsResult(result: ReplaceableTxPrePublisher.PreconditionsResult) extends Command
  private case object TimeLocksOk extends Command
  private case class WrappedFundingResult(result: ReplaceableTxFunder.FundingResult) extends Command
  private case class WrappedTxResult(result: MempoolTxMonitor.TxResult) extends Command
  private case class CheckFee(currentBlockCount: Long) extends Command
  private case class BumpFee(targetFeerate: FeeratePerKw) extends Command
  private case object UnlockUtxos extends Command
  private case object UtxosUnlocked extends Command
  // @formatter:on

  // Timer key to ensure we don't have multiple concurrent timers running.
  private case object CheckFeeKey

  def apply(nodeParams: NodeParams, bitcoinClient: BitcoinCoreClient, watcher: ActorRef[ZmqWatcher.Command], loggingInfo: TxPublishLogContext): Behavior[Command] = {
    Behaviors.setup { context =>
      Behaviors.withTimers { timers =>
        Behaviors.withMdc(loggingInfo.mdc()) {
          Behaviors.receiveMessagePartial {
            case Publish(replyTo, cmd) => new ReplaceableTxPublisher(nodeParams, replyTo, cmd, bitcoinClient, watcher, context, timers, loggingInfo).checkPreconditions()
            case Stop => Behaviors.stopped
          }
        }
      }
    }
  }

  def getFeerate(feeEstimator: FeeEstimator, confirmBefore: BlockHeight, currentBlockHeight: BlockHeight): FeeratePerKw = {
    val remainingBlocks = (confirmBefore - currentBlockHeight).toLong
    val blockTarget = remainingBlocks match {
      // If our target is still very far in the future, no need to rush
      case t if t >= 144 => 144
      case t if t >= 72 => 72
      case t if t >= 36 => 36
      // However, if we get closer to the target, we start being more aggressive
      case t if t >= 18 => 12
      case t if t >= 12 => 6
      case t if t >= 2 => 2
      case _ => 1
    }
    feeEstimator.getFeeratePerKw(blockTarget)
  }

}

private class ReplaceableTxPublisher(nodeParams: NodeParams,
                                     replyTo: ActorRef[TxPublisher.PublishTxResult],
                                     cmd: TxPublisher.PublishReplaceableTx,
                                     bitcoinClient: BitcoinCoreClient,
                                     watcher: ActorRef[ZmqWatcher.Command],
                                     context: ActorContext[ReplaceableTxPublisher.Command],
                                     timers: TimerScheduler[ReplaceableTxPublisher.Command],
                                     loggingInfo: TxPublishLogContext)(implicit ec: ExecutionContext = ExecutionContext.Implicits.global) {

  import ReplaceableTxPublisher._

  private val log = context.log

  def checkPreconditions(): Behavior[Command] = {
    val prePublisher = context.spawn(ReplaceableTxPrePublisher(nodeParams, bitcoinClient, loggingInfo), "pre-publisher")
    prePublisher ! ReplaceableTxPrePublisher.CheckPreconditions(context.messageAdapter[ReplaceableTxPrePublisher.PreconditionsResult](WrappedPreconditionsResult), cmd)
    Behaviors.receiveMessagePartial {
      case WrappedPreconditionsResult(result) =>
        result match {
          case ReplaceableTxPrePublisher.PreconditionsOk(txWithWitnessData) => checkTimeLocks(txWithWitnessData)
          case ReplaceableTxPrePublisher.PreconditionsFailed(reason) => sendResult(TxPublisher.TxRejected(loggingInfo.id, cmd, reason))
        }
      case Stop =>
        prePublisher ! ReplaceableTxPrePublisher.Stop
        Behaviors.stopped
    }
  }

  def checkTimeLocks(txWithWitnessData: ReplaceableTxWithWitnessData): Behavior[Command] = {
    txWithWitnessData match {
      // There are no time locks on anchor transactions, we can claim them right away.
      case _: ClaimLocalAnchorWithWitnessData => fund(txWithWitnessData)
      case _ =>
        val timeLocksChecker = context.spawn(TxTimeLocksMonitor(nodeParams, watcher, loggingInfo), "time-locks-monitor")
        timeLocksChecker ! TxTimeLocksMonitor.CheckTx(context.messageAdapter[TxTimeLocksMonitor.TimeLocksOk](_ => TimeLocksOk), cmd.txInfo.tx, cmd.desc)
        Behaviors.receiveMessagePartial {
          case TimeLocksOk => fund(txWithWitnessData)
          case Stop =>
            timeLocksChecker ! TxTimeLocksMonitor.Stop
            Behaviors.stopped
        }
    }
  }

  def fund(txWithWitnessData: ReplaceableTxWithWitnessData): Behavior[Command] = {
    val targetFeerate = getFeerate(nodeParams.onChainFeeConf.feeEstimator, cmd.txInfo.confirmBefore, BlockHeight(nodeParams.currentBlockHeight))
    val txFunder = context.spawn(ReplaceableTxFunder(nodeParams, bitcoinClient, loggingInfo), "tx-funder")
    txFunder ! ReplaceableTxFunder.FundTransaction(context.messageAdapter[ReplaceableTxFunder.FundingResult](WrappedFundingResult), cmd, Right(txWithWitnessData), targetFeerate)
    Behaviors.receiveMessagePartial {
      case WrappedFundingResult(result) =>
        result match {
          case ReplaceableTxFunder.TransactionReady(tx) =>
            val txMonitor = context.spawn(MempoolTxMonitor(nodeParams, bitcoinClient, loggingInfo), "mempool-tx-monitor")
            txMonitor ! MempoolTxMonitor.Publish(context.messageAdapter[MempoolTxMonitor.TxResult](WrappedTxResult), tx.signedTx, cmd.input, cmd.desc, tx.fee)
            wait(Seq(tx))
          case ReplaceableTxFunder.FundingFailed(reason) => sendResult(TxPublisher.TxRejected(loggingInfo.id, cmd, reason))
        }
      case Stop =>
        // We can't stop right now, the child actor is currently funding the transaction and will send its result soon.
        // We just wait for the funding process to finish before stopping (in the next state).
        timers.startSingleTimer(Stop, 1 second)
        Behaviors.same
    }
  }

  // Wait for our transaction to be confirmed or rejected from the mempool.
  // If we get close to the confirmation target and our transaction is stuck in the mempool, we will initiate an RBF attempt.
  def wait(txs: Seq[FundedTx]): Behavior[Command] = {
    require(txs.nonEmpty, "there is always one tx") // could be "if txs.isEmpty then stop" instead ?
    Behaviors.receiveMessagePartial {
      case WrappedTxResult(txResult) =>
        txResult match {
          case MempoolTxMonitor.TxInMempool(txid, currentBlockCount) =>
            if (txid == txs.last.signedTx.txid) {
              // We avoid a herd effect whenever we fee bump transactions.
              timers.startSingleTimer(CheckFeeKey, CheckFee(currentBlockCount), (1 + Random.nextLong(nodeParams.maxTxPublishRetryDelay.toMillis)).millis)
              Behaviors.same
            } else {
              // this is for an old tx: ignore
              Behaviors.same
            }
          case MempoolTxMonitor.TxRecentlyConfirmed(_, _) => Behaviors.same // just wait for the tx to be deeply buried
          case MempoolTxMonitor.TxDeeplyBuried(confirmedTx) =>
            replyTo ! TxPublisher.TxConfirmed(cmd, confirmedTx)
            unlockAndStop(cmd.input, txs.map(_.signedTx))
          case MempoolTxMonitor.TxRejected(txid, reason) =>
            val failedTx = txs.find(_.signedTx.txid == txid).get.signedTx
            if (txs.size == 1) {
              replyTo ! TxPublisher.TxRejected(loggingInfo.id, cmd, reason)
              // We wait for our parent to stop us: when that happens we will unlock utxos.
              Behaviors.same
            } else if (txid == txs.last.signedTx.txid) {
              log.warn("{} transaction paying more fees (txid={}) failed to replace previous transaction", cmd.desc, txid)
              cleanUpFailedTxAndWait(failedTx, txs.filterNot(_.signedTx.txid == txid))
            } else {
              log.info("previous {} probably replaced by new transaction paying more fees (txid={})", cmd.desc, txs.last.signedTx.txid)
              cleanUpFailedTxAndWait(failedTx, txs.filterNot(_.signedTx.txid == txid))
            }
        }
      case CheckFee(currentBlockCount) =>
        // We make sure we increase the fees by at least 20% as we get closer to the confirmation target.
        val bumpRatio = 1.2
        val currentFeerate = getFeerate(nodeParams.onChainFeeConf.feeEstimator, cmd.txInfo.confirmBefore, BlockHeight(currentBlockCount))
        val tx = txs.last
        if (cmd.txInfo.confirmBefore.toLong <= currentBlockCount + 6) {
          log.debug("{} confirmation target is close (in {} blocks): bumping fees", cmd.desc, cmd.txInfo.confirmBefore.toLong - currentBlockCount)
          context.self ! BumpFee(currentFeerate.max(tx.feerate * bumpRatio))
        } else if (tx.feerate * bumpRatio <= currentFeerate) {
          log.debug("{} confirmation target is in {} blocks: bumping fees", cmd.desc, cmd.txInfo.confirmBefore.toLong - currentBlockCount)
          context.self ! BumpFee(currentFeerate)
        } else {
          log.debug("{} confirmation target is in {} blocks: no need to bump fees", cmd.desc, cmd.txInfo.confirmBefore.toLong - currentBlockCount)
        }
        Behaviors.same
      case BumpFee(targetFeerate) => fundReplacement(targetFeerate, txs)
      case Stop => unlockAndStop(cmd.input, txs.map(_.signedTx))
    }
  }

  // Fund a replacement transaction because our previous attempt seems to be stuck in the mempool.
  def fundReplacement(targetFeerate: FeeratePerKw, txs: Seq[FundedTx]): Behavior[Command] = {
    val previousTx = txs.last
    log.info("bumping {} fees: previous feerate={}, next feerate={}", cmd.desc, previousTx.feerate, targetFeerate)
    val txFunder = context.spawn(ReplaceableTxFunder(nodeParams, bitcoinClient, loggingInfo), "tx-funder-rbf")
    txFunder ! ReplaceableTxFunder.FundTransaction(context.messageAdapter[ReplaceableTxFunder.FundingResult](WrappedFundingResult), cmd, Left(previousTx), targetFeerate)
    Behaviors.receiveMessagePartial {
      case WrappedFundingResult(result) =>
        result match {
          case success: ReplaceableTxFunder.TransactionReady =>
            // Publish an RBF attempt. We then have two concurrent transactions: the previous one and the updated one.
            // Only one of them can be in the mempool, so we wait for the other to be rejected. Once that's done, we're back to a
            // situation where we have one transaction in the mempool and wait for it to confirm.
            val bumpedTx = success.fundedTx
            val txMonitor = context.spawn(MempoolTxMonitor(nodeParams, bitcoinClient, loggingInfo), s"mempool-tx-monitor-rbf-${bumpedTx.signedTx.txid}")
            txMonitor ! MempoolTxMonitor.Publish(context.messageAdapter[MempoolTxMonitor.TxResult](WrappedTxResult), bumpedTx.signedTx, cmd.input, cmd.desc, bumpedTx.fee)
            wait(txs :+ bumpedTx)
          case ReplaceableTxFunder.FundingFailed(_) =>
            log.warn("could not fund {} replacement transaction", cmd.desc)
            wait(txs)
        }
      case txResult: WrappedTxResult =>
        // This is the result of the previous publishing attempt.
        // We don't need to handle it now that we're in the middle of funding, we can defer it to the next state.
        timers.startSingleTimer(txResult, 1 second)
        Behaviors.same
      case Stop =>
        // We can't stop right away, because the child actor may need to unlock utxos first.
        // We just wait for the funding process to finish before stopping.
        timers.startSingleTimer(Stop, 1 second)
        Behaviors.same
    }
  }

  // Clean up the failed transaction attempt. Once that's done, go back to the waiting state with the new transaction.
  def cleanUpFailedTxAndWait(failedTx: Transaction, mempoolTxs: Seq[FundedTx]): Behavior[Command] = {
    context.pipeToSelf(bitcoinClient.abandonTransaction(failedTx.txid))(_ => UnlockUtxos)
    Behaviors.receiveMessagePartial {
      case UnlockUtxos =>
        val toUnlock = failedTx.txIn.map(_.outPoint).toSet -- mempoolTxs.flatMap(_.signedTx.txIn).map(_.outPoint).toSet
        if (toUnlock.isEmpty) {
          context.self ! UtxosUnlocked
        } else {
          log.debug("unlocking utxos={}", toUnlock.mkString(", "))
          context.pipeToSelf(bitcoinClient.unlockOutpoints(toUnlock.toSeq))(_ => UtxosUnlocked)
        }
        Behaviors.same
      case UtxosUnlocked =>
        // Now that we've cleaned up the failed transaction, we can go back to waiting for the current mempool transaction
        // or bump it if it doesn't confirm fast enough either.
        wait(mempoolTxs)
      case txResult: WrappedTxResult =>
        // This is the result of the current mempool tx: we will handle this command once we're back in the waiting
        // state for this transaction.
        timers.startSingleTimer(txResult, 1 second)
        Behaviors.same
      case Stop =>
        // We don't stop right away, because we're cleaning up the failed transaction.
        // This shouldn't take long so we'll handle this command once we're back in the waiting state.
        timers.startSingleTimer(Stop, 1 second)
        Behaviors.same
    }
  }

  def unlockAndStop(input: OutPoint, txs: Seq[Transaction]): Behavior[Command] = {
    // The bitcoind wallet will keep transactions around even when they can't be published (e.g. one of their inputs has
    // disappeared but bitcoind thinks it may reappear later), hoping that it will be able to automatically republish
    // them later. In our case this is unnecessary, we will publish ourselves, and we don't want to pollute the wallet
    // state with transactions that will never be valid, so we eagerly abandon every time.
    // If the transaction is in the mempool or confirmed, it will be a no-op.
    context.pipeToSelf(Future.traverse(txs)(tx => bitcoinClient.abandonTransaction(tx.txid)))(_ => UnlockUtxos)
    Behaviors.receiveMessagePartial {
      case UnlockUtxos =>
        val toUnlock = txs.flatMap(_.txIn).filterNot(_.outPoint == input).map(_.outPoint).toSet
        if (toUnlock.isEmpty) {
          context.self ! UtxosUnlocked
        } else {
          log.debug("unlocking utxos={}", toUnlock.mkString(", "))
          context.pipeToSelf(bitcoinClient.unlockOutpoints(toUnlock.toSeq))(_ => UtxosUnlocked)
        }
        Behaviors.same
      case UtxosUnlocked =>
        log.debug("utxos unlocked")
        Behaviors.stopped
      case Stop =>
        log.debug("waiting for utxos to be unlocked before stopping")
        Behaviors.same
    }
  }

  /** Use this function to send the result upstream and stop without stopping child actors. */
  def sendResult(result: TxPublisher.PublishTxResult): Behavior[Command] = {
    replyTo ! result
    Behaviors.receiveMessagePartial {
      case Stop => Behaviors.stopped
    }
  }

}

