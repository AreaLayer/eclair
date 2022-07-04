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

package fr.acinq.eclair.crypto.keymanager

import com.google.common.cache.{CacheBuilder, CacheLoader, LoadingCache}
import fr.acinq.bitcoin.ScriptWitness
import fr.acinq.bitcoin.psbt.{Psbt, SignPsbtResult, UpdateFailure}
import fr.acinq.bitcoin.scalacompat.Crypto.{PrivateKey, PublicKey}
import fr.acinq.bitcoin.scalacompat.DeterministicWallet._
import fr.acinq.bitcoin.scalacompat.{Block, ByteVector32, ByteVector64, Crypto, DeterministicWallet}
import fr.acinq.bitcoin.utils.EitherKt
import fr.acinq.eclair.crypto.Generators
import fr.acinq.eclair.crypto.Monitoring.{Metrics, Tags}
import fr.acinq.eclair.crypto.keymanager.LocalChannelKeyManager.keyBasePath
import fr.acinq.eclair.router.Announcements
import fr.acinq.eclair.transactions.{Scripts, Transactions}
import fr.acinq.eclair.transactions.Transactions.{CommitmentFormat, TransactionWithInputInfo, TxOwner}
import fr.acinq.eclair.{KamonExt, randomLong}
import grizzled.slf4j.Logging
import kamon.tag.TagSet
import kotlin.jvm.functions
import scodec.bits.ByteVector

import java.util
import scala.jdk.CollectionConverters.MapHasAsScala

object LocalChannelKeyManager {
  def keyBasePath(chainHash: ByteVector32): List[Long] = (chainHash: @unchecked) match {
    case Block.RegtestGenesisBlock.hash | Block.TestnetGenesisBlock.hash | Block.SignetGenesisBlock.hash => DeterministicWallet.hardened(46) :: DeterministicWallet.hardened(1) :: Nil
    case Block.LivenetGenesisBlock.hash => DeterministicWallet.hardened(47) :: DeterministicWallet.hardened(1) :: Nil
  }

  private def polyMod(cc: Long, value: Int): Long = {
    var c = cc;
    val c0 = c >> 35;
    c = ((c & 0x7ffffffffL) << 5) ^ value
    if ((c0 & 1L) != 0) c = c ^ 0xf5dee51989L
    if ((c0 & 2L) != 0) c = c ^ 0xa9fdca3312L
    if ((c0 & 4L) != 0) c = c ^ 0x1bab10e32dL
    if ((c0 & 8L) != 0) c = c ^ 0x3706b1677aL
    if ((c0 & 16L) != 0) c = c ^ 0x644d626ffdL
    c
  }

  def descriptorChecksum(span: String): String = {
    /** A character set designed such that:
     *  - The most common 'unprotected' descriptor characters (hex, keypaths) are in the first group of 32.
     *  - Case errors cause an offset that's a multiple of 32.
     *  - As many alphabetic characters are in the same group (while following the above restrictions).
     *
     * If p(x) gives the position of a character c in this character set, every group of 3 characters
     * (a,b,c) is encoded as the 4 symbols (p(a) & 31, p(b) & 31, p(c) & 31, (p(a) / 32) + 3 * (p(b) / 32) + 9 * (p(c) / 32).
     * This means that changes that only affect the lower 5 bits of the position, or only the higher 2 bits, will just
     * affect a single symbol.
     *
     * As a result, within-group-of-32 errors count as 1 symbol, as do cross-group errors that don't affect
     * the position within the groups.
     */
    val INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}" + "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" + "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "

    /** The character set for the checksum itself (same as bech32). */
    val CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    var c = 1L;
    var cls = 0;
    var clscount = 0;
    span.foreach(ch => {
      val pos = INPUT_CHARSET.indexOf(ch);
      if (pos == -1) return "";
      c = polyMod(c, pos & 31); // Emit a symbol for the position inside the group, for every character.
      cls = cls * 3 + (pos >> 5); // Accumulate the group numbers
      clscount = clscount + 1
      if (clscount == 3) {
        // Emit an extra symbol representing the group numbers, for every 3 characters.
        c = polyMod(c, cls);
        cls = 0;
        clscount = 0;
      }
    })
    if (clscount > 0) c = polyMod(c, cls);
    for (j <- 0 until 8) c = polyMod(c, 0); // Shift further to determine the checksum.
    c ^= 1; // Prevent appending zeroes from not affecting the checksum.

    var ret = "        "
    for (j <- 0 until 8) {
      val pos1 = (c >> (5 * (7 - j))) & 31
      val char = CHECKSUM_CHARSET.charAt(pos1.toInt);
      ret = ret.updated(j, char)
    }
    ret
  }
}

/**
 * This class manages channel secrets and private keys.
 * It exports points and public keys, and provides signing methods
 *
 * @param seed seed from which the channel keys will be derived
 */
class LocalChannelKeyManager(seed: ByteVector, chainHash: ByteVector32) extends ChannelKeyManager with Logging {
  private val master = DeterministicWallet.generate(seed)

  private val privateKeys: LoadingCache[KeyPath, ExtendedPrivateKey] = CacheBuilder.newBuilder()
    .maximumSize(6 * 200) // 6 keys per channel * 200 channels
    .build[KeyPath, ExtendedPrivateKey](new CacheLoader[KeyPath, ExtendedPrivateKey] {
      override def load(keyPath: KeyPath): ExtendedPrivateKey = derivePrivateKey(master, keyPath)
    })

  private val publicKeys: LoadingCache[KeyPath, ExtendedPublicKey] = CacheBuilder.newBuilder()
    .maximumSize(6 * 200) // 6 keys per channel * 200 channels
    .build[KeyPath, ExtendedPublicKey](new CacheLoader[KeyPath, ExtendedPublicKey] {
      override def load(keyPath: KeyPath): ExtendedPublicKey = publicKey(privateKeys.get(keyPath))
    })

  private def internalKeyPath(channelKeyPath: DeterministicWallet.KeyPath, index: Long): KeyPath = KeyPath((LocalChannelKeyManager.keyBasePath(chainHash) ++ channelKeyPath.path) :+ index)

  private def fundingPrivateKey(channelKeyPath: DeterministicWallet.KeyPath): ExtendedPrivateKey = privateKeys.get(internalKeyPath(channelKeyPath, hardened(0)))

  private def revocationSecret(channelKeyPath: DeterministicWallet.KeyPath): ExtendedPrivateKey = privateKeys.get(internalKeyPath(channelKeyPath, hardened(1)))

  private def paymentSecret(channelKeyPath: DeterministicWallet.KeyPath): ExtendedPrivateKey = privateKeys.get(internalKeyPath(channelKeyPath, hardened(2)))

  private def delayedPaymentSecret(channelKeyPath: DeterministicWallet.KeyPath): ExtendedPrivateKey = privateKeys.get(internalKeyPath(channelKeyPath, hardened(3)))

  private def htlcSecret(channelKeyPath: DeterministicWallet.KeyPath): ExtendedPrivateKey = privateKeys.get(internalKeyPath(channelKeyPath, hardened(4)))

  private def shaSeed(channelKeyPath: DeterministicWallet.KeyPath): ByteVector32 = Crypto.sha256(privateKeys.get(internalKeyPath(channelKeyPath, hardened(5))).privateKey.value :+ 1.toByte)

  override def newFundingKeyPath(isInitiator: Boolean): KeyPath = {
    val last = DeterministicWallet.hardened(if (isInitiator) 1 else 0)

    def next(): Long = randomLong() & 0xFFFFFFFFL

    DeterministicWallet.KeyPath(Seq(next(), next(), next(), next(), next(), next(), next(), next(), last))
  }

  override def fundingPublicKey(channelKeyPath: DeterministicWallet.KeyPath): ExtendedPublicKey = publicKeys.get(internalKeyPath(channelKeyPath, hardened(0)))

  override def revocationPoint(channelKeyPath: DeterministicWallet.KeyPath): ExtendedPublicKey = publicKeys.get(internalKeyPath(channelKeyPath, hardened(1)))

  override def paymentPoint(channelKeyPath: DeterministicWallet.KeyPath): ExtendedPublicKey = publicKeys.get(internalKeyPath(channelKeyPath, hardened(2)))

  override def delayedPaymentPoint(channelKeyPath: DeterministicWallet.KeyPath): ExtendedPublicKey = publicKeys.get(internalKeyPath(channelKeyPath, hardened(3)))

  override def htlcPoint(channelKeyPath: DeterministicWallet.KeyPath): ExtendedPublicKey = publicKeys.get(internalKeyPath(channelKeyPath, hardened(4)))

  override def commitmentSecret(channelKeyPath: DeterministicWallet.KeyPath, index: Long): PrivateKey = Generators.perCommitSecret(shaSeed(channelKeyPath), index)

  override def commitmentPoint(channelKeyPath: DeterministicWallet.KeyPath, index: Long): PublicKey = Generators.perCommitPoint(shaSeed(channelKeyPath), index)

  /**
   * @param tx               input transaction
   * @param publicKey        extended public key
   * @param txOwner          owner of the transaction (local/remote)
   * @param commitmentFormat format of the commitment tx
   * @return a signature generated with the private key that matches the input extended public key
   */
  override def sign(tx: TransactionWithInputInfo, publicKey: ExtendedPublicKey, txOwner: TxOwner, commitmentFormat: CommitmentFormat): ByteVector64 = {
    // NB: not all those transactions are actually commit txs (especially during closing), but this is good enough for monitoring purposes
    val tags = TagSet.Empty.withTag(Tags.TxOwner, txOwner.toString).withTag(Tags.TxType, Tags.TxTypes.CommitTx)
    Metrics.SignTxCount.withTags(tags).increment()
    KamonExt.time(Metrics.SignTxDuration.withTags(tags)) {
      val privateKey = privateKeys.get(publicKey.path)
      Transactions.sign(tx, privateKey.privateKey, txOwner, commitmentFormat)
    }
  }

  /**
   * This method is used to spend funds sent to htlc keys/delayed keys
   *
   * @param tx               input transaction
   * @param publicKey        extended public key
   * @param remotePoint      remote point
   * @param txOwner          owner of the transaction (local/remote)
   * @param commitmentFormat format of the commitment tx
   * @return a signature generated with a private key generated from the input key's matching private key and the remote point.
   */
  override def sign(tx: TransactionWithInputInfo, publicKey: ExtendedPublicKey, remotePoint: PublicKey, txOwner: TxOwner, commitmentFormat: CommitmentFormat): ByteVector64 = {
    // NB: not all those transactions are actually htlc txs (especially during closing), but this is good enough for monitoring purposes
    val tags = TagSet.Empty.withTag(Tags.TxOwner, txOwner.toString).withTag(Tags.TxType, Tags.TxTypes.HtlcTx)
    Metrics.SignTxCount.withTags(tags).increment()
    KamonExt.time(Metrics.SignTxDuration.withTags(tags)) {
      val privateKey = privateKeys.get(publicKey.path)
      val currentKey = Generators.derivePrivKey(privateKey.privateKey, remotePoint)
      Transactions.sign(tx, currentKey, txOwner, commitmentFormat)
    }
  }

  /**
   * Ths method is used to spend revoked transactions, with the corresponding revocation key
   *
   * @param tx               input transaction
   * @param publicKey        extended public key
   * @param remoteSecret     remote secret
   * @param txOwner          owner of the transaction (local/remote)
   * @param commitmentFormat format of the commitment tx
   * @return a signature generated with a private key generated from the input key's matching private key and the remote secret.
   */
  override def sign(tx: TransactionWithInputInfo, publicKey: ExtendedPublicKey, remoteSecret: PrivateKey, txOwner: TxOwner, commitmentFormat: CommitmentFormat): ByteVector64 = {
    val tags = TagSet.Empty.withTag(Tags.TxOwner, txOwner.toString).withTag(Tags.TxType, Tags.TxTypes.RevokedTx)
    Metrics.SignTxCount.withTags(tags).increment()
    KamonExt.time(Metrics.SignTxDuration.withTags(tags)) {
      val privateKey = privateKeys.get(publicKey.path)
      val currentKey = Generators.revocationPrivKey(privateKey.privateKey, remoteSecret)
      Transactions.sign(tx, currentKey, txOwner, commitmentFormat)
    }
  }

  override def signChannelAnnouncement(witness: ByteVector, fundingKeyPath: KeyPath): ByteVector64 =
    Announcements.signChannelAnnouncement(witness, privateKeys.get(fundingKeyPath).privateKey)

  override def getAccountPubKey(keyPath: KeyPath): ExtendedPublicKey = publicKey(derivePrivateKey(master, keyPath))

  override def getDescriptors(): (List[String], List[String]) = {
    val (keyPath: String, prefix: Int) = chainHash match {
      case Block.RegtestGenesisBlock.hash | Block.TestnetGenesisBlock.hash => "84'/1'/0'/0" -> tpub
      case Block.LivenetGenesisBlock.hash => "84'/0'/0'/0" -> xpub
      case _ => throw new IllegalArgumentException(s"invalid chain hash ${chainHash}")
    }
    val accountPub = getAccountPubKey(KeyPath(keyPath))
    val fingerprint = DeterministicWallet.fingerprint(master) & 0xFFFFFFFFL
    val accountDesc = s"wpkh([${fingerprint.toHexString}/$keyPath]${encode(accountPub, prefix)}/0/*)"
    val changeDesc = s"wpkh([${fingerprint.toHexString}/$keyPath]${encode(accountPub, prefix)}/1/*)"
    (
      List(s"$accountDesc#${LocalChannelKeyManager.descriptorChecksum(accountDesc)}"),
      List(s"$changeDesc#${LocalChannelKeyManager.descriptorChecksum(changeDesc)}")
    )
  }

  override def signPsbt(psbt: Psbt): Psbt = {
    import fr.acinq.bitcoin.{SigHash, SigVersion, Script, Transaction}
    import fr.acinq.bitcoin.scalacompat.KotlinUtils._

    // check that outputs send either to one of our key or to a funding tx (a multisig 2-2 for which we have one of the 2 keys)
    for (i <- 0 until psbt.getOutputs.size()) {
      val output = psbt.getOutputs.get(i)
      val txout = psbt.getGlobal.getTx.txOut.get(i)
      output.getDerivationPaths.size() match {
        case 2 =>
          // check that this output is a multisig 2-2 funding tx output, and that we own one of the keys
          var count = 0
          val paths = output.getDerivationPaths.asScala.toList
          paths.foreach { case (pub, keypath) =>
            // add the chain-specific prefix
            val prefix = KeyPath(keyBasePath(this.chainHash))
            val path1 = prefix.keyPath.append(keypath.getKeyPath)
            val priv = fr.acinq.bitcoin.DeterministicWallet.derivePrivateKey(master.priv, path1).getPrivateKey
            val check = priv.publicKey()
            if (pub == check) count = count + 1
          }
          require(count >= 1)
          val script = fr.acinq.bitcoin.scalacompat.Script.write(fr.acinq.bitcoin.scalacompat.Script.pay2wsh(Scripts.multiSig2of2(paths(0)._1, paths(1)._1)))
          assert(script == kmp2scala(txout.publicKeyScript))
        case 1 =>
          // change output, check that we own the key
          output.getDerivationPaths.asScala.foreach { case (pub, keypath) =>
            val priv = fr.acinq.bitcoin.DeterministicWallet.derivePrivateKey(master.priv, keypath.getKeyPath).getPrivateKey
            val check = priv.publicKey()
            require(pub == check)
          }
        case _ => throw new IllegalArgumentException("invalid psbt")
      }
    }
    var psbt1 = psbt
    for (pos <- 0 until psbt1.getInputs.size()) {
      val input = psbt1.getInput(pos)
      input.getDerivationPaths.asScala.foreach { case (pub, keypath) =>
        val priv = fr.acinq.bitcoin.DeterministicWallet.derivePrivateKey(master.priv, keypath.getKeyPath).getPrivateKey
        val check = priv.publicKey()
        assert(check == pub)
        assert(Script.isPay2wpkh(input.getWitnessUtxo.publicKeyScript.toByteArray))
        val updated = psbt1.updateWitnessInput(psbt1.getGlobal.getTx.txIn.get(pos).outPoint, input.getWitnessUtxo, null, Script.pay2pkh(pub), SigHash.SIGHASH_ALL, input.getDerivationPaths)
        val signed = EitherKt.flatMap(updated, (p: Psbt) => p.sign(priv, pos))
        val finalized = EitherKt.flatMap(signed, (p: SignPsbtResult) => p.getPsbt.finalizeWitnessInput(pos, new ScriptWitness().push(p.getSig).push(pub.value)))
        if (finalized.isLeft) {
          throw new RuntimeException(finalized.getLeft.toString)
        } else {
          psbt1 = finalized.getRight
        }
      }
    }
    psbt1
  }
}