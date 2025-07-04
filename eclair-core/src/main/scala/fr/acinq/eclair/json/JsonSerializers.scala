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

package fr.acinq.eclair.json

import com.google.common.net.HostAndPort
import fr.acinq.bitcoin.scalacompat.Crypto.{PrivateKey, PublicKey}
import fr.acinq.bitcoin.scalacompat.DeterministicWallet.KeyPath
import fr.acinq.bitcoin.scalacompat.{BlockHash, BlockId, Btc, ByteVector32, ByteVector64, OutPoint, Satoshi, Transaction, TxId}
import fr.acinq.eclair.balance.CheckBalance.{DetailedOnChainBalance, GlobalBalance, OffChainBalance}
import fr.acinq.eclair.blockchain.fee.FeeratePerKw
import fr.acinq.eclair.channel._
import fr.acinq.eclair.crypto.{ShaChain, Sphinx}
import fr.acinq.eclair.db.FailureType.FailureType
import fr.acinq.eclair.db.{IncomingPaymentStatus, OfferData, OutgoingPaymentStatus}
import fr.acinq.eclair.io.Peer
import fr.acinq.eclair.io.Peer.OpenChannelResponse
import fr.acinq.eclair.message.OnionMessages
import fr.acinq.eclair.payment.PaymentFailure.PaymentFailedSummary
import fr.acinq.eclair.payment._
import fr.acinq.eclair.router.Router._
import fr.acinq.eclair.transactions.DirectedHtlc
import fr.acinq.eclair.transactions.Transactions._
import fr.acinq.eclair.wire.protocol.OfferTypes.Offer
import fr.acinq.eclair.wire.protocol._
import fr.acinq.eclair.{Alias, BlockHeight, CltvExpiry, CltvExpiryDelta, EncodedNodeId, Feature, FeatureSupport, Features, MilliSatoshi, RealShortChannelId, ShortChannelId, TimestampMilli, TimestampSecond, UInt64, UnknownFeature}
import org.json4s
import org.json4s.JsonAST._
import org.json4s.jackson.Serialization
import org.json4s.{CustomSerializer, DefaultFormats, Extraction, Formats, JDecimal, JValue, KeySerializer, Serializer, ShortTypeHints, TypeHints, jackson}
import scodec.bits.ByteVector

import java.net.InetSocketAddress
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.util.UUID

/**
 * Minimal serializer that only does serialization, not deserialization, and does not depend on external formats.
 *
 * NB: this is a stripped-down version of [[org.json4s.CustomSerializer]]
 */
class MinimalSerializer(ser: PartialFunction[Any, JValue]) extends Serializer[Nothing] {

  def deserialize(implicit format: Formats): PartialFunction[(json4s.TypeInfo, JValue), Nothing] = PartialFunction.empty

  def serialize(implicit format: Formats): PartialFunction[Any, JValue] = ser
}

/** Same as above, but for [[org.json4s.CustomKeySerializer]] */
class MinimalKeySerializer(ser: PartialFunction[Any, String]) extends KeySerializer[Nothing] {

  def deserialize(implicit format: Formats): PartialFunction[(json4s.TypeInfo, String), Nothing] = PartialFunction.empty

  def serialize(implicit format: Formats): PartialFunction[Any, String] = ser
}

/**
 * Custom serializer where, instead of providing a `MyClass => JValue` conversion method, we provide a
 * `MyClass => MyClassJson` method, with the assumption that `MyClassJson` is serializable using the base serializers.
 *
 * The rationale is that it's easier to define the structure with types rather than by building json objects.
 *
 * Usage:
 * {{{
 *   /** A type used in eclair */
 *   case class Foo(a: String, b: Int, c: ByteVector32)
 *
 *   /** Special purpose type used only for serialization */
 *   private[json] case class FooJson(a: String, c: ByteVector32)
 *   object FooSerializer extends ConvertClassSerializer[Foo]({ foo: Foo =>
 *     FooJson(foo.a, foo.c)
 * }}}
 *
 */
class ConvertClassSerializer[T: Manifest](f: T => Any) extends Serializer[Nothing] {

  def deserialize(implicit format: Formats): PartialFunction[(json4s.TypeInfo, JValue), Nothing] = PartialFunction.empty

  def serialize(implicit format: Formats): PartialFunction[Any, JValue] = {
    case o: T => Extraction.decompose(f(o))
  }
}

object ActorRefSerializer extends MinimalSerializer({
  case _: akka.actor.ActorRef => JNothing
})

object TypedActorRefSerializer extends MinimalSerializer({
  case _: akka.actor.typed.ActorRef[_] => JNothing
})

object ByteVectorSerializer extends MinimalSerializer({
  case x: ByteVector => JString(x.toHex)
})

object ByteVector32Serializer extends MinimalSerializer({
  case x: ByteVector32 => JString(x.toHex)
})

object ByteVector32KeySerializer extends MinimalKeySerializer({
  case x: ByteVector32 => x.toHex
})

object ByteVector32KmpSerializer extends MinimalSerializer({
  case x: fr.acinq.bitcoin.ByteVector32 => JString(x.toHex)
})

object TxIdSerializer extends MinimalSerializer({
  case x: TxId => JString(x.value.toHex)
})

object TxIdKeySerializer extends MinimalKeySerializer({
  case x: TxId => x.value.toHex
})

object TxIdKmpSerializer extends MinimalSerializer({
  case x: fr.acinq.bitcoin.TxId => JString(x.value.toHex)
})

object BlockIdSerializer extends MinimalSerializer({
  case x: BlockId => JString(x.value.toHex)
})

object BlockIdKmpSerializer extends MinimalSerializer({
  case x: fr.acinq.bitcoin.BlockId => JString(x.value.toHex)
})

object BlockHashSerializer extends MinimalSerializer({
  case x: BlockHash => JString(x.value.toHex)
})

object BlockHashKmpSerializer extends MinimalSerializer({
  case x: fr.acinq.bitcoin.BlockHash => JString(x.value.toHex)
})

object ByteVector64Serializer extends MinimalSerializer({
  case x: ByteVector64 => JString(x.toHex)
})

object UInt64Serializer extends MinimalSerializer({
  case x: UInt64 => JInt(x.toBigInt)
})

// @formatter:off
private case class TimestampJson(iso: String, unix: Long)
object TimestampSecondSerializer extends ConvertClassSerializer[TimestampSecond](ts => TimestampJson(
  iso = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochSecond(ts.toLong)),
  unix = ts.toLong
))
object TimestampMilliSerializer extends ConvertClassSerializer[TimestampMilli](ts => TimestampJson(
  iso = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(ts.toLong)),
  unix = ts.toLong / 1000 // we convert to standard unix timestamp with second precision
))
// @formatter:on

object BtcSerializer extends MinimalSerializer({
  case x: Btc => JDecimal(x.toDouble)
})

object SatoshiSerializer extends MinimalSerializer({
  case x: Satoshi => JInt(x.toLong)
})

object MilliSatoshiSerializer extends MinimalSerializer({
  case x: MilliSatoshi => JInt(x.toLong)
})

object CltvExpirySerializer extends MinimalSerializer({
  case x: CltvExpiry => JLong(x.toLong)
})

object CltvExpiryDeltaSerializer extends MinimalSerializer({
  case x: CltvExpiryDelta => JInt(x.toInt)
})

object BlockHeightSerializer extends MinimalSerializer({
  case h: BlockHeight => JLong(h.toLong)
})

object FeeratePerKwSerializer extends MinimalSerializer({
  case x: FeeratePerKw => JLong(x.toLong)
})

object ShortChannelIdSerializer extends MinimalSerializer({
  case x: ShortChannelId => JString(x.toString)
})

object ChannelIdentifierSerializer extends MinimalKeySerializer({
  case Left(x: ByteVector32) => x.toHex
  case Right(x: ShortChannelId) => x.toString
})

object ChannelStateSerializer extends MinimalSerializer({
  case x: ChannelState => JString(x.toString)
})

object ShaChainSerializer extends MinimalSerializer({
  case _: ShaChain => JNull
})

object PublicKeySerializer extends MinimalSerializer({
  case x: PublicKey => JString(x.toString())
})

object PrivateKeySerializer extends MinimalSerializer({
  case _: PrivateKey => JString("XXX")
})

object FeatureKeySerializer extends MinimalKeySerializer({ case f: Feature => f.rfcName })

object FeatureSupportSerializer extends MinimalSerializer({ case s: FeatureSupport => JString(s.toString) })

object UnknownFeatureSerializer extends MinimalSerializer({ case f: UnknownFeature => JInt(f.bitIndex) })

object ChannelConfigSerializer extends MinimalSerializer({
  case x: ChannelConfig => JArray(x.options.toList.map(o => JString(o.name)))
})

object ChannelFeaturesSerializer extends MinimalSerializer({
  case channelFeatures: ChannelFeatures => JArray(channelFeatures.features.map(f => JString(f.rfcName)).toList)
})

object OpenChannelResponseSerializer extends MinimalSerializer({
  case x: OpenChannelResponse => JString(x.toString)
})

object CommandResponseSerializer extends MinimalSerializer({
  case RES_SUCCESS(_: CloseCommand, channelId) => JString(s"closed channel $channelId")
  case RES_SUCCESS(_, _) => JString("ok")
  case RES_FAILURE(_: Command, ex: Throwable) => JString(ex.getMessage)
})

object TransactionSerializer extends MinimalSerializer({
  case x: Transaction => JObject(List(
    JField("txid", JString(x.txid.value.toHex)),
    JField("tx", JString(x.toString()))
  ))
})

object KeyPathSerializer extends MinimalSerializer({
  case x: KeyPath => JArray(x.path.map(x => JLong(x)).toList)
})

object TransactionWithInputInfoSerializer extends MinimalSerializer({
  case x: HtlcTx => JObject(List(
    JField("txid", JString(x.tx.txid.value.toHex)),
    JField("tx", JString(x.tx.toString())),
    JField("paymentHash", JString(x.paymentHash.toString())),
    JField("htlcId", JLong(x.htlcId)),
    JField("htlcExpiry", JLong(x.htlcExpiry.toLong))
  ))
  case x: ClaimHtlcTx => JObject(List(
    JField("txid", JString(x.tx.txid.value.toHex)),
    JField("tx", JString(x.tx.toString())),
    JField("paymentHash", JString(x.paymentHash.toString())),
    JField("htlcId", JLong(x.htlcId)),
    JField("htlcExpiry", JLong(x.htlcExpiry.toLong))
  ))
  case x: HtlcPenaltyTx => JObject(List(
    JField("txid", JString(x.tx.txid.value.toHex)),
    JField("tx", JString(x.tx.toString())),
    JField("paymentHash", JString(x.paymentHash.toString())),
    JField("htlcExpiry", JLong(x.htlcExpiry.toLong))
  ))
  case x: ClosingTx =>
    val txFields = List(
      JField("txid", JString(x.tx.txid.value.toHex)),
      JField("tx", JString(x.tx.toString()))
    )
    x.toLocalOutput_opt match {
      case Some(toLocal) =>
        val toLocalField = JField("toLocalOutput", JObject(List(
          JField("amount", JLong(toLocal.amount.toLong)),
          JField("publicKeyScript", JString(toLocal.publicKeyScript.toHex))
        )))
        JObject(txFields :+ toLocalField)
      case None => JObject(txFields)
    }
  case x: TransactionWithInputInfo => JObject(List(
    JField("txid", JString(x.tx.txid.value.toHex)),
    JField("tx", JString(x.tx.toString()))
  ))
})

object InetSocketAddressSerializer extends MinimalSerializer({
  case address: InetSocketAddress => JString(HostAndPort.fromParts(address.getHostString, address.getPort).toString)
})

object OutPointSerializer extends MinimalSerializer({
  case x: OutPoint => JString(s"${x.txid}:${x.index}")
})

object OutPointKeySerializer extends MinimalKeySerializer({
  case x: OutPoint => s"${x.txid}:${x.index}"
})

// @formatter:off
private case class InputInfoJson(outPoint: OutPoint, amountSatoshis: Satoshi)
object InputInfoSerializer extends ConvertClassSerializer[InputInfo](i => InputInfoJson(i.outPoint, i.txOut.amount))
// @formatter:on

object ColorSerializer extends MinimalSerializer({
  case c: Color => JString(c.toString)
})

// @formatter:off
private sealed trait HopJson
private case class ChannelHopJson(nodeId: PublicKey, nextNodeId: PublicKey, source: HopRelayParams) extends HopJson
private case class BlindedHopJson(nodeId: PublicKey, nextNodeId: PublicKey, paymentInfo: OfferTypes.PaymentInfo) extends HopJson
private case class NodeHopJson(nodeId: PublicKey, nextNodeId: PublicKey, fee: MilliSatoshi, cltvExpiryDelta: CltvExpiryDelta) extends HopJson
private case class RouteFullJson(amount: MilliSatoshi, hops: Seq[HopJson])
object RouteFullSerializer extends ConvertClassSerializer[Route](route => {
  val channelHops = route.hops.map(h => ChannelHopJson(h.nodeId, h.nextNodeId, h.params))
  val finalHop_opt = route.finalHop_opt.map {
    case h: NodeHop => NodeHopJson(h.nodeId, h.nextNodeId, h.fee, h.cltvExpiryDelta)
    case h: BlindedHop => BlindedHopJson(h.nodeId, h.nextNodeId, h.paymentInfo)
  }
  RouteFullJson(route.amount, channelHops ++ finalHop_opt.toSeq)
})

private case class RouteNodeIdsJson(amount: MilliSatoshi, nodeIds: Seq[PublicKey])
object RouteNodeIdsSerializer extends ConvertClassSerializer[Route](route => {
  val channelNodeIds = route.hops.headOption match {
    case Some(hop) => Seq(hop.nodeId, hop.nextNodeId) ++ route.hops.tail.map(_.nextNodeId)
    case None => Nil
  }
  val finalNodeIds = route.finalHop_opt match {
    case Some(hop: NodeHop) if channelNodeIds.nonEmpty => Seq(hop.nextNodeId)
    case Some(hop: NodeHop) => Seq(hop.nodeId, hop.nextNodeId)
    case Some(hop: BlindedHop) if channelNodeIds.nonEmpty => hop.resolved.route.blindedNodeIds.tail
    case Some(hop: BlindedHop) => hop.nodeId +: hop.resolved.route.blindedNodeIds.tail
    case None => Nil
  }
  RouteNodeIdsJson(route.amount, channelNodeIds ++ finalNodeIds)
})

private case class RouteShortChannelIdsJson(amount: MilliSatoshi, shortChannelIds: Seq[ShortChannelId], finalHop: Option[String])
object RouteShortChannelIdsSerializer extends ConvertClassSerializer[Route](route => {
  val hops = route.hops.map(_.shortChannelId)
  val finalHop = route.finalHop_opt.map {
    case _: NodeHop => "trampoline"
    case _: BlindedHop => "blinded"
  }
  RouteShortChannelIdsJson(route.amount, hops, finalHop)
})
// @formatter:on

// @formatter:off
private case class PaymentFailureSummaryJson(amount: MilliSatoshi, route: Seq[PublicKey], message: String)
private case class PaymentFailedSummaryJson(paymentHash: ByteVector32, destination: PublicKey, pathFindingExperiment: String, failures: Seq[PaymentFailureSummaryJson])
object PaymentFailedSummarySerializer extends ConvertClassSerializer[PaymentFailedSummary](p => PaymentFailedSummaryJson(
  p.cfg.paymentHash,
  p.cfg.recipientNodeId,
  p.pathFindingExperiment,
  p.paymentFailed.failures.map(f => {
    val route = f.route.map(_.nodeId) ++ f.route.lastOption.map(_.nextNodeId)
    val message = f match {
      case LocalFailure(_, _, t) => t.getMessage
      case RemoteFailure(_, _, Sphinx.DecryptedFailurePacket(origin, failureMessage)) => s"$origin returned: ${failureMessage.message}"
      case _: UnreadableRemoteFailure => "unreadable remote failure"
    }
    PaymentFailureSummaryJson(f.amount, route, message)
  })
))
// @formatter:on

object ThrowableSerializer extends MinimalSerializer({
  case t: Throwable if t.getMessage != null => JString(t.getMessage)
  case t: Throwable => JString(t.getClass.getSimpleName)
})

object FailureMessageSerializer extends MinimalSerializer({
  case m: FailureMessage => JString(m.message)
})

object FailureTypeSerializer extends MinimalSerializer({
  case ft: FailureType => JString(ft.toString)
})

object NodeAddressSerializer extends MinimalSerializer({
  case n: NodeAddress => JString(n.toString)
})

// @formatter:off
// We only keep the most important htlc fields: serializing the onion and the tlv stream would waste memory for no good reason.
private case class DirectedHtlcJson(direction: String, id: Long, amountMsat: MilliSatoshi, paymentHash: ByteVector32, cltvExpiry: CltvExpiry)
object DirectedHtlcSerializer extends ConvertClassSerializer[DirectedHtlc](h => DirectedHtlcJson(h.direction, h.add.id, h.add.amountMsat, h.add.paymentHash, h.add.cltvExpiry))
// @formatter:on

object InvoiceSerializer extends MinimalSerializer({
  case p: Bolt11Invoice =>
    val expiry = p.tags
      .collectFirst { case expiry: Bolt11Invoice.Expiry => expiry.toLong } // NB: we look at fields directly because the value has a spec-defined default
      .map(ex => JField("expiry", JLong(ex))).toSeq
    val minFinalCltvExpiry = p.tags
      .collectFirst { case cltvExpiry: Bolt11Invoice.MinFinalCltvExpiry => cltvExpiry.toCltvExpiryDelta } // NB: we look at fields directly because the value has a spec-defined default
      .map(mfce => JField("minFinalCltvExpiry", JInt(mfce.toInt))).toSeq
    val amount = p.amount_opt.map(msat => JField("amount", JLong(msat.toLong))).toSeq
    val features = JField("features", Extraction.decompose(p.features)(
      DefaultFormats +
        FeatureKeySerializer +
        FeatureSupportSerializer +
        UnknownFeatureSerializer
    ))
    val paymentMetadata = p.paymentMetadata.map(m => JField("paymentMetadata", JString(m.toHex))).toSeq
    val routingInfo = JField("routingInfo", Extraction.decompose(p.routingInfo)(
      DefaultFormats +
        ByteVector32Serializer +
        ByteVectorSerializer +
        PublicKeySerializer +
        ShortChannelIdSerializer +
        MilliSatoshiSerializer +
        CltvExpiryDeltaSerializer
    ))
    val fieldList = List(
      JField("prefix", JString(p.prefix)),
      JField("timestamp", JLong(p.createdAt.toLong)),
      JField("nodeId", JString(p.nodeId.toString())),
      JField("serialized", JString(p.toString)),
      p.description.fold(string => JField("description", JString(string)), hash => JField("descriptionHash", JString(hash.toHex))),
      JField("paymentHash", JString(p.paymentHash.toString()))) ++
      paymentMetadata ++
      expiry ++
      minFinalCltvExpiry ++
      amount :+
      features :+
      routingInfo
    JObject(fieldList)
  case p: Bolt12Invoice =>
    val fieldList = List(
      Some(JField("amount", JLong(p.amount.toLong))),
      Some(JField("nodeId", JString(p.nodeId.toString()))),
      Some(JField("paymentHash", JString(p.paymentHash.toString()))),
      p.description.map(string => JField("description", JString(string))),
      Some(JField("features", Extraction.decompose(p.features)(
        DefaultFormats +
          FeatureKeySerializer +
          FeatureSupportSerializer +
          UnknownFeatureSerializer
      ))),
      Some(JField("blindedPaths", JArray(p.blindedPaths.map(path => {
        val introductionNode = path.route.firstNodeId.toString
        val blindedNodes = path.route.blindedHops
        JObject(List(
          JField("introductionNodeId", JString(introductionNode)),
          JField("blindedNodeIds", JArray(blindedNodes.map(n => JString(n.blindedPublicKey.toString)).toList))
        ))
      }).toList))),
      Some(JField("createdAt", JLong(p.createdAt.toLong))),
      Some(JField("expiresAt", JLong((p.createdAt + p.relativeExpiry).toLong))),
      Some(JField("serialized", JString(p.toString)))).flatten
    JObject(fieldList)
})

private case class BlindedRouteJson(firstNodeId: EncodedNodeId, length: Int)
private case class OfferJson(chains: Option[Seq[String]],
                             amount: Option[String],
                             currency: Option[String],
                             description: Option[String],
                             expiry: Option[TimestampSecond],
                             issuer: Option[String],
                             nodeId: Option[PublicKey],
                             paths: Option[Seq[BlindedRouteJson]],
                             quantityMax: Option[Long],
                             features: Option[Features[Feature]],
                             metadata: Option[String],
                             unknownTlvs: Option[Map[String, String]])
object OfferSerializer extends ConvertClassSerializer[Offer](o => {
  val fractionDigits = o.records.get[OfferTypes.OfferCurrency].map(_.currency.getDefaultFractionDigits()).getOrElse(3)
  OfferJson(
    chains = o.records.get[OfferTypes.OfferChains].map(_.chains.map(_.toString())),
    amount = o.records.get[OfferTypes.OfferAmount].map(a =>
      if (fractionDigits == 0) {
        a.amount.toString
      } else {
        val one = scala.math.pow(10, fractionDigits).toInt
        s"${a.amount / one}.%0${fractionDigits}d".format(a.amount % one)
      }
    ),
    currency = if (o.records.get[OfferTypes.OfferAmount].isEmpty) {
      None
    } else {
      Some(o.records.get[OfferTypes.OfferCurrency].map(_.currency.getCurrencyCode()).getOrElse("satoshi"))
    },
    description = o.records.get[OfferTypes.OfferDescription].map(_.description),
    expiry = o.records.get[OfferTypes.OfferAbsoluteExpiry].map(_.absoluteExpiry),
    issuer = o.records.get[OfferTypes.OfferIssuer].map(_.issuer),
    nodeId = o.records.get[OfferTypes.OfferNodeId].map(_.publicKey),
    paths = o.records.get[OfferTypes.OfferPaths].map(_.paths.map(p => BlindedRouteJson(p.firstNodeId, p.blindedHops.length))),
    quantityMax = o.records.get[OfferTypes.OfferQuantityMax].map(_.max),
    features = o.records.get[OfferTypes.OfferFeatures].map(f => Features(f.features)),
    metadata = o.records.get[OfferTypes.OfferMetadata].map(_.data.toHex),
    unknownTlvs = if (o.records.unknown.isEmpty) {
      None
    } else {
      Some(o.records.unknown.map(tlv => tlv.tag.toString -> tlv.value.toHex).toMap)
    }
  )
})

private case class OfferDataJson(amountMsat: Option[MilliSatoshi],
                                 description: Option[String],
                                 issuer: Option[String],
                                 nodeId: Option[PublicKey],
                                 blindedPathFirstNodeId: Option[PublicKey],
                                 createdAt: TimestampMilli,
                                 expiry: Option[TimestampSecond],
                                 disabled: Boolean,
                                 disabledAt: Option[TimestampMilli],
                                 encoded: String)
object OfferDataSerializer extends ConvertClassSerializer[OfferData](o => OfferDataJson(
  amountMsat = o.offer.amount,
  description = o.offer.description,
  issuer = o.offer.issuer,
  nodeId = o.offer.nodeId,
  blindedPathFirstNodeId = o.offer.contactInfos.collect { case OfferTypes.BlindedPath(path) => path.firstNodeId }.collectFirst { case p: EncodedNodeId.WithPublicKey => p.publicKey },
  createdAt = o.createdAt,
  expiry = o.offer.expiry,
  disabled = o.disabled,
  disabledAt = o.disabledAt_opt,
  encoded = o.offer.encode()
))

object JavaUUIDSerializer extends MinimalSerializer({
  case id: UUID => JString(id.toString)
})

object ChannelEventSerializer extends MinimalSerializer({
  case e: ChannelCreated => JObject(
    JField("type", JString("channel-created")),
    JField("remoteNodeId", JString(e.remoteNodeId.toString())),
    JField("isOpener", JBool(e.isOpener)),
    JField("temporaryChannelId", JString(e.temporaryChannelId.toHex)),
    JField("commitTxFeeratePerKw", JLong(e.commitTxFeerate.toLong)),
    JField("fundingTxFeeratePerKw", e.fundingTxFeerate.map(f => JLong(f.toLong)).getOrElse(JNothing))
  )
  case e: ChannelOpened => JObject(
    JField("type", JString("channel-opened")),
    JField("remoteNodeId", JString(e.remoteNodeId.toString())),
    JField("channelId", JString(e.channelId.toHex)),
  )
  case e: ChannelStateChanged => JObject(
    JField("type", JString("channel-state-changed")),
    JField("channelId", JString(e.channelId.toHex)),
    JField("remoteNodeId", JString(e.remoteNodeId.toString())),
    JField("previousState", JString(e.previousState.toString)),
    JField("currentState", JString(e.currentState.toString))
  )
  case e: ChannelClosed => JObject(
    JField("type", JString("channel-closed")),
    JField("channelId", JString(e.channelId.toHex)),
    JField("closingType", JString(e.closingType.getClass.getSimpleName))
  )
})

object OriginSerializer extends MinimalSerializer({
  case o: Origin => o.upstream match {
    case u: Upstream.Local => JObject(JField("paymentId", JString(u.id.toString)))
    case u: Upstream.Hot.Channel => JObject(
      JField("channelId", JString(u.add.channelId.toHex)),
      JField("htlcId", JLong(u.add.id)),
      JField("amount", JLong(u.add.amountMsat.toLong)),
      JField("expiry", JLong(u.add.cltvExpiry.toLong)),
      JField("receivedAt", JLong(u.receivedAt.toLong)),
    )
    case u: Upstream.Hot.Trampoline => JArray(u.received.map { htlc =>
      JObject(
        JField("channelId", JString(htlc.add.channelId.toHex)),
        JField("htlcId", JLong(htlc.add.id)),
        JField("amount", JLong(htlc.add.amountMsat.toLong)),
        JField("expiry", JLong(htlc.add.cltvExpiry.toLong)),
        JField("receivedAt", JLong(htlc.receivedAt.toLong)),
      )
    })
    case o: Upstream.Cold.Channel => JObject(
      JField("channelId", JString(o.originChannelId.toHex)),
      JField("htlcId", JLong(o.originHtlcId)),
      JField("amount", JLong(o.amountIn.toLong)),
    )
    case o: Upstream.Cold.Trampoline => JArray(o.originHtlcs.map { htlc =>
      JObject(
        JField("channelId", JString(htlc.originChannelId.toHex)),
        JField("htlcId", JLong(htlc.originHtlcId)),
        JField("amount", JLong(htlc.amountIn.toLong)),
      )
    })
  }
})

// @formatter:off
case class CommitmentJson(fundingTxIndex: Long, fundingTx: InputInfo, localFunding: LocalFundingStatus, remoteFunding: RemoteFundingStatus, localCommit: LocalCommit, remoteCommit: RemoteCommit, nextRemoteCommit: Option[RemoteCommit])
object CommitmentSerializer extends ConvertClassSerializer[Commitment](c => CommitmentJson(c.fundingTxIndex, c.commitInput, c.localFundingStatus, c.remoteFundingStatus, c.localCommit, c.remoteCommit, c.nextRemoteCommit_opt.map(_.commit)))
// @formatter:on

// @formatter:off
private case class DetailedOnChainBalanceJson(total: Btc, deeplyConfirmed: Map[OutPoint, Btc], recentlyConfirmed: Map[OutPoint, Btc], unconfirmed: Map[OutPoint, Btc])
object DetailedOnChainBalanceSerializer extends ConvertClassSerializer[DetailedOnChainBalance](b => DetailedOnChainBalanceJson(b.total, deeplyConfirmed = b.deeplyConfirmed, recentlyConfirmed = b.recentlyConfirmed, unconfirmed = b.unconfirmed))
private case class GlobalBalanceJson(total: Btc, onChain: DetailedOnChainBalance, offChain: OffChainBalance)
object GlobalBalanceSerializer extends ConvertClassSerializer[GlobalBalance](b => GlobalBalanceJson(b.total, b.onChain, b.offChain))

private case class PeerInfoJson(nodeId: PublicKey, state: String, address: Option[String], channels: Int)
object PeerInfoSerializer extends ConvertClassSerializer[Peer.PeerInfo](peerInfo => PeerInfoJson(peerInfo.nodeId, peerInfo.state.toString, peerInfo.address.map(_.toString), peerInfo.channels.size))

private[json] case class MessageReceivedJson(pathId: Option[ByteVector], tlvs: TlvStream[OnionMessagePayloadTlv])
object OnionMessageReceivedSerializer extends ConvertClassSerializer[OnionMessages.ReceiveMessage](m => MessageReceivedJson(m.finalPayload.pathId_opt, m.finalPayload.records))
// @formatter:on

// @formatter:off
/** this is cosmetic, just to not have a '_opt' field in json, which will only appear if the option is defined anyway */
private case class ShortIdAliasesJson(localAlias: Alias, remoteAlias: Option[ShortChannelId])
object ShortIdAliasesSerializer extends ConvertClassSerializer[ShortIdAliases](s => ShortIdAliasesJson(s.localAlias, s.remoteAlias_opt))
// @formatter:on

// @formatter:off
private case class FundingTxStatusJson(status: String, txid: Option[TxId], shortChannelId: Option[RealShortChannelId])
object FundingTxStatusSerializer extends ConvertClassSerializer[LocalFundingStatus]({
  case s: LocalFundingStatus.UnconfirmedFundingTx => FundingTxStatusJson("unconfirmed", s.signedTx_opt.map(_.txid), None)
  case s: LocalFundingStatus.ConfirmedFundingTx => FundingTxStatusJson("confirmed", s.signedTx_opt.map(_.txid), Some(s.shortChannelId))
})
// @formatter:on

object TlvStreamSerializer extends ConvertClassSerializer[TlvStream[_]](tlvs =>
  tlvs.records.map(tlv => tlv.getClass.getSimpleName -> tlv).toMap ++
    tlvs.unknown.map(unknown => ("Unknown" + unknown.tag.toString) -> unknown.value).toMap
)

case class CustomTypeHints(custom: Map[Class[_], String], override val typeHintFieldName: String = "type") extends TypeHints {
  val reverse: Map[String, Class[_]] = custom.map(_.swap)

  override val hints: List[Class[_]] = custom.keys.toList

  override def hintFor(clazz: Class[_]): Option[String] = custom.get(clazz)

  override def classFor(hint: String, parent: Class[_]): Option[Class[_]] = reverse.get(hint)
}

object CustomTypeHints {

  val incomingPaymentStatus: CustomTypeHints = CustomTypeHints(Map(
    IncomingPaymentStatus.Pending.getClass -> "pending",
    IncomingPaymentStatus.Expired.getClass -> "expired",
    classOf[IncomingPaymentStatus.Received] -> "received"
  ))

  val outgoingPaymentStatus: CustomTypeHints = CustomTypeHints(Map(
    OutgoingPaymentStatus.Pending.getClass -> "pending",
    classOf[OutgoingPaymentStatus.Failed] -> "failed",
    classOf[OutgoingPaymentStatus.Succeeded] -> "sent"
  ))

  val paymentEvent: CustomTypeHints = CustomTypeHints(Map(
    classOf[PaymentSent] -> "payment-sent",
    classOf[ChannelPaymentRelayed] -> "payment-relayed",
    classOf[TrampolinePaymentRelayed] -> "trampoline-payment-relayed",
    classOf[PaymentReceived] -> "payment-received",
    classOf[PaymentSettlingOnChain] -> "payment-settling-onchain",
    classOf[PaymentFailed] -> "payment-failed",
  ))

  val onionMessageEvent: CustomTypeHints = CustomTypeHints(Map(
    classOf[MessageReceivedJson] -> "onion-message-received"
  ))

  val channelSources: CustomTypeHints = CustomTypeHints(Map(
    classOf[HopRelayParams.FromAnnouncement] -> "announcement",
    classOf[HopRelayParams.FromHint] -> "hint"
  ))

  val channelStates: ShortTypeHints = ShortTypeHints(
    List(
      classOf[Nothing],
      classOf[DATA_WAIT_FOR_OPEN_CHANNEL],
      classOf[DATA_WAIT_FOR_ACCEPT_CHANNEL],
      classOf[DATA_WAIT_FOR_FUNDING_INTERNAL],
      classOf[DATA_WAIT_FOR_FUNDING_CREATED],
      classOf[DATA_WAIT_FOR_FUNDING_SIGNED],
      classOf[DATA_WAIT_FOR_FUNDING_CONFIRMED],
      classOf[DATA_WAIT_FOR_CHANNEL_READY],
      classOf[DATA_WAIT_FOR_OPEN_DUAL_FUNDED_CHANNEL],
      classOf[DATA_WAIT_FOR_ACCEPT_DUAL_FUNDED_CHANNEL],
      classOf[DATA_WAIT_FOR_DUAL_FUNDING_CREATED],
      classOf[DATA_WAIT_FOR_DUAL_FUNDING_SIGNED],
      classOf[DATA_WAIT_FOR_DUAL_FUNDING_CONFIRMED],
      classOf[DATA_WAIT_FOR_DUAL_FUNDING_READY],
      classOf[DATA_NORMAL],
      classOf[DATA_SHUTDOWN],
      classOf[DATA_NEGOTIATING],
      classOf[DATA_NEGOTIATING_SIMPLE],
      classOf[DATA_CLOSING],
      classOf[DATA_WAIT_FOR_REMOTE_PUBLISH_FUTURE_COMMITMENT]
    ), typeHintFieldName = "type")

  val remoteFundingStatuses: CustomTypeHints = CustomTypeHints(Map(
    classOf[RemoteFundingStatus.NotLocked.type] -> "not-locked",
    classOf[RemoteFundingStatus.Locked.type] -> "locked",
  ), typeHintFieldName = "status")
}

object JsonSerializers {

  implicit val serialization: Serialization.type = jackson.Serialization

  implicit val formats: Formats = org.json4s.DefaultFormats +
    CustomTypeHints.incomingPaymentStatus +
    CustomTypeHints.outgoingPaymentStatus +
    CustomTypeHints.paymentEvent +
    CustomTypeHints.onionMessageEvent +
    CustomTypeHints.channelSources +
    CustomTypeHints.channelStates +
    CustomTypeHints.remoteFundingStatuses +
    ActorRefSerializer +
    TypedActorRefSerializer +
    ByteVectorSerializer +
    ByteVector32Serializer +
    TxIdSerializer +
    BlockIdSerializer +
    BlockHashSerializer +
    ByteVector64Serializer +
    ChannelEventSerializer +
    UInt64Serializer +
    TimestampSecondSerializer +
    TimestampMilliSerializer +
    BtcSerializer +
    SatoshiSerializer +
    MilliSatoshiSerializer +
    CltvExpirySerializer +
    CltvExpiryDeltaSerializer +
    BlockHeightSerializer +
    FeeratePerKwSerializer +
    ShortChannelIdSerializer +
    ChannelIdentifierSerializer +
    ChannelStateSerializer +
    ShaChainSerializer +
    PublicKeySerializer +
    PrivateKeySerializer +
    TransactionSerializer +
    TransactionWithInputInfoSerializer +
    KeyPathSerializer +
    InetSocketAddressSerializer +
    OutPointSerializer +
    OutPointKeySerializer +
    FeatureKeySerializer +
    FeatureSupportSerializer +
    UnknownFeatureSerializer +
    ChannelConfigSerializer +
    ChannelFeaturesSerializer +
    OpenChannelResponseSerializer +
    CommandResponseSerializer +
    InputInfoSerializer +
    ColorSerializer +
    ThrowableSerializer +
    FailureMessageSerializer +
    FailureTypeSerializer +
    NodeAddressSerializer +
    DirectedHtlcSerializer +
    InvoiceSerializer +
    OfferSerializer +
    OfferDataSerializer +
    JavaUUIDSerializer +
    OriginSerializer +
    ByteVector32KeySerializer +
    TxIdKeySerializer +
    DetailedOnChainBalanceSerializer +
    GlobalBalanceSerializer +
    PeerInfoSerializer +
    PaymentFailedSummarySerializer +
    OnionMessageReceivedSerializer +
    ShortIdAliasesSerializer +
    FundingTxStatusSerializer +
    CommitmentSerializer +
    TlvStreamSerializer +
    new CustomSerializer[SpliceStatus](_ => (
      PartialFunction.empty, {
      case _: SpliceStatus => JNothing
    }
    ))

}
