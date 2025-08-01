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

package fr.acinq.eclair.payment.relay

import akka.actor.typed.Behavior
import akka.actor.typed.eventstream.EventStream
import akka.actor.typed.scaladsl.Behaviors
import akka.actor.{ActorRef, typed}
import fr.acinq.bitcoin.scalacompat.ByteVector32
import fr.acinq.bitcoin.scalacompat.Crypto.PublicKey
import fr.acinq.eclair.channel._
import fr.acinq.eclair.payment.IncomingPaymentPacket
import fr.acinq.eclair.reputation.ReputationRecorder
import fr.acinq.eclair.{Logs, NodeParams, ShortChannelId, SubscriptionsComplete}

import java.util.UUID
import scala.collection.mutable

/**
 * Created by t-bast on 09/10/2019.
 */

/**
 * The [[ChannelRelayer]] relays a single upstream HTLC to a downstream channel.
 * It selects the best channel to use to relay and retries using other channels in case a local failure happens.
 */
object ChannelRelayer {

  // @formatter:off
  sealed trait Command
  case class GetOutgoingChannels(replyTo: ActorRef, getOutgoingChannels: Relayer.GetOutgoingChannels) extends Command
  case class Relay(channelRelayPacket: IncomingPaymentPacket.ChannelRelayPacket, originNode: PublicKey, incomingChannelOccupancy: Double) extends Command
  private[payment] case class WrappedLocalChannelUpdate(localChannelUpdate: LocalChannelUpdate) extends Command
  private[payment] case class WrappedLocalChannelDown(localChannelDown: LocalChannelDown) extends Command
  private[payment] case class WrappedAvailableBalanceChanged(availableBalanceChanged: AvailableBalanceChanged) extends Command
  // @formatter:on

  def mdc: Command => Map[String, String] = {
    case c: Relay => Logs.mdc(paymentHash_opt = Some(c.channelRelayPacket.add.paymentHash))
    case c: WrappedLocalChannelUpdate => Logs.mdc(channelId_opt = Some(c.localChannelUpdate.channelId))
    case c: WrappedLocalChannelDown => Logs.mdc(channelId_opt = Some(c.localChannelDown.channelId))
    case c: WrappedAvailableBalanceChanged => Logs.mdc(channelId_opt = Some(c.availableBalanceChanged.channelId))
    case _ => Map.empty
  }

  def apply(nodeParams: NodeParams,
            register: ActorRef,
            reputationRecorder_opt: Option[typed.ActorRef[ReputationRecorder.GetConfidence]],
            channels: Map[ByteVector32, Relayer.OutgoingChannel] = Map.empty,
            scid2channels: Map[ShortChannelId, ByteVector32] = Map.empty,
            node2channels: mutable.MultiDict[PublicKey, ByteVector32] = mutable.MultiDict.empty): Behavior[Command] =
    Behaviors.setup { context =>
      context.system.eventStream ! EventStream.Subscribe(context.messageAdapter[LocalChannelUpdate](WrappedLocalChannelUpdate))
      context.system.eventStream ! EventStream.Subscribe(context.messageAdapter[LocalChannelDown](WrappedLocalChannelDown))
      context.system.eventStream ! EventStream.Subscribe(context.messageAdapter[AvailableBalanceChanged](WrappedAvailableBalanceChanged))
      context.system.eventStream ! EventStream.Publish(SubscriptionsComplete(this.getClass))
      Behaviors.withMdc(Logs.mdc(category_opt = Some(Logs.LogCategory.PAYMENT), nodeAlias_opt = Some(nodeParams.alias)), mdc) {
        Behaviors.receiveMessage {
          case Relay(channelRelayPacket, originNode, incomingChannelOccupancy) =>
            val relayId = UUID.randomUUID()
            val nextNodeId_opt: Option[PublicKey] = channelRelayPacket.payload.outgoing match {
              case Left(outgoingNodeId) => Some(outgoingNodeId.publicKey)
              case Right(outgoingChannelId) => scid2channels.get(outgoingChannelId) match {
                case Some(channelId) => channels.get(channelId).map(_.nextNodeId)
                case None => None
              }
            }
            val nextChannels: Map[ByteVector32, Relayer.OutgoingChannel] = nextNodeId_opt match {
              case Some(nextNodeId) => node2channels.get(nextNodeId).flatMap(channels.get).map(c => c.channelId -> c).toMap
              case None => Map.empty
            }
            context.log.debug(s"spawning a new handler with relayId=$relayId to nextNodeId={} with channels={}", nextNodeId_opt.getOrElse(""), nextChannels.keys.mkString(","))
            context.spawn(ChannelRelay.apply(nodeParams, register, reputationRecorder_opt, nextChannels, originNode, relayId, channelRelayPacket, incomingChannelOccupancy), name = relayId.toString)
            Behaviors.same

          case GetOutgoingChannels(replyTo, Relayer.GetOutgoingChannels(enabledOnly)) =>
            val selected = if (enabledOnly) {
              channels.values.filter(o => o.channelUpdate.channelFlags.isEnabled)
            } else {
              channels.values
            }
            replyTo ! Relayer.OutgoingChannels(selected.toSeq)
            Behaviors.same

          case WrappedLocalChannelUpdate(lcu@LocalChannelUpdate(_, channelId, shortIds, remoteNodeId, announcement_opt, channelUpdate, commitments)) =>
            context.log.debug("updating local channel info for channelId={} realScid={} localAlias={} remoteNodeId={} channelUpdate={}", channelId, announcement_opt.map(_.shortChannelId), shortIds.localAlias, remoteNodeId, channelUpdate)
            val prevChannelUpdate = channels.get(channelId).map(_.channelUpdate)
            val channel = Relayer.OutgoingChannel(shortIds, remoteNodeId, channelUpdate, prevChannelUpdate, announcement_opt.map(_.announcement), commitments)
            val channels1 = channels + (channelId -> channel)
            val mappings = lcu.scidsForRouting.map(_ -> channelId).toMap
            context.log.debug("adding mappings={} to channelId={}", mappings.keys.mkString(","), channelId)
            val scid2channels1 = scid2channels ++ mappings
            val node2channels1 = node2channels.addOne(remoteNodeId, channelId)
            apply(nodeParams, register, reputationRecorder_opt, channels1, scid2channels1, node2channels1)

          case WrappedLocalChannelDown(LocalChannelDown(_, channelId, realScids, aliases, remoteNodeId)) =>
            context.log.debug("removed local channel info for channelId={} localAlias={}", channelId, aliases.localAlias)
            val channels1 = channels - channelId
            val scid2Channels1 = scid2channels - aliases.localAlias -- realScids
            val node2channels1 = node2channels.subtractOne(remoteNodeId, channelId)
            apply(nodeParams, register, reputationRecorder_opt, channels1, scid2Channels1, node2channels1)

          case WrappedAvailableBalanceChanged(AvailableBalanceChanged(_, channelId, aliases, commitments, _)) =>
            val channels1 = channels.get(channelId) match {
              case Some(c: Relayer.OutgoingChannel) =>
                context.log.debug("available balance changed for channelId={} localAlias={} availableForSend={} availableForReceive={}", channelId, aliases.localAlias, commitments.availableBalanceForSend, commitments.availableBalanceForReceive)
                channels + (channelId -> c.copy(commitments = commitments))
              case None => channels // we only consider the balance if we have the channel_update
            }
            apply(nodeParams, register, reputationRecorder_opt, channels1, scid2channels, node2channels)

        }
      }
    }
}
