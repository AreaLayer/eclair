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

package fr.acinq.eclair.db.pg

import com.zaxxer.hikari.util.IsolationLevel
import fr.acinq.bitcoin.scalacompat.ByteVector32
import fr.acinq.bitcoin.scalacompat.Crypto.PublicKey
import fr.acinq.eclair.channel.PersistentChannelData
import fr.acinq.eclair.db.ChannelsDb
import fr.acinq.eclair.db.DbEventHandler.ChannelEvent
import fr.acinq.eclair.db.Monitoring.Metrics.withMetrics
import fr.acinq.eclair.db.Monitoring.Tags.DbBackends
import fr.acinq.eclair.db.pg.PgUtils.PgLock
import fr.acinq.eclair.wire.internal.channel.ChannelCodecs.channelDataCodec
import fr.acinq.eclair.{CltvExpiry, Paginated}
import grizzled.slf4j.Logging
import scodec.bits.BitVector

import java.sql.{Connection, Statement, Timestamp}
import java.time.Instant
import javax.sql.DataSource

object PgChannelsDb {
  val DB_NAME = "channels"
  val CURRENT_VERSION = 10
}

class PgChannelsDb(implicit ds: DataSource, lock: PgLock) extends ChannelsDb with Logging {

  import PgChannelsDb._
  import PgUtils.ExtendedResultSet._
  import PgUtils._
  import fr.acinq.eclair.json.JsonSerializers.{formats, serialization}
  import lock._

  inTransaction { pg =>
    using(pg.createStatement()) { statement =>

      def migration23(statement: Statement): Unit = {
        statement.executeUpdate("ALTER TABLE local_channels ADD COLUMN created_timestamp BIGINT")
        statement.executeUpdate("ALTER TABLE local_channels ADD COLUMN last_payment_sent_timestamp BIGINT")
        statement.executeUpdate("ALTER TABLE local_channels ADD COLUMN last_payment_received_timestamp BIGINT")
        statement.executeUpdate("ALTER TABLE local_channels ADD COLUMN last_connected_timestamp BIGINT")
        statement.executeUpdate("ALTER TABLE local_channels ADD COLUMN closed_timestamp BIGINT")
      }

      def migration34(statement: Statement): Unit = {
        statement.executeUpdate("ALTER TABLE local_channels ALTER COLUMN created_timestamp SET DATA TYPE TIMESTAMP WITH TIME ZONE USING timestamp with time zone 'epoch' + created_timestamp * interval '1 millisecond'")
        statement.executeUpdate("ALTER TABLE local_channels ALTER COLUMN last_payment_sent_timestamp SET DATA TYPE TIMESTAMP WITH TIME ZONE USING timestamp with time zone 'epoch' + last_payment_sent_timestamp * interval '1 millisecond'")
        statement.executeUpdate("ALTER TABLE local_channels ALTER COLUMN last_payment_received_timestamp SET DATA TYPE TIMESTAMP WITH TIME ZONE USING timestamp with time zone 'epoch' + last_payment_received_timestamp * interval '1 millisecond'")
        statement.executeUpdate("ALTER TABLE local_channels ALTER COLUMN last_connected_timestamp SET DATA TYPE TIMESTAMP WITH TIME ZONE USING timestamp with time zone 'epoch' + last_connected_timestamp * interval '1 millisecond'")
        statement.executeUpdate("ALTER TABLE local_channels ALTER COLUMN closed_timestamp SET DATA TYPE TIMESTAMP WITH TIME ZONE USING timestamp with time zone 'epoch' + closed_timestamp * interval '1 millisecond'")

        statement.executeUpdate("ALTER TABLE htlc_infos ALTER COLUMN commitment_number SET DATA TYPE BIGINT USING commitment_number::BIGINT")
      }

      def migration45(statement: Statement): Unit = {
        statement.executeUpdate("ALTER TABLE local_channels ADD COLUMN json JSONB")
        resetJsonColumns(pg, oldTableName = true)
        statement.executeUpdate("ALTER TABLE local_channels ALTER COLUMN json SET NOT NULL")
        statement.executeUpdate("CREATE INDEX local_channels_type_idx ON local_channels ((json->>'type'))")
        statement.executeUpdate("CREATE INDEX local_channels_remote_node_id_idx ON local_channels ((json->'commitments'->'params'->'remoteParams'->>'nodeId'))")
      }

      def migration56(statement: Statement): Unit = {
        statement.executeUpdate("CREATE SCHEMA IF NOT EXISTS local")
        statement.executeUpdate("ALTER TABLE local_channels SET SCHEMA local")
        statement.executeUpdate("ALTER TABLE local.local_channels RENAME TO channels")
        statement.executeUpdate("ALTER TABLE htlc_infos SET SCHEMA local")
      }

      def migration67(): Unit = {
        migrateTable(pg, pg,
          "local.channels",
          "UPDATE local.channels SET data=?, json=?::JSONB WHERE channel_id=?",
          (rs, statement) => {
            // This forces a re-serialization of the channel data with latest codecs, because as of codecs v3 we don't
            // store local commitment signatures anymore, and we want to clean up existing data
            val state = channelDataCodec.decode(BitVector(rs.getBytes("data"))).require.value
            val data = channelDataCodec.encode(state).require.toByteArray
            val json = serialization.write(state)
            statement.setBytes(1, data)
            statement.setString(2, json)
            statement.setString(3, state.channelId.toHex)
          }
        )(logger)
      }

      def migration78(statement: Statement): Unit = {
        statement.executeUpdate("DROP INDEX IF EXISTS local.local_channels_remote_node_id_idx")
        statement.executeUpdate("ALTER TABLE local.channels ADD COLUMN remote_node_id TEXT")
        migrateTable(pg, pg,
          "local.channels",
          "UPDATE local.channels SET remote_node_id=? WHERE channel_id=?",
          (rs, statement) => {
            val state = channelDataCodec.decode(BitVector(rs.getBytes("data"))).require.value
            statement.setString(1, state.remoteNodeId.toHex)
            statement.setString(2, state.channelId.toHex)
          })(logger)
        statement.executeUpdate("ALTER TABLE local.channels ALTER COLUMN remote_node_id SET NOT NULL")
        statement.executeUpdate("CREATE INDEX local_channels_remote_node_id_idx ON local.channels(remote_node_id)")
      }

      def migration89(statement: Statement): Unit = {
        statement.executeUpdate("CREATE TABLE local.htlc_infos_to_remove (channel_id TEXT NOT NULL PRIMARY KEY, before_commitment_number BIGINT NOT NULL)")
      }
      
      def migration910(statement: Statement): Unit = {
        // We're changing our composite index to two distinct indices to improve performance.
        statement.executeUpdate("CREATE INDEX htlc_infos_channel_id_idx ON local.htlc_infos(channel_id)")
        statement.executeUpdate("CREATE INDEX htlc_infos_commitment_number_idx ON local.htlc_infos(commitment_number)")
        statement.executeUpdate("DROP INDEX IF EXISTS local.htlc_infos_idx")
      }

      getVersion(statement, DB_NAME) match {
        case None =>
          statement.executeUpdate("CREATE SCHEMA IF NOT EXISTS local")

          statement.executeUpdate("CREATE TABLE local.channels (channel_id TEXT NOT NULL PRIMARY KEY, remote_node_id TEXT NOT NULL, data BYTEA NOT NULL, json JSONB NOT NULL, is_closed BOOLEAN NOT NULL DEFAULT FALSE, created_timestamp TIMESTAMP WITH TIME ZONE, last_payment_sent_timestamp TIMESTAMP WITH TIME ZONE, last_payment_received_timestamp TIMESTAMP WITH TIME ZONE, last_connected_timestamp TIMESTAMP WITH TIME ZONE, closed_timestamp TIMESTAMP WITH TIME ZONE)")
          statement.executeUpdate("CREATE TABLE local.htlc_infos (channel_id TEXT NOT NULL, commitment_number BIGINT NOT NULL, payment_hash TEXT NOT NULL, cltv_expiry BIGINT NOT NULL, FOREIGN KEY(channel_id) REFERENCES local.channels(channel_id))")
          statement.executeUpdate("CREATE TABLE local.htlc_infos_to_remove (channel_id TEXT NOT NULL PRIMARY KEY, before_commitment_number BIGINT NOT NULL)")

          statement.executeUpdate("CREATE INDEX local_channels_type_idx ON local.channels ((json->>'type'))")
          statement.executeUpdate("CREATE INDEX local_channels_remote_node_id_idx ON local.channels(remote_node_id)")
          // Note that we use two distinct indices instead of a composite index on (channel_id, commitment_number).
          // This is more efficient because we're writing a lot to this table but only reading when a channel is force-closed.
          statement.executeUpdate("CREATE INDEX htlc_infos_channel_id_idx ON local.htlc_infos(channel_id)")
          statement.executeUpdate("CREATE INDEX htlc_infos_commitment_number_idx ON local.htlc_infos(commitment_number)")
        case Some(v@(2 | 3 | 4 | 5 | 6 | 7 | 8 | 9)) =>
          logger.warn(s"migrating db $DB_NAME, found version=$v current=$CURRENT_VERSION")
          if (v < 3) {
            migration23(statement)
          }
          if (v < 4) {
            migration34(statement)
          }
          if (v < 5) {
            migration45(statement)
          }
          if (v < 6) {
            migration56(statement)
          }
          if (v < 7) {
            migration67()
          }
          if (v < 8) {
            migration78(statement)
          }
          if (v < 9) {
            migration89(statement)
          }
          if (v < 10) {
            migration910(statement)
          }
        case Some(CURRENT_VERSION) => () // table is up-to-date, nothing to do
        case Some(unknownVersion) => throw new RuntimeException(s"Unknown version of DB $DB_NAME found, version=$unknownVersion")
      }
      setVersion(statement, DB_NAME, CURRENT_VERSION)
    }
  }

  /** Sometimes we may want to do a full reset when we update the json format */
  def resetJsonColumns(connection: Connection, oldTableName: Boolean = false): Unit = {
    val table = if (oldTableName) "local_channels" else "local.channels"
    migrateTable(connection, connection,
      table,
      s"UPDATE $table SET json=?::JSONB WHERE channel_id=?",
      (rs, statement) => {
        val state = channelDataCodec.decode(BitVector(rs.getBytes("data"))).require.value
        val json = serialization.write(state)
        statement.setString(1, json)
        statement.setString(2, state.channelId.toHex)
      }
    )(logger)
  }

  override def addOrUpdateChannel(data: PersistentChannelData): Unit = withMetrics("channels/add-or-update-channel", DbBackends.Postgres) {
    withLock { pg =>
      val encoded = channelDataCodec.encode(data).require.toByteArray
      using(pg.prepareStatement(
        """
          | INSERT INTO local.channels (channel_id, remote_node_id, data, json, created_timestamp, last_connected_timestamp, is_closed)
          | VALUES (?, ?, ?, ?::JSONB, ?, ?, FALSE)
          | ON CONFLICT (channel_id)
          | DO UPDATE SET data = EXCLUDED.data, json = EXCLUDED.json ;
          | """.stripMargin)) { statement =>
        statement.setString(1, data.channelId.toHex)
        statement.setString(2, data.remoteNodeId.toHex)
        statement.setBytes(3, encoded)
        statement.setString(4, serialization.write(data))
        statement.setTimestamp(5, Timestamp.from(Instant.now()))
        statement.setTimestamp(6, Timestamp.from(Instant.now()))
        statement.executeUpdate()
      }
    }
  }

  override def getChannel(channelId: ByteVector32): Option[PersistentChannelData] = withMetrics("channels/get-channel", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.prepareStatement("SELECT data FROM local.channels WHERE channel_id=? AND is_closed=FALSE")) { statement =>
        statement.setString(1, channelId.toHex)
        statement.executeQuery.mapCodec(channelDataCodec).lastOption
      }
    }
  }

  /** Helper method to factor updating timestamp columns */
  private def updateChannelMetaTimestampColumn(channelId: ByteVector32, columnName: String): Unit = {
    inTransaction(IsolationLevel.TRANSACTION_READ_UNCOMMITTED) { pg =>
      using(pg.prepareStatement(s"UPDATE local.channels SET $columnName=? WHERE channel_id=?")) { statement =>
        statement.setTimestamp(1, Timestamp.from(Instant.now()))
        statement.setString(2, channelId.toHex)
        statement.executeUpdate()
      }
    }
  }

  override def updateChannelMeta(channelId: ByteVector32, event: ChannelEvent.EventType): Unit = {
    val timestampColumn_opt = event match {
      case ChannelEvent.EventType.Connected => Some("last_connected_timestamp")
      case ChannelEvent.EventType.PaymentReceived => Some("last_payment_received_timestamp")
      case ChannelEvent.EventType.PaymentSent => Some("last_payment_sent_timestamp")
      case _ => None
    }
    timestampColumn_opt.foreach(updateChannelMetaTimestampColumn(channelId, _))
  }

  override def removeChannel(channelId: ByteVector32): Unit = withMetrics("channels/remove-channel", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.prepareStatement("DELETE FROM local.pending_settlement_commands WHERE channel_id=?")) { statement =>
        statement.setString(1, channelId.toHex)
        statement.executeUpdate()
      }

      // The htlc_infos may contain millions of rows, which is very expensive to delete synchronously.
      // We instead run an asynchronous job to clean up that data in small batches.
      markHtlcInfosForRemoval(channelId, Long.MaxValue)

      using(pg.prepareStatement("UPDATE local.channels SET is_closed=TRUE, closed_timestamp=? WHERE channel_id=?")) { statement =>
        statement.setTimestamp(1, Timestamp.from(Instant.now()))
        statement.setString(2, channelId.toHex)
        statement.executeUpdate()
      }
    }
  }

  override def markHtlcInfosForRemoval(channelId: ByteVector32, beforeCommitIndex: Long): Unit = withMetrics("channels/forget-htlc-infos", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.prepareStatement("INSERT INTO local.htlc_infos_to_remove (channel_id, before_commitment_number) VALUES(?, ?) ON CONFLICT (channel_id) DO UPDATE SET before_commitment_number = EXCLUDED.before_commitment_number")) { statement =>
        statement.setString(1, channelId.toHex)
        statement.setLong(2, beforeCommitIndex)
        statement.executeUpdate()
      }
    }
  }

  override def removeHtlcInfos(batchSize: Int): Unit = withMetrics("channels/remove-htlc-infos", DbBackends.Postgres) {
    withLock { pg =>
      // Check if there are channels that need to be cleaned up.
      val channelToCleanUp_opt = using(pg.prepareStatement("SELECT channel_id, before_commitment_number FROM local.htlc_infos_to_remove LIMIT 1")) { statement =>
        statement.executeQuery().map(rs => {
          val channelId = ByteVector32(rs.getByteVector32FromHex("channel_id"))
          val beforeCommitmentNumber = rs.getLong("before_commitment_number")
          (channelId, beforeCommitmentNumber)
        }).lastOption
      }
      // Remove a batch of HTLC information for that channel.
      channelToCleanUp_opt.foreach { case (channelId, beforeCommitmentNumber) =>
        val deletedCount = using(pg.prepareStatement(s"DELETE FROM local.htlc_infos WHERE channel_id=? AND commitment_number IN (SELECT commitment_number FROM local.htlc_infos WHERE channel_id=? AND commitment_number<? LIMIT $batchSize)")) { statement =>
          statement.setString(1, channelId.toHex)
          statement.setString(2, channelId.toHex)
          statement.setLong(3, beforeCommitmentNumber)
          statement.executeUpdate()
        }
        logger.info(s"deleted $deletedCount rows from htlc_infos for channelId=$channelId beforeCommitmentNumber=$beforeCommitmentNumber")
        // If we've deleted all HTLC information for that channel, we can now remove it from the DB.
        if (deletedCount < batchSize) {
          using(pg.prepareStatement("DELETE FROM local.htlc_infos_to_remove WHERE channel_id=?")) { statement =>
            statement.setString(1, channelId.toHex)
            statement.executeUpdate()
          }
        }
      }
    }
  }

  override def listLocalChannels(): Seq[PersistentChannelData] = withMetrics("channels/list-local-channels", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.createStatement) { statement =>
        statement.executeQuery("SELECT data FROM local.channels WHERE is_closed=FALSE")
          .mapCodec(channelDataCodec).toSeq
      }
    }
  }

  override def listClosedChannels(remoteNodeId_opt: Option[PublicKey], paginated_opt: Option[Paginated]): Seq[PersistentChannelData] = withMetrics("channels/list-closed-channels", DbBackends.Postgres) {
    val sql = remoteNodeId_opt match {
      case None => "SELECT data FROM local.channels WHERE is_closed=TRUE ORDER BY closed_timestamp DESC"
      case Some(remoteNodeId) => s"SELECT data FROM local.channels WHERE is_closed=TRUE AND remote_node_id = '${remoteNodeId.toHex}' ORDER BY closed_timestamp DESC"
    }
    withLock { pg =>
      using(pg.prepareStatement(limited(sql, paginated_opt))) { statement =>
        statement.executeQuery()
          .mapCodec(channelDataCodec).toSeq
      }
    }
  }

  override def addHtlcInfo(channelId: ByteVector32, commitmentNumber: Long, paymentHash: ByteVector32, cltvExpiry: CltvExpiry): Unit = withMetrics("channels/add-htlc-info", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.prepareStatement("INSERT INTO local.htlc_infos VALUES (?, ?, ?, ?)")) { statement =>
        statement.setString(1, channelId.toHex)
        statement.setLong(2, commitmentNumber)
        statement.setString(3, paymentHash.toHex)
        statement.setLong(4, cltvExpiry.toLong)
        statement.executeUpdate()
      }
    }
  }

  override def listHtlcInfos(channelId: ByteVector32, commitmentNumber: Long): Seq[(ByteVector32, CltvExpiry)] = withMetrics("channels/list-htlc-infos", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.prepareStatement("SELECT payment_hash, cltv_expiry FROM local.htlc_infos WHERE channel_id=? AND commitment_number=?")) { statement =>
        statement.setString(1, channelId.toHex)
        statement.setLong(2, commitmentNumber)
        statement.executeQuery
          .map { rs =>
            (ByteVector32(rs.getByteVector32FromHex("payment_hash")), CltvExpiry(rs.getLong("cltv_expiry")))
          }.toSeq
      }
    }
  }
}
