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

import fr.acinq.bitcoin.scalacompat.Crypto
import fr.acinq.bitcoin.scalacompat.Crypto.PublicKey
import fr.acinq.eclair.{MilliSatoshi, TimestampSecond}
import fr.acinq.eclair.db.Monitoring.Metrics.withMetrics
import fr.acinq.eclair.db.Monitoring.Tags.DbBackends
import fr.acinq.eclair.db.PeersDb
import fr.acinq.eclair.db.pg.PgUtils.PgLock
import fr.acinq.eclair.payment.relay.Relayer.RelayFees
import fr.acinq.eclair.wire.protocol._
import grizzled.slf4j.Logging
import scodec.bits.{BitVector, ByteVector}

import java.sql.Statement
import javax.sql.DataSource

object PgPeersDb {
  val DB_NAME = "peers"
  val CURRENT_VERSION = 4
}

class PgPeersDb(implicit ds: DataSource, lock: PgLock) extends PeersDb with Logging {

  import PgPeersDb._
  import PgUtils.ExtendedResultSet._
  import PgUtils._
  import lock._

  inTransaction { pg =>

    def migration12(statement: Statement): Unit = {
      statement.executeUpdate("CREATE SCHEMA IF NOT EXISTS local")
      statement.executeUpdate("ALTER TABLE peers SET SCHEMA local")
    }

    def migration23(statement: Statement): Unit = {
      statement.executeUpdate("CREATE TABLE local.relay_fees (node_id TEXT NOT NULL PRIMARY KEY, fee_base_msat BIGINT NOT NULL, fee_proportional_millionths BIGINT NOT NULL)")
    }

    def migration34(statement: Statement): Unit = {
      statement.executeUpdate("CREATE TABLE local.peer_storage (node_id TEXT NOT NULL PRIMARY KEY, data BYTEA NOT NULL, last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL, removed_peer_at TIMESTAMP WITH TIME ZONE)")
      statement.executeUpdate("CREATE INDEX removed_peer_at_idx ON local.peer_storage(removed_peer_at)")
    }

    using(pg.createStatement()) { statement =>
      getVersion(statement, DB_NAME) match {
        case None =>
          statement.executeUpdate("CREATE SCHEMA IF NOT EXISTS local")
          statement.executeUpdate("CREATE TABLE local.peers (node_id TEXT NOT NULL PRIMARY KEY, data BYTEA NOT NULL)")
          statement.executeUpdate("CREATE TABLE local.relay_fees (node_id TEXT NOT NULL PRIMARY KEY, fee_base_msat BIGINT NOT NULL, fee_proportional_millionths BIGINT NOT NULL)")
          statement.executeUpdate("CREATE TABLE local.peer_storage (node_id TEXT NOT NULL PRIMARY KEY, data BYTEA NOT NULL, last_updated_at TIMESTAMP WITH TIME ZONE NOT NULL, removed_peer_at TIMESTAMP WITH TIME ZONE)")

          statement.executeUpdate("CREATE INDEX removed_peer_at_idx ON local.peer_storage(removed_peer_at)")
        case Some(v@(1 | 2 | 3)) =>
          logger.warn(s"migrating db $DB_NAME, found version=$v current=$CURRENT_VERSION")
          if (v < 2) {
            migration12(statement)
          }
          if (v < 3) {
            migration23(statement)
          }
          if (v < 4) {
            migration34(statement)
          }
        case Some(CURRENT_VERSION) => () // table is up-to-date, nothing to do
        case Some(unknownVersion) => throw new RuntimeException(s"Unknown version of DB $DB_NAME found, version=$unknownVersion")
      }
      setVersion(statement, DB_NAME, CURRENT_VERSION)
    }
  }

  override def addOrUpdatePeer(nodeId: Crypto.PublicKey, nodeaddress: NodeAddress): Unit = withMetrics("peers/add-or-update", DbBackends.Postgres) {
    withLock { pg =>
      val data = CommonCodecs.nodeaddress.encode(nodeaddress).require.toByteArray
      using(pg.prepareStatement(
        """
          | INSERT INTO local.peers (node_id, data)
          | VALUES (?, ?)
          | ON CONFLICT (node_id)
          | DO UPDATE SET data = EXCLUDED.data ;
          | """.stripMargin)) { statement =>
        statement.setString(1, nodeId.value.toHex)
        statement.setBytes(2, data)
        statement.executeUpdate()
      }
    }
  }

  override def removePeer(nodeId: Crypto.PublicKey): Unit = withMetrics("peers/remove", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.prepareStatement("DELETE FROM local.peers WHERE node_id=?")) { statement =>
        statement.setString(1, nodeId.value.toHex)
        statement.executeUpdate()
      }
      using(pg.prepareStatement("UPDATE local.peer_storage SET removed_peer_at = ? WHERE node_id = ?")) { statement =>
        statement.setTimestamp(1, TimestampSecond.now().toSqlTimestamp)
        statement.setString(2, nodeId.value.toHex)
        statement.executeUpdate()
      }
    }
  }

  override def removePeerStorage(peerRemovedBefore: TimestampSecond): Unit = withMetrics("peers/remove-storage", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.prepareStatement("DELETE FROM local.peer_storage WHERE removed_peer_at < ?")) { statement =>
        statement.setTimestamp(1, peerRemovedBefore.toSqlTimestamp)
        statement.executeUpdate()
      }
    }
  }

  override def getPeer(nodeId: PublicKey): Option[NodeAddress] = withMetrics("peers/get", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.prepareStatement("SELECT data FROM local.peers WHERE node_id=?")) { statement =>
        statement.setString(1, nodeId.value.toHex)
        statement.executeQuery()
          .mapCodec(CommonCodecs.nodeaddress)
          .headOption
      }
    }
  }

  override def listPeers(): Map[PublicKey, NodeAddress] = withMetrics("peers/list", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.createStatement()) { statement =>
        statement.executeQuery("SELECT node_id, data FROM local.peers")
          .map { rs =>
            val nodeid = PublicKey(rs.getByteVectorFromHex("node_id"))
            val nodeaddress = CommonCodecs.nodeaddress.decode(BitVector(rs.getBytes("data"))).require.value
            nodeid -> nodeaddress
          }
          .toMap
      }
    }
  }

  override def addOrUpdateRelayFees(nodeId: Crypto.PublicKey, fees: RelayFees): Unit = withMetrics("peers/add-or-update-relay-fees", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.prepareStatement(
      """
      INSERT INTO local.relay_fees (node_id, fee_base_msat, fee_proportional_millionths)
      VALUES (?, ?, ?)
      ON CONFLICT (node_id)
      DO UPDATE SET fee_base_msat = EXCLUDED.fee_base_msat, fee_proportional_millionths = EXCLUDED.fee_proportional_millionths
      """)) { statement =>
        statement.setString(1, nodeId.value.toHex)
        statement.setLong(2, fees.feeBase.toLong)
        statement.setLong(3, fees.feeProportionalMillionths)
        statement.executeUpdate()
      }
    }
  }

  override def getRelayFees(nodeId: PublicKey): Option[RelayFees] = withMetrics("peers/get-relay-fees", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.prepareStatement("SELECT fee_base_msat, fee_proportional_millionths FROM local.relay_fees WHERE node_id=?")) { statement =>
        statement.setString(1, nodeId.value.toHex)
        statement.executeQuery()
          .headOption
          .map(rs =>
            RelayFees(MilliSatoshi(rs.getLong("fee_base_msat")), rs.getLong("fee_proportional_millionths"))
          )
      }
    }
  }

  override def updateStorage(nodeId: PublicKey, data: ByteVector): Unit = withMetrics("peers/update-storage", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.prepareStatement(
        """
        INSERT INTO local.peer_storage (node_id, data, last_updated_at, removed_peer_at)
        VALUES (?, ?, ?, NULL)
        ON CONFLICT (node_id)
        DO UPDATE SET data = EXCLUDED.data, last_updated_at = EXCLUDED.last_updated_at, removed_peer_at = NULL
        """)) { statement =>
        statement.setString(1, nodeId.value.toHex)
        statement.setBytes(2, data.toArray)
        statement.setTimestamp(3, TimestampSecond.now().toSqlTimestamp)
        statement.executeUpdate()
      }
    }
  }

  override def getStorage(nodeId: PublicKey): Option[ByteVector] = withMetrics("peers/get-storage", DbBackends.Postgres) {
    withLock { pg =>
      using(pg.prepareStatement("SELECT data FROM local.peer_storage WHERE node_id = ?")) { statement =>
        statement.setString(1, nodeId.value.toHex)
        statement.executeQuery()
          .headOption
          .map(rs => ByteVector(rs.getBytes("data")))
      }
    }
  }
}
