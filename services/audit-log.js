const crypto = require('crypto');
const db = require('../config/database');

class ImmutableAuditLog {
  async log(event) {
    const client = await db.pool.connect();

    try {
      await client.query('BEGIN');

      const {
        action,
        actorId,
        actorRole,
        resourceType,
        resourceId,
        resourceData,
        status,
        result,
        errorMessage,
        ipAddress,
        userAgent,
      } = event;

      const previousLog = await client.query(
        'SELECT hash_chain FROM audit_log ORDER BY id DESC LIMIT 1'
      );

      const previousHash =
        previousLog.rows[0]?.hash_chain || '0'.repeat(64);

      const logString = JSON.stringify({
        action,
        actorId,
        actorRole,
        resourceType,
        resourceId,
        timestamp: new Date().toISOString(),
        previousHash,
      });

      const currentHash = crypto
        .createHash('sha256')
        .update(logString + previousHash)
        .digest('hex');

      const result = await client.query(
        `INSERT INTO audit_log (
          action, actor_id, actor_role, resource_type, resource_id,
          resource_data, status, result, error_message, ip_address,
          user_agent, hash_chain, previous_hash
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        RETURNING id, event_id, timestamp`,
        [
          action,
          actorId,
          actorRole,
          resourceType,
          resourceId,
          resourceData ? JSON.stringify(resourceData) : null,
          status,
          result,
          errorMessage,
          ipAddress,
          userAgent,
          currentHash,
          previousHash,
        ]
      );

      await client.query('COMMIT');
      return result.rows[0];
    } catch (error) {
      await client.query('ROLLBACK');
      console.error('Audit log error:', error);
      throw error;
    } finally {
      client.release();
    }
  }

  async verify() {
    try {
      const logs = await db.query(
        'SELECT id, hash_chain, previous_hash FROM audit_log ORDER BY id ASC'
      );

      let previousHash = '0'.repeat(64);
      let valid = true;

      for (const log of logs.rows) {
        if (log.previous_hash !== previousHash) {
          console.error(`Audit log integrity violation at id ${log.id}`);
          valid = false;
          break;
        }
        previousHash = log.hash_chain;
      }

      return valid;
    } catch (error) {
      console.error('Audit verification error:', error);
      throw error;
    }
  }

  async generateReport(startDate, endDate) {
    try {
      const logs = await db.query(
        `SELECT * FROM audit_log
         WHERE timestamp BETWEEN $1 AND $2
         ORDER BY id ASC`,
        [startDate, endDate]
      );

      const reportData = {
        generatedAt: new Date().toISOString(),
        period: { startDate, endDate },
        totalEvents: logs.rows.length,
        events: logs.rows,
        integrityValid: await this.verify(),
      };

      const reportHash = crypto
        .createHash('sha256')
        .update(JSON.stringify(reportData))
        .digest('hex');

      return {
        ...reportData,
        reportHash,
      };
    } catch (error) {
      console.error('Report generation error:', error);
      throw error;
    }
  }

  async getResourceAuditTrail(resourceType, resourceId) {
    try {
      const result = await db.query(
        `SELECT * FROM audit_log
         WHERE resource_type = $1 AND resource_id = $2
         ORDER BY timestamp DESC
         LIMIT 100`,
        [resourceType, resourceId]
      );

      return result.rows;
    } catch (error) {
      console.error('Audit trail retrieval error:', error);
      throw error;
    }
  }
}

module.exports = new ImmutableAuditLog();
