const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'voting_system',
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  max: 20,
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
});

async function initializeDatabase() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS students (
        id VARCHAR(50) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        name VARCHAR(255) NOT NULL,
        class VARCHAR(10),
        phone VARCHAR(20),
        eligible BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_students_email ON students(email);
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'admin',
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
      CREATE INDEX IF NOT EXISTS idx_admins_email ON admins(email);
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS otps (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id VARCHAR(50) NOT NULL,
        otp VARCHAR(10) NOT NULL,
        attempts INT DEFAULT 0,
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_otps_student_id ON otps(student_id);
      CREATE INDEX IF NOT EXISTS idx_otps_expires_at ON otps(expires_at);
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS credentials (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        student_id VARCHAR(50) NOT NULL,
        token VARCHAR(255) UNIQUE NOT NULL,
        token_hash VARCHAR(64) NOT NULL,
        issued_at TIMESTAMP DEFAULT NOW(),
        used_at TIMESTAMP,
        used BOOLEAN DEFAULT FALSE,
        expires_at TIMESTAMP NOT NULL,
        FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
        CONSTRAINT one_token_per_student_unused UNIQUE(student_id, used) WHERE NOT used
      );
      CREATE INDEX IF NOT EXISTS idx_credentials_student_id ON credentials(student_id);
      CREATE INDEX IF NOT EXISTS idx_credentials_token_hash ON credentials(token_hash);
      CREATE INDEX IF NOT EXISTS idx_credentials_expires_at ON credentials(expires_at);
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS votes (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        credential_id UUID NOT NULL,
        encrypted_votes BYTEA NOT NULL,
        iv VARCHAR(255) NOT NULL,
        auth_tag VARCHAR(255) NOT NULL,
        vote_hash VARCHAR(64) NOT NULL,
        integrity_hash VARCHAR(64) NOT NULL,
        timestamp TIMESTAMP DEFAULT NOW(),
        ip_address INET,
        user_agent TEXT,
        FOREIGN KEY (credential_id) REFERENCES credentials(id),
        CONSTRAINT unique_vote_per_credential UNIQUE(credential_id)
      );
      CREATE INDEX IF NOT EXISTS idx_votes_timestamp ON votes(timestamp);
      CREATE INDEX IF NOT EXISTS idx_votes_credential_id ON votes(credential_id);
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS vote_tracking (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        vote_id UUID UNIQUE NOT NULL,
        tracker_token VARCHAR(255) UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        FOREIGN KEY (vote_id) REFERENCES votes(id) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_vote_tracking_tracker_token ON vote_tracking(tracker_token);
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id BIGSERIAL PRIMARY KEY,
        event_id UUID DEFAULT gen_random_uuid() UNIQUE,
        action VARCHAR(100) NOT NULL,
        actor_id VARCHAR(100),
        actor_role VARCHAR(50),
        resource_type VARCHAR(50),
        resource_id UUID,
        resource_data JSONB,
        status VARCHAR(20),
        result VARCHAR(20),
        error_message TEXT,
        ip_address INET,
        user_agent TEXT,
        timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
        hash_chain VARCHAR(64),
        previous_hash VARCHAR(64),
        CONSTRAINT valid_timestamp CHECK (timestamp <= NOW())
      );
      CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_audit_log_actor ON audit_log(actor_id);
      CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS elections (
        id VARCHAR(50) PRIMARY KEY DEFAULT 'current',
        is_open BOOLEAN DEFAULT false,
        start_time TIMESTAMP,
        end_time TIMESTAMP,
        positions JSONB NOT NULL,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS results (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        position VARCHAR(100) NOT NULL,
        candidate_name VARCHAR(255) NOT NULL,
        vote_count INT DEFAULT 0,
        candidate_class VARCHAR(10),
        created_at TIMESTAMP DEFAULT NOW(),
        CONSTRAINT unique_position_candidate UNIQUE(position, candidate_name)
      );
      CREATE INDEX IF NOT EXISTS idx_results_position ON results(position);
    `);

    console.log('✅ Database schema initialized successfully');
  } catch (error) {
    console.error('❌ Error initializing database schema:', error);
    throw error;
  }
}

module.exports = {
  pool,
  initializeDatabase,
  query: (text, params) => pool.query(text, params),
};
