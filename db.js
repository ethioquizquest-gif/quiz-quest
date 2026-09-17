const { createClient } = require('@libsql/client/web');
const path = require('path');
require('dotenv').config();

// Use Turso if available, fallback to local SQLite
const dbUrl = process.env.TURSO_DATABASE_URL || `file:${path.join(__dirname, 'database.sqlite')}`;
const authToken = process.env.TURSO_AUTH_TOKEN;

const db = createClient({
    url: dbUrl,
    authToken: authToken
});

// ============ CREATE ALL TABLES ============
async function initDb() {
    try {
        await db.execute(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                is_verified BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        `);

        await db.execute(`
            CREATE TABLE IF NOT EXISTS screenshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await db.execute(`
            CREATE TABLE IF NOT EXISTS quest_participants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await db.execute(`
            CREATE TABLE IF NOT EXISTS quiz_pairs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                player1_id INTEGER NOT NULL,
                player2_id INTEGER NOT NULL,
                round INTEGER DEFAULT 1,
                winner_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await db.execute(`
            CREATE TABLE IF NOT EXISTS quiz_answers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pair_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                question_index INTEGER NOT NULL,
                is_correct BOOLEAN DEFAULT 0,
                answered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await db.execute(`
            CREATE TABLE IF NOT EXISTS tournament_rounds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                round_number INTEGER NOT NULL,
                status TEXT DEFAULT 'active',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                completed_at TIMESTAMP
            )
        `);

        console.log('✅ Database tables initialized (Turso)');
    } catch (error) {
        console.error('❌ Database init error:', error);
    }
}

initDb();

// ============ HELPER FUNCTIONS ============
const query = async (sql, params = []) => {
    const result = await db.execute({ sql, args: params });
    return result.rows;
};

const run = async (sql, params = []) => {
    const result = await db.execute({ sql, args: params });
    return { id: Number(result.lastInsertRowid) };
};

const get = async (sql, params = []) => {
    const result = await db.execute({ sql, args: params });
    return result.rows[0] || null;
};

module.exports = { query, run, get, db };