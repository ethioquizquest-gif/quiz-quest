const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { query, run, get } = require('./db');
const allQuestions = require('./questions.js');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

// ============ CREATE UPLOADS FOLDER ============
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

// ============ MULTER SETUP ============
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const unique = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, unique + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// ============ JWT HELPERS ============
const generateToken = (userId) => {
    return jwt.sign({ userId }, process.env.JWT_SECRET || 'mysecretkey', { expiresIn: '7d' });
};

const authMiddleware = async (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'mysecretkey');
        const user = await get('SELECT id, email FROM users WHERE id = ?', [decoded.userId]);
        if (!user) {
            return res.status(401).json({ error: 'User not found' });
        }
        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid or expired token' });
    }
};

// ============ REGISTER ============
app.post('/api/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }
        const passwordHash = await bcrypt.hash(password, 10);
        try {
            const result = await run(
                'INSERT INTO users (email, password_hash) VALUES (?, ?)',
                [email.toLowerCase().trim(), passwordHash]
            );
            res.status(201).json({
                message: 'User created successfully! Please login.',
                user: { id: result.id, email }
            });
        } catch (error) {
            if (error.message.includes('UNIQUE constraint')) {
                return res.status(400).json({ error: 'Email already registered' });
            }
            throw error;
        }
    } catch (error) {
        console.error('Register error:', error.message);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ LOGIN ============
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        const user = await get(
            'SELECT id, email, password_hash FROM users WHERE email = ?',
            [email.toLowerCase().trim()]
        );
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const isValid = await bcrypt.compare(password, user.password_hash);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        await run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);
        const token = generateToken(user.id);
        res.json({
            message: 'Login successful!',
            token,
            user: { id: user.id, email: user.email }
        });
    } catch (error) {
        console.error('Login error:', error.message);
        res.status(500).json({ error: 'Server error' });
    }
});

// ============ UPLOAD SCREENSHOT ============
app.post('/api/upload-screenshot', authMiddleware, upload.single('screenshot'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        const userId = req.user.id;
        const filename = req.file.filename;
        const existing = await get('SELECT id FROM screenshots WHERE user_id = ?', [userId]);
        if (existing) {
            const old = await get('SELECT filename FROM screenshots WHERE user_id = ?', [userId]);
            if (old) {
                const oldPath = path.join(__dirname, 'uploads', old.filename);
                if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
            }
            await run(
                "UPDATE screenshots SET filename = ?, status = 'pending', uploaded_at = CURRENT_TIMESTAMP WHERE user_id = ?",
                [filename, userId]
            );
        } else {
            await run("INSERT INTO screenshots (user_id, filename, status) VALUES (?, ?, 'pending')", [userId, filename]);
        }
        res.json({ message: 'Screenshot uploaded! Waiting for admin approval.' });
    } catch (error) {
        console.error('Upload error:', error.message);
        res.status(500).json({ error: 'Upload failed: ' + error.message });
    }
});

// ============ CHECK SCREENSHOT STATUS ============
app.get('/api/screenshot-status', authMiddleware, async (req, res) => {
    try {
        const result = await get('SELECT status FROM screenshots WHERE user_id = ?', [req.user.id]);
        res.json({ status: result ? result.status : 'none' });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============ ADMIN: GET PENDING SCREENSHOTS ============
app.get('/api/admin/pending', authMiddleware, async (req, res) => {
    try {
        if (req.user.id !== 1) {
            return res.status(403).json({ error: 'Admin only' });
        }
        const pending = await query(`
            SELECT s.id, s.user_id, s.filename, s.status, u.email
            FROM screenshots s
            JOIN users u ON s.user_id = u.id
            WHERE s.status = 'pending'
        `);
        res.json(pending);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============ ADMIN: APPROVE / REJECT SCREENSHOT ============
app.post('/api/admin/approve', authMiddleware, async (req, res) => {
    try {
        const { screenshotId, action } = req.body;
        if (req.user.id !== 1) {
            return res.status(403).json({ error: 'Admin only' });
        }
        const status = action === 'approve' ? 'approved' : 'rejected';
        await run('UPDATE screenshots SET status = ? WHERE id = ?', [status, screenshotId]);
        res.json({ message: 'Screenshot ' + status });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============ JOIN QUEST ============
app.post('/api/join-quest', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;

        if (userId === 1) {
            return res.status(403).json({ error: 'Admin accounts cannot join the quest.' });
        }

        const screenshot = await get('SELECT status FROM screenshots WHERE user_id = ?', [userId]);
        if (!screenshot || screenshot.status !== 'approved') {
            return res.status(403).json({ error: 'You must be approved to join the quest.' });
        }

        const existing = await get('SELECT id FROM quest_participants WHERE user_id = ?', [userId]);
        if (existing) {
            return res.status(400).json({ error: 'You already joined the quest.' });
        }

        const countResult = await get('SELECT COUNT(*) as count FROM quest_participants');
        const currentCount = Number(countResult?.count || 0);

        if (currentCount >= 80) {
            return res.status(400).json({ error: 'Quest is full! Maximum 80 users allowed.' });
        }

        await run('INSERT INTO quest_participants (user_id) VALUES (?)', [userId]);

        const remaining = 80 - (currentCount + 1);
        res.json({
            message: '🎉 You joined the quest!',
            totalJoined: currentCount + 1,
            spotsLeft: remaining
        });
    } catch (error) {
        console.error('Join quest error:', error.message);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ GET QUEST STATUS ============
app.get('/api/quest-status', authMiddleware, async (req, res) => {
    try {
        const countResult = await get('SELECT COUNT(*) as count FROM quest_participants');
        const total = Number(countResult?.count || 0);
        const remaining = Math.max(0, 80 - total);

        const userJoined = await get('SELECT id FROM quest_participants WHERE user_id = ?', [req.user.id]);

        res.json({
            totalJoined: total,
            spotsLeft: remaining,
            isFull: total >= 80,
            userJoined: !!userJoined
        });
    } catch (error) {
        console.error('Quest status error:', error.message);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ ADMIN: GET ALL PARTICIPANTS ============
app.get('/api/admin/participants', authMiddleware, async (req, res) => {
    try {
        if (req.user.id !== 1) {
            return res.status(403).json({ error: 'Admin only' });
        }
        const participants = await query(`
            SELECT u.id, u.email, u.created_at, qp.joined_at
            FROM quest_participants qp
            JOIN users u ON qp.user_id = u.id
            WHERE u.id != 1
            ORDER BY u.created_at ASC
        `);
        console.log('📊 Participants found:', participants.length);
        res.json(participants);
    } catch (error) {
        console.error('Participants error:', error.message);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ ADMIN: GET ALL PAIRS ============
app.get('/api/admin/pairs', authMiddleware, async (req, res) => {
    try {
        if (req.user.id !== 1) {
            return res.status(403).json({ error: 'Admin only' });
        }
        const pairs = await query(`
            SELECT 
                qp.id,
                qp.player1_id,
                qp.player2_id,
                qp.winner_id,
                qp.round,
                qp.created_at,
                u1.email as player1_email,
                u2.email as player2_email,
                u3.email as winner_email
            FROM quiz_pairs qp
            JOIN users u1 ON qp.player1_id = u1.id
            JOIN users u2 ON qp.player2_id = u2.id
            LEFT JOIN users u3 ON qp.winner_id = u3.id
            ORDER BY qp.created_at DESC
        `);
        res.json(pairs);
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============ PAIR USERS (ADMIN ONLY) ============
app.post('/api/pair-users', authMiddleware, async (req, res) => {
    try {
        if (req.user.id !== 1) {
            return res.status(403).json({ error: 'Admin only' });
        }

        const participants = await query(`
            SELECT user_id FROM quest_participants 
            WHERE user_id != 1
            ORDER BY joined_at ASC
        `);

        if (participants.length < 2) {
            return res.status(400).json({ error: 'Need at least 2 participants to pair.' });
        }

        const shuffled = participants.sort(() => Math.random() - 0.5);
        const pairs = [];

        for (let i = 0; i < shuffled.length - 1; i += 2) {
            const p1 = shuffled[i].user_id;
            const p2 = shuffled[i + 1].user_id;
            const result = await run(
                'INSERT INTO quiz_pairs (player1_id, player2_id, round) VALUES (?, ?, 1)',
                [p1, p2]
            );
            pairs.push({ pairId: result.id, player1: p1, player2: p2 });
        }

        res.json({ 
            message: `${pairs.length} pairs created!`, 
            pairs 
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ ADMIN: RESET PAIRS ============
app.post('/api/admin/reset-pairs', authMiddleware, async (req, res) => {
    try {
        if (req.user.id !== 1) {
            return res.status(403).json({ error: 'Admin only' });
        }
        await run('DELETE FROM quiz_answers');
        await run('DELETE FROM quiz_pairs');
        await run('DELETE FROM tournament_rounds');
        res.json({ message: '✅ All pairs, answers, and rounds have been reset!' });
    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ GET MY PAIR ============
app.get('/api/my-pair', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const pair = await get(`
            SELECT id, round FROM quiz_pairs 
            WHERE (player1_id = ? OR player2_id = ?) 
            AND winner_id IS NULL
            ORDER BY created_at DESC LIMIT 1
        `, [userId, userId]);
        
        res.json({ 
            pairId: pair ? pair.id : null,
            round: pair ? pair.round : null
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============ CHECK IF USER WAS ELIMINATED ============
app.get('/api/am-i-eliminated', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;

        const lostPair = await get(`
            SELECT id, round, winner_id 
            FROM quiz_pairs 
            WHERE (player1_id = ? OR player2_id = ?) 
            AND winner_id IS NOT NULL 
            AND winner_id != ?
            ORDER BY created_at DESC LIMIT 1
        `, [userId, userId, userId]);

        if (!lostPair) {
            return res.json({ eliminated: false });
        }

        const stillActive = await get(`
            SELECT id FROM quiz_pairs 
            WHERE (player1_id = ? OR player2_id = ?) 
            AND winner_id IS NULL
            LIMIT 1
        `, [userId, userId]);

        if (stillActive) {
            return res.json({ eliminated: false });
        }

        const finalWin = await get(`
            SELECT id FROM quiz_pairs 
            WHERE winner_id = ? AND round = 4
        `, [userId]);

        if (finalWin) {
            return res.json({ eliminated: false, isFinalWinner: true });
        }

        res.json({
            eliminated: true,
            round: lostPair.round,
            reason: `You were eliminated in Round ${lostPair.round}.`
        });

    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ CHECK IF USER ALREADY COMPLETED QUIZ ============
app.get('/api/quiz-completed/:pairId', authMiddleware, async (req, res) => {
    try {
        const pairId = req.params.pairId;
        const userId = req.user.id;

        const pair = await get('SELECT * FROM quiz_pairs WHERE id = ?', [pairId]);
        if (!pair) {
            return res.status(404).json({ error: 'Pair not found' });
        }

        if (pair.player1_id !== userId && pair.player2_id !== userId) {
            return res.status(403).json({ error: 'You are not part of this pair' });
        }

        const existingAnswers = await query(
            'SELECT COUNT(*) as count FROM quiz_answers WHERE pair_id = ? AND user_id = ?',
            [pairId, userId]
        );

        const answeredCount = Number(existingAnswers[0]?.count || 0);
        const hasCompleted = answeredCount >= 8;

        res.json({
            completed: hasCompleted,
            answeredCount: answeredCount,
            totalQuestions: 8,
            winnerId: pair.winner_id
        });

    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ GET QUESTIONS FOR SPECIFIC PAIR ============
app.get('/api/questions', authMiddleware, async (req, res) => {
    try {
        const { round, pairId } = req.query;
        
        const roundNum = parseInt(round) || 1;
        const pairNum = parseInt(pairId) || 1;
        
        const questions = allQuestions[roundNum]?.[pairNum];
        
        if (!questions || questions.length === 0) {
            return res.status(404).json({ 
                error: `No questions found for Round ${roundNum}, Pair ${pairNum}` 
            });
        }
        
        res.json(questions);
    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ DISQUALIFY USER ============
app.post('/api/disqualify', authMiddleware, async (req, res) => {
    try {
        const { pairId } = req.body;
        const userId = req.user.id;

        if (!pairId) {
            return res.status(400).json({ error: 'Pair ID required' });
        }

        const pair = await get('SELECT * FROM quiz_pairs WHERE id = ?', [pairId]);
        if (!pair) {
            return res.status(404).json({ error: 'Pair not found' });
        }

        let opponentId;
        if (pair.player1_id === userId) {
            opponentId = pair.player2_id;
        } else if (pair.player2_id === userId) {
            opponentId = pair.player1_id;
        } else {
            return res.status(403).json({ error: 'You are not part of this pair' });
        }

        await run('UPDATE quiz_pairs SET winner_id = ? WHERE id = ?', [opponentId, pairId]);

        res.json({ 
            message: 'You have been disqualified. Your opponent wins.',
            winnerId: opponentId
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ GET QUIZ RESULTS (Registration Time Tiebreaker) ============
app.get('/api/quiz-results/:pairId', authMiddleware, async (req, res) => {
    try {
        const pairId = req.params.pairId;
        const userId = req.user.id;

        const pair = await get(`
            SELECT qp.id, qp.player1_id, qp.player2_id, 
                   u1.email as player1_email, u1.created_at as player1_registered,
                   u2.email as player2_email, u2.created_at as player2_registered
            FROM quiz_pairs qp
            JOIN users u1 ON qp.player1_id = u1.id
            JOIN users u2 ON qp.player2_id = u2.id
            WHERE qp.id = ?
        `, [pairId]);

        if (!pair) {
            return res.status(404).json({ error: 'Pair not found' });
        }

        if (userId !== pair.player1_id && userId !== pair.player2_id) {
            return res.status(403).json({ error: 'You are not part of this pair' });
        }

        const answers = await query(`
            SELECT user_id, question_index, is_correct
            FROM quiz_answers
            WHERE pair_id = ?
            ORDER BY user_id, question_index
        `, [pairId]);

        const player1Answers = answers.filter(a => a.user_id === pair.player1_id);
        const player2Answers = answers.filter(a => a.user_id === pair.player2_id);

        const player1Score = player1Answers.filter(a => a.is_correct === 1).length;
        const player2Score = player2Answers.filter(a => a.is_correct === 1).length;

        let winnerId = null;
        let winnerEmail = null;
        let resultMessage = '';

        if (player1Score > player2Score) {
            winnerId = pair.player1_id;
            winnerEmail = pair.player1_email;
            resultMessage = `${pair.player1_email} wins! 🎉`;
        } else if (player2Score > player1Score) {
            winnerId = pair.player2_id;
            winnerEmail = pair.player2_email;
            resultMessage = `${pair.player2_email} wins! 🎉`;
        } else {
            const p1RegTime = new Date(pair.player1_registered).getTime();
            const p2RegTime = new Date(pair.player2_registered).getTime();

            if (p1RegTime < p2RegTime) {
                winnerId = pair.player1_id;
                winnerEmail = pair.player1_email;
                resultMessage = `🤝 Tie (${player1Score}-${player2Score})! ${pair.player1_email} wins by earlier registration.`;
            } else if (p2RegTime < p1RegTime) {
                winnerId = pair.player2_id;
                winnerEmail = pair.player2_email;
                resultMessage = `🤝 Tie (${player1Score}-${player2Score})! ${pair.player2_email} wins by earlier registration.`;
            } else {
                if (pair.player1_id < pair.player2_id) {
                    winnerId = pair.player1_id;
                    winnerEmail = pair.player1_email;
                    resultMessage = `🤝 Tie! ${pair.player1_email} wins by earlier registration.`;
                } else {
                    winnerId = pair.player2_id;
                    winnerEmail = pair.player2_email;
                    resultMessage = `🤝 Tie! ${pair.player2_email} wins by earlier registration.`;
                }
            }
        }

        if (winnerId) {
            await run('UPDATE quiz_pairs SET winner_id = ? WHERE id = ?', [winnerId, pairId]);
        }

        res.json({
            pairId: pair.id,
            player1: { id: pair.player1_id, email: pair.player1_email, score: player1Score },
            player2: { id: pair.player2_id, email: pair.player2_email, score: player2Score },
            winnerId: winnerId,
            winnerEmail: winnerEmail,
            message: resultMessage
        });

    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ SUBMIT ANSWER ============
app.post('/api/submit-answer', authMiddleware, async (req, res) => {
    try {
        const { pairId, questionIndex, selectedOption } = req.body;
        const userId = req.user.id;

        const round = parseInt(req.query.round) || 1;
        const pairNum = parseInt(req.query.pairId) || 1;

        const pairQuestions = allQuestions[round]?.[pairNum];
        if (!pairQuestions || !pairQuestions[questionIndex]) {
            return res.status(404).json({ error: 'Question not found' });
        }

        const isCorrect = pairQuestions[questionIndex].correctAnswer === selectedOption;

        await run(
            'INSERT INTO quiz_answers (pair_id, user_id, question_index, is_correct) VALUES (?, ?, ?, ?)',
            [pairId, userId, questionIndex, isCorrect ? 1 : 0]
        );

        res.json({ isCorrect });
    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ AUTO-KICK INACTIVE USERS (5 MINUTES) ============
app.post('/api/admin/check-timeouts', authMiddleware, async (req, res) => {
    try {
        if (req.user.id !== 1) {
            return res.status(403).json({ error: 'Admin only' });
        }

        const TIMEOUT_MINUTES = 5;
        const timeoutMs = TIMEOUT_MINUTES * 60 * 1000;

        const activePairs = await query(`
            SELECT 
                qp.id,
                qp.player1_id,
                qp.player2_id,
                qp.round,
                qp.created_at,
                u1.email as player1_email,
                u2.email as player2_email
            FROM quiz_pairs qp
            JOIN users u1 ON qp.player1_id = u1.id
            JOIN users u2 ON qp.player2_id = u2.id
            WHERE qp.winner_id IS NULL
        `);

        const now = Date.now();
        const resolved = [];

        for (const pair of activePairs) {
            const pairCreated = new Date(pair.created_at).getTime();
            const elapsed = now - pairCreated;

            if (elapsed < timeoutMs) continue;

            const p1Answers = await get(
                'SELECT COUNT(*) as count FROM quiz_answers WHERE pair_id = ? AND user_id = ?',
                [pair.id, pair.player1_id]
            );
            const p2Answers = await get(
                'SELECT COUNT(*) as count FROM quiz_answers WHERE pair_id = ? AND user_id = ?',
                [pair.id, pair.player2_id]
            );

            const p1Count = Number(p1Answers?.count || 0);
            const p2Count = Number(p2Answers?.count || 0);

            let winnerId = null;
            let loserId = null;
            let reason = '';

            if (p1Count >= 8 && p2Count < 8) {
                winnerId = pair.player1_id;
                loserId = pair.player2_id;
                reason = `${pair.player2_email} did not finish in time`;
            } else if (p2Count >= 8 && p1Count < 8) {
                winnerId = pair.player2_id;
                loserId = pair.player1_id;
                reason = `${pair.player1_email} did not finish in time`;
            } else if (p1Count === 0 && p2Count === 0) {
                const p1Reg = await get('SELECT created_at FROM users WHERE id = ?', [pair.player1_id]);
                const p2Reg = await get('SELECT created_at FROM users WHERE id = ?', [pair.player2_id]);

                if (p1Reg && p2Reg) {
                    const p1Time = new Date(p1Reg.created_at).getTime();
                    const p2Time = new Date(p2Reg.created_at).getTime();
                    if (p1Time <= p2Time) {
                        winnerId = pair.player1_id;
                        loserId = pair.player2_id;
                    } else {
                        winnerId = pair.player2_id;
                        loserId = pair.player1_id;
                    }
                } else {
                    winnerId = pair.player1_id < pair.player2_id ? pair.player1_id : pair.player2_id;
                    loserId = winnerId === pair.player1_id ? pair.player2_id : pair.player1_id;
                }
                reason = 'Both inactive — earlier registration wins';
            } else if (p1Count > 0 && p2Count > 0) {
                const p1Correct = await get(
                    'SELECT COUNT(*) as count FROM quiz_answers WHERE pair_id = ? AND user_id = ? AND is_correct = 1',
                    [pair.id, pair.player1_id]
                );
                const p2Correct = await get(
                    'SELECT COUNT(*) as count FROM quiz_answers WHERE pair_id = ? AND user_id = ? AND is_correct = 1',
                    [pair.id, pair.player2_id]
                );

                const p1CorrectCount = Number(p1Correct?.count || 0);
                const p2CorrectCount = Number(p2Correct?.count || 0);

                if (p1CorrectCount > p2CorrectCount) {
                    winnerId = pair.player1_id;
                    loserId = pair.player2_id;
                    reason = 'Timeout — higher score wins';
                } else if (p2CorrectCount > p1CorrectCount) {
                    winnerId = pair.player2_id;
                    loserId = pair.player1_id;
                    reason = 'Timeout — higher score wins';
                } else {
                    const p1Reg = await get('SELECT created_at FROM users WHERE id = ?', [pair.player1_id]);
                    const p2Reg = await get('SELECT created_at FROM users WHERE id = ?', [pair.player2_id]);
                    if (p1Reg && p2Reg) {
                        const p1Time = new Date(p1Reg.created_at).getTime();
                        const p2Time = new Date(p2Reg.created_at).getTime();
                        winnerId = p1Time <= p2Time ? pair.player1_id : pair.player2_id;
                    } else {
                        winnerId = pair.player1_id < pair.player2_id ? pair.player1_id : pair.player2_id;
                    }
                    loserId = winnerId === pair.player1_id ? pair.player2_id : pair.player1_id;
                    reason = 'Timeout — tie broken by earlier registration';
                }
            }

            if (winnerId) {
                await run('UPDATE quiz_pairs SET winner_id = ? WHERE id = ?', [winnerId, pair.id]);
                resolved.push({
                    pairId: pair.id,
                    winnerId: winnerId,
                    loserId: loserId,
                    reason: reason
                });
            }
        }

        res.json({
            message: `✅ Checked ${activePairs.length} active pairs. ${resolved.length} resolved by timeout (5 min).`,
            resolved: resolved
        });

    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ TOURNAMENT: GET CURRENT ROUND ============
app.get('/api/tournament/current-round', authMiddleware, async (req, res) => {
    try {
        const currentRound = await get(`
            SELECT * FROM tournament_rounds 
            ORDER BY round_number DESC LIMIT 1
        `);

        if (!currentRound) {
            return res.json({ round: 0, status: 'not_started' });
        }

        res.json({
            round: currentRound.round_number,
            status: currentRound.status,
            startedAt: currentRound.started_at,
            completedAt: currentRound.completed_at
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============ ADMIN: START NEW ROUND ============
app.post('/api/admin/start-round', authMiddleware, async (req, res) => {
    try {
        if (req.user.id !== 1) {
            return res.status(403).json({ error: 'Admin only' });
        }

        const { roundNumber } = req.body;
        const round = parseInt(roundNumber);

        if (!round || round < 1 || round > 4) {
            return res.status(400).json({ error: 'Round must be 1, 2, 3, or 4' });
        }

        const activeRound = await get(`
            SELECT * FROM tournament_rounds WHERE status = 'active'
        `);

        if (activeRound && activeRound.round_number !== round) {
            return res.status(400).json({ 
                error: `Round ${activeRound.round_number} is still active. Complete it first.` 
            });
        }

        let participants = [];

        if (round === 1) {
            participants = await query(`
                SELECT user_id FROM quest_participants 
                WHERE user_id != 1
            `);
        } else {
            const previousRound = round - 1;
            participants = await query(`
                SELECT DISTINCT winner_id as user_id
                FROM quiz_pairs 
                WHERE round = ? AND winner_id IS NOT NULL
            `, [previousRound]);
        }

        if (participants.length < 2) {
            return res.status(400).json({ 
                error: `Not enough participants for Round ${round}. Need at least 2, found ${participants.length}.` 
            });
        }

        await run(`
            UPDATE tournament_rounds SET status = 'completed', completed_at = CURRENT_TIMESTAMP
            WHERE status = 'active'
        `);

        await run(`
            INSERT INTO tournament_rounds (round_number, status) 
            VALUES (?, 'active')
        `, [round]);

        const shuffled = participants.sort(() => Math.random() - 0.5);
        const pairs = [];

        for (let i = 0; i < shuffled.length - 1; i += 2) {
            const p1 = shuffled[i].user_id;
            const p2 = shuffled[i + 1].user_id;
            const result = await run(
                'INSERT INTO quiz_pairs (player1_id, player2_id, round) VALUES (?, ?, ?)',
                [p1, p2, round]
            );
            pairs.push({ pairId: result.id, player1: p1, player2: p2 });
        }

        res.json({
            message: `🎉 Round ${round} started with ${pairs.length} pairs!`,
            round: round,
            totalParticipants: participants.length,
            totalPairs: pairs.length,
            pairs: pairs
        });

    } catch (error) {
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ TOURNAMENT: GET ROUND RESULTS ============
app.get('/api/tournament/round/:roundNumber/results', authMiddleware, async (req, res) => {
    try {
        const roundNumber = parseInt(req.params.roundNumber);

        const pairs = await query(`
            SELECT 
                qp.id,
                qp.player1_id,
                qp.player2_id,
                qp.winner_id,
                u1.email as player1_email,
                u2.email as player2_email,
                u3.email as winner_email
            FROM quiz_pairs qp
            JOIN users u1 ON qp.player1_id = u1.id
            JOIN users u2 ON qp.player2_id = u2.id
            LEFT JOIN users u3 ON qp.winner_id = u3.id
            WHERE qp.round = ?
            ORDER BY qp.id ASC
        `, [roundNumber]);

        const totalPairs = pairs.length;
        const completedPairs = pairs.filter(p => p.winner_id !== null).length;
        const winners = pairs.filter(p => p.winner_id !== null).length;

        res.json({
            round: roundNumber,
            totalPairs: totalPairs,
            completedPairs: completedPairs,
            isComplete: totalPairs > 0 && totalPairs === completedPairs,
            winners: winners,
            pairs: pairs
        });

    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============ TOURNAMENT: GET FINAL WINNERS ============
app.get('/api/tournament/final-winners', authMiddleware, async (req, res) => {
    try {
        const winners = await query(`
            SELECT 
                u.id,
                u.email,
                qp.winner_id
            FROM quiz_pairs qp
            JOIN users u ON qp.winner_id = u.id
            WHERE qp.round = 4 AND qp.winner_id IS NOT NULL
        `);

        res.json({
            totalWinners: winners.length,
            winners: winners
        });

    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// ============ ADMIN: KICK USER (DELETE) ============
app.delete('/api/admin/kick-user/:userId', authMiddleware, async (req, res) => {
    try {
        if (req.user.id !== 1) {
            return res.status(403).json({ error: 'Admin only' });
        }

        const userId = parseInt(req.params.userId);

        if (userId === 1) {
            return res.status(400).json({ error: 'Cannot kick the admin account' });
        }

        await run('DELETE FROM quiz_answers WHERE user_id = ?', [userId]);
        await run('DELETE FROM quiz_pairs WHERE player1_id = ? OR player2_id = ?', [userId, userId]);
        await run('DELETE FROM quest_participants WHERE user_id = ?', [userId]);
        await run('DELETE FROM screenshots WHERE user_id = ?', [userId]);
        await run('DELETE FROM users WHERE id = ?', [userId]);

        console.log(`🗑️ Kicked user ID: ${userId}`);
        res.json({ message: `✅ User ${userId} kicked successfully!` });
    } catch (error) {
        console.error('Kick user error:', error.message);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ ADMIN: GET ALL USERS (FOR KICK PANEL) ============
app.get('/api/admin/all-users', authMiddleware, async (req, res) => {
    try {
        if (req.user.id !== 1) {
            return res.status(403).json({ error: 'Admin only' });
        }

        const users = await query(`
            SELECT 
                u.id,
                u.email,
                u.created_at,
                u.last_login,
                (SELECT COUNT(*) FROM quest_participants WHERE user_id = u.id) as joined_quest,
                (SELECT COUNT(*) FROM screenshots WHERE user_id = u.id) as has_screenshot
            FROM users u
            ORDER BY u.created_at ASC
        `);

        res.json(users);
    } catch (error) {
        console.error('All users error:', error.message);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ ADMIN: KICK DEMO USERS (BULK) ============
app.post('/api/admin/kick-demos', authMiddleware, async (req, res) => {
    try {
        if (req.user.id !== 1) {
            return res.status(403).json({ error: 'Admin only' });
        }

        const { pattern } = req.body;
        const searchPattern = pattern || '%test%';

        const demoUsers = await query(`
            SELECT id, email FROM users 
            WHERE email LIKE ? AND id != 1
        `, [searchPattern]);

        if (demoUsers.length === 0) {
            return res.json({ message: 'No demo users found.', kicked: 0 });
        }

        for (const user of demoUsers) {
            await run('DELETE FROM quiz_answers WHERE user_id = ?', [user.id]);
            await run('DELETE FROM quiz_pairs WHERE player1_id = ? OR player2_id = ?', [user.id, user.id]);
            await run('DELETE FROM quest_participants WHERE user_id = ?', [user.id]);
            await run('DELETE FROM screenshots WHERE user_id = ?', [user.id]);
            await run('DELETE FROM users WHERE id = ?', [user.id]);
        }

        console.log(`🗑️ Kicked ${demoUsers.length} demo users`);
        res.json({ 
            message: `✅ Kicked ${demoUsers.length} demo users!`,
            kicked: demoUsers.length,
            users: demoUsers.map(u => u.email)
        });
    } catch (error) {
        console.error('Kick demos error:', error.message);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ ADMIN: RESET EVERYTHING (NUCLEAR) ============
app.post('/api/admin/reset-everything', authMiddleware, async (req, res) => {
    try {
        if (req.user.id !== 1) {
            return res.status(403).json({ error: 'Admin only' });
        }

        const { confirm } = req.body;
        if (confirm !== 'RESET') {
            return res.status(400).json({ error: 'Type RESET to confirm' });
        }

        await run('DELETE FROM quiz_answers');
        await run('DELETE FROM quiz_pairs');
        await run('DELETE FROM quest_participants');
        await run('DELETE FROM screenshots');
        await run('DELETE FROM tournament_rounds');
        await run('DELETE FROM users WHERE id != 1');

        console.log('🚨 FULL RESET - all data cleared except admin');
        res.json({ message: '✅ Everything reset! Only admin remains.' });
    } catch (error) {
        console.error('Reset error:', error.message);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ============ START SERVER ============
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📁 Database: Turso (cloud)`);
    console.log(`📚 Questions loaded: Round 1, 2, 3, 4`);
    console.log(`⏰ Auto-kick timeout: 5 minutes`);
    console.log(`✅ Ready to accept registrations and logins!`);
});
