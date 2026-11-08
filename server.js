require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const session = require('express-session');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'peer_eval_db',
  waitForConnections: true,
  connectionLimit: 10
});

function authRequired(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Unauthorized: Login required.' });
  next();
}

function adminOnly(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: Admin access required.' });
  }
  next();
}

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) return res.status(401).json({ error: 'Invalid credentials.' });

    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials.' });

    req.session.user = { 
      id: user.id, 
      name: user.full_name, 
      email: user.email, 
      role: user.role, 
      groupId: user.group_id, 
      isLeader: user.is_leader 
    };
    res.json({ success: true, user: req.session.user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', (req, res) => {
  res.json({ user: req.session.user || null });
});

// Update Profile & Security Settings for Current User
app.put('/api/user/settings', authRequired, async (req, res) => {
  const userId = req.session.user.id;
  const { fullName, email, currentPassword, newPassword } = req.body;

  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE id = ?', [userId]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found.' });

    const user = rows[0];

    // Password verification for changes
    if (newPassword) {
      if (!currentPassword) return res.status(400).json({ error: 'Current password is required to set a new password.' });
      const match = await bcrypt.compare(currentPassword, user.password_hash);
      if (!match) return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    let passwordHash = user.password_hash;
    if (newPassword && newPassword.trim() !== '') {
      passwordHash = await bcrypt.hash(newPassword, 10);
    }

    await db.execute(
      'UPDATE users SET full_name = ?, email = ?, password_hash = ? WHERE id = ?',
      [fullName, email, passwordHash, userId]
    );

    req.session.user.name = fullName;
    req.session.user.email = email;

    res.json({ success: true, user: req.session.user });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin Dashboard Summary Metrics & System-wide Stats
app.get('/api/admin/dashboard-stats', authRequired, adminOnly, async (req, res) => {
  try {
    const [[{ totalGroups }]] = await db.execute('SELECT COUNT(*) AS totalGroups FROM groups');
    const [[{ totalStudents }]] = await db.execute('SELECT COUNT(*) AS totalStudents FROM users WHERE role = "student"');
    const [[{ totalSubmissions }]] = await db.execute('SELECT COUNT(*) AS totalSubmissions FROM peer_evaluations');
    const [[{ avgScore }]] = await db.execute('SELECT IFNULL(AVG(overall_weighted_score), 0) AS avgScore FROM peer_evaluations');

    res.json({
      totalGroups,
      totalStudents,
      totalSubmissions,
      avgScore: parseFloat(avgScore).toFixed(2)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Groups List
app.get('/api/admin/groups', authRequired, adminOnly, async (req, res) => {
  try {
    const [groups] = await db.execute(`
      SELECT 
        g.id, 
        g.group_name, 
        g.course_subject,
        g.project_title,
        COUNT(DISTINCT u.id) AS member_count,
        COUNT(DISTINCT pe.id) AS submitted_evals
      FROM groups g 
      LEFT JOIN users u ON g.id = u.group_id 
      LEFT JOIN peer_evaluations pe ON g.id = pe.group_id
      GROUP BY g.id, g.group_name, g.course_subject, g.project_title 
      ORDER BY g.id DESC
    `);

    const result = groups.map(g => {
      const requiredTotal = g.member_count * g.member_count;
      const isComplete = requiredTotal > 0 && g.submitted_evals >= requiredTotal;
      const completionPercent = requiredTotal > 0 ? Math.min(100, Math.round((g.submitted_evals / requiredTotal) * 100)) : 0;
      return { ...g, requiredTotal, isComplete, completionPercent };
    });

    res.json({ groups: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Create New Group with Course & Project Title
app.post('/api/admin/create-group', authRequired, adminOnly, async (req, res) => {
  const { groupName, courseSubject, projectTitle, members } = req.body;
  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();
    const [grp] = await conn.execute(
      'INSERT INTO groups (group_name, course_subject, project_title) VALUES (?, ?, ?)',
      [groupName, courseSubject || 'General Assessment', projectTitle || 'Cap-Stone / Final Project']
    );
    const groupId = grp.insertId;

    const defaultPassword = 'student123';
    const hash = await bcrypt.hash(defaultPassword, 10);

    for (const m of members) {
      await conn.execute(
        'INSERT INTO users (full_name, email, password_hash, role, group_id, is_leader) VALUES (?, ?, ?, "student", ?, ?)',
        [m.full_name, m.email, hash, groupId, m.is_leader ? 1 : 0]
      );
    }

    await conn.commit();
    res.json({ success: true, groupId, defaultPassword });
  } catch (err) {
    await conn.rollback();
    res.status(400).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// Admin: Edit Group Name, Course, Project Title & Roster
app.put('/api/admin/groups/:groupId', authRequired, adminOnly, async (req, res) => {
  const { groupId } = req.params;
  const { groupName, courseSubject, projectTitle, members } = req.body;
  const conn = await db.getConnection();

  try {
    await conn.beginTransaction();

    await conn.execute(
      'UPDATE groups SET group_name = ?, course_subject = ?, project_title = ? WHERE id = ?',
      [groupName, courseSubject, projectTitle, groupId]
    );

    const defaultPassword = 'student123';
    const hash = await bcrypt.hash(defaultPassword, 10);
    const existingMemberIds = [];

    for (const m of members) {
      if (m.id) {
        await conn.execute(
          'UPDATE users SET full_name = ?, email = ?, is_leader = ? WHERE id = ? AND group_id = ?',
          [m.full_name, m.email, m.is_leader ? 1 : 0, m.id, groupId]
        );
        existingMemberIds.push(m.id);
      } else {
        const [u] = await conn.execute(
          'INSERT INTO users (full_name, email, password_hash, role, group_id, is_leader) VALUES (?, ?, ?, "student", ?, ?)',
          [m.full_name, m.email, hash, groupId, m.is_leader ? 1 : 0]
        );
        existingMemberIds.push(u.insertId);
      }
    }

    if (existingMemberIds.length > 0) {
      await conn.execute(
        `UPDATE users SET group_id = NULL WHERE group_id = ? AND id NOT IN (${existingMemberIds.map(() => '?').join(',')})`,
        [groupId, ...existingMemberIds]
      );
    }

    await conn.commit();
    res.json({ success: true });
  } catch (err) {
    await conn.rollback();
    res.status(400).json({ error: err.message });
  } finally {
    conn.release();
  }
});

// Admin: Inspect Group Details
app.get('/api/admin/groups/:groupId', authRequired, adminOnly, async (req, res) => {
  const { groupId } = req.params;
  try {
    const [[group]] = await db.execute('SELECT * FROM groups WHERE id = ?', [groupId]);
    if (!group) return res.status(404).json({ error: 'Group not found' });

    const [members] = await db.execute(
      'SELECT id, full_name, email, is_leader FROM users WHERE group_id = ? ORDER BY full_name ASC',
      [groupId]
    );

    const [evaluations] = await db.execute(`
      SELECT 
        pe.*,
        u_evaluator.full_name AS evaluator_name,
        u_evaluatee.full_name AS evaluatee_name
      FROM peer_evaluations pe
      JOIN users u_evaluator ON pe.evaluator_id = u_evaluator.id
      JOIN users u_evaluatee ON pe.evaluatee_id = u_evaluatee.id
      WHERE pe.group_id = ?
      ORDER BY u_evaluatee.full_name ASC
    `, [groupId]);

    const studentScores = {};
    members.forEach(m => {
      studentScores[m.id] = { id: m.id, name: m.full_name, is_leader: m.is_leader, email: m.email, ratingsCount: 0, totalWeightedScore: 0, avgWeightedScore: '0.00', interpretation: 'Pending' };
    });

    evaluations.forEach(ev => {
      if (studentScores[ev.evaluatee_id]) {
        studentScores[ev.evaluatee_id].ratingsCount += 1;
        studentScores[ev.evaluatee_id].totalWeightedScore += parseFloat(ev.overall_weighted_score);
      }
    });

    Object.values(studentScores).forEach(s => {
      if (s.ratingsCount > 0) {
        s.avgWeightedScore = (s.totalWeightedScore / s.ratingsCount).toFixed(2);
        const score = parseFloat(s.avgWeightedScore);
        if (score >= 90) s.interpretation = "Outstanding Contributor";
        else if (score >= 70) s.interpretation = "Strong Contributor";
        else if (score >= 50) s.interpretation = "Satisfactory Contributor";
        else if (score >= 30) s.interpretation = "Limited Contributor";
        else s.interpretation = "Minimal Contributor";
      }
    });

    res.json({
      group,
      members,
      evaluations,
      summary: Object.values(studentScores)
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Delete Group
app.delete('/api/admin/groups/:groupId', authRequired, adminOnly, async (req, res) => {
  const { groupId } = req.params;
  try {
    await db.execute('DELETE FROM groups WHERE id = ?', [groupId]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Admin: Export CSV Matrix Report
app.get('/api/admin/groups/:groupId/export-csv', authRequired, adminOnly, async (req, res) => {
  const { groupId } = req.params;
  try {
    const [evaluations] = await db.execute(`
      SELECT 
        u_evaluator.full_name AS evaluator,
        u_evaluatee.full_name AS evaluatee,
        pe.course_subject,
        pe.project_title,
        pe.perf_avg,
        pe.fin_avg,
        pe.overall_weighted_score,
        pe.score_interpretation,
        pe.fin_unpaid_balance,
        pe.comments_contributions,
        pe.comments_failures
      FROM peer_evaluations pe
      JOIN users u_evaluator ON pe.evaluator_id = u_evaluator.id
      JOIN users u_evaluatee ON pe.evaluatee_id = u_evaluatee.id
      WHERE pe.group_id = ?
    `, [groupId]);

    let csv = "Evaluator,Evaluatee,Course,Project,Performance Avg (80%),Financial Avg (20%),Weighted Score (/100),Interpretation,Unpaid Balance,Contributions,Failures\n";
    evaluations.forEach(e => {
      csv += `"${e.evaluator}","${e.evaluatee}","${e.course_subject}","${e.project_title}",${e.perf_avg},${e.fin_avg},${e.overall_weighted_score},"${e.score_interpretation}",${e.fin_unpaid_balance},"${(e.comments_contributions||'').replace(/"/g, '""')}","${(e.comments_failures||'').replace(/"/g, '""')}"\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=Group_${groupId}_Evaluation_Report.csv`);
    res.send(csv);
  } catch (err) {
    res.status(500).send("Error generating CSV");
  }
});

// Student Group & Peer Info (Fetches preset course_subject & project_title set by Admin)
app.get('/api/group/peers', authRequired, async (req, res) => {
  const user = req.session.user;
  if (!user.groupId) return res.status(400).json({ error: 'User is not assigned to any group.' });

  try {
    const [[group]] = await db.execute('SELECT id, group_name, course_subject, project_title FROM groups WHERE id = ?', [user.groupId]);

    const [members] = await db.execute(
      'SELECT id, full_name, is_leader FROM users WHERE group_id = ? ORDER BY full_name ASC',
      [user.groupId]
    );

    const [submitted] = await db.execute(
      'SELECT evaluatee_id FROM peer_evaluations WHERE group_id = ? AND evaluator_id = ?',
      [user.groupId, user.id]
    );
    const completedIds = submitted.map(s => s.evaluatee_id);

    res.json({ group, members, completedIds });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Submit Peer Rating
app.post('/api/evaluations/submit', authRequired, async (req, res) => {
  const evaluatorId = req.session.user.id;
  const groupId = req.session.user.groupId;
  const { evaluateeId, criteria, financial, comments } = req.body;

  const conn = await db.getConnection();
  try {
    await conn.beginTransaction();

    // Fetch preset course & project details set by Admin for this group
    const [[group]] = await conn.execute('SELECT course_subject, project_title FROM groups WHERE id = ?', [groupId]);
    if (!group) throw new Error("Group details not found.");

    const [evalCheck] = await conn.execute('SELECT group_id FROM users WHERE id = ?', [evaluateeId]);
    if (evalCheck.length === 0 || evalCheck[0].group_id !== groupId) {
      throw new Error("Target peer is not in your group.");
    }

    const perfItems = [1,2,3,4,5,6,7,8];
    const finItems = [9,10,11,12];

    let perfSum = 0, perfCount = 0;
    let finSum = 0, finCount = 0;

    for (let i = 1; i <= 12; i++) {
      const val = criteria[i];
      if (val !== 'N/O') {
        const num = parseInt(val, 10);
        if (perfItems.includes(i)) { perfSum += num; perfCount++; }
        if (finItems.includes(i)) { finSum += num; finCount++; }
      }
    }

    const perfAvg = perfCount > 0 ? (perfSum / perfCount) : 0;
    const finAvg = finCount > 0 ? (finSum / finCount) : 0;
    
    let weightedScore = 0;
    if (perfCount > 0 && finCount > 0) {
      weightedScore = ((perfAvg / 5) * 80) + ((finAvg / 5) * 20);
    } else if (perfCount > 0 && finCount === 0) {
      weightedScore = (perfAvg / 5) * 100;
    }

    let interpretation = "Minimal Contributor";
    if (weightedScore >= 90) interpretation = "Outstanding Contributor";
    else if (weightedScore >= 70) interpretation = "Strong Contributor";
    else if (weightedScore >= 50) interpretation = "Satisfactory Contributor";
    else if (weightedScore >= 30) interpretation = "Limited Contributor";

    const agreedAmt = parseFloat(financial.agreedAmount || 0);
    const actualAmt = parseFloat(financial.actualContributed || 0);
    const unpaidBalance = Math.max(0, agreedAmt - actualAmt);

    await conn.execute(
      `INSERT INTO peer_evaluations 
       (group_id, evaluator_id, evaluatee_id, course_subject, project_title, perf_avg, fin_avg, overall_weighted_score, score_interpretation, fin_agreed_responsibility, fin_agreed_amount, fin_actual_contributed, fin_unpaid_balance, fin_was_agreed, fin_limitations_communicated, comments_contributions, comments_failures, comments_additional)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE 
         perf_avg = VALUES(perf_avg), fin_avg = VALUES(fin_avg), overall_weighted_score = VALUES(overall_weighted_score), score_interpretation = VALUES(score_interpretation)`,
      [groupId, evaluatorId, evaluateeId, group.course_subject, group.project_title, perfAvg, finAvg, weightedScore, interpretation, financial.responsibility || '', agreedAmt, actualAmt, unpaidBalance, financial.wasAgreed || 'N/A', financial.limitationsCommunicated || 'N/A', comments.contributions || '', comments.failures || '', comments.additional || '']
    );

    await conn.commit();
    res.json({ success: true, overallWeightedScore: weightedScore, interpretation });
  } catch (err) {
    await conn.rollback();
    res.status(400).json({ error: err.message });
  } finally {
    conn.release();
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT}`);
});
