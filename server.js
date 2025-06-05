// server.js
const express = require("express");
const app = express();
const cors = require("cors");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const upload = multer({ dest: "uploads/" });

// PostgreSQL connection config
const db = new Pool({
    user: process.env.PGUSER || "postgres",
    host: process.env.PGHOST || "localhost",
    database: process.env.PGDATABASE || "ideasdb",
    password: process.env.PGPASSWORD || "postgres",
    port: process.env.PGPORT ? parseInt(process.env.PGPORT) : 5432,
});

// SECRET for JWT – in production, set via ENV
const JWT_SECRET = process.env.JWT_SECRET || "please_change_me";

function handleError(res, err) {
    console.error(err);
    res.status(500).json({ message: "Server error." });
}

// ——— Middleware ——————————————————————————
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

app.use((req, res, next) => {
    console.log(
        `[${new Date().toISOString()}] ${req.method} ${req.url}`,
        req.body
    );
    next();
});

// quick health check
app.get("/api/ping", async (req, res) => {
    const { rows } = await db.query("SELECT NOW()");
    res.json({ pong: true, dbTime: rows[0].now });
});

// ——— Initialize (fresh) schema ———————————————————
// (async () => {
//   try {
//     await db.query('DROP TABLE IF EXISTS ideas')
//     await db.query('DROP TABLE IF EXISTS users')
// await db.query(`
//   CREATE TABLE users (
//     id SERIAL PRIMARY KEY,
//     username TEXT UNIQUE NOT NULL,
//     email TEXT UNIQUE NOT NULL,
//     password TEXT NOT NULL
//   )
// `)
//     await db.query(`
//       CREATE TABLE ideas (
//         id SERIAL PRIMARY KEY,
//         title TEXT NOT NULL,
//         description TEXT,
//         area TEXT,
//         status TEXT DEFAULT 'New',
//         userId INTEGER NOT NULL REFERENCES users(id),
//         createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
//       )
//     `)
//   } catch (err) {
//     console.error('DB init error ▶', err)
//   }
// })()

// ——— Auth helper ————————————————————————————
async function authenticateToken(req, res, next) {
    const auth = req.headers.authorization;
    if (!auth?.startsWith("Bearer ")) {
        return res.status(401).json({ message: "Missing or invalid token." });
    }
    const token = auth.split(" ")[1];
    try {
        const payload = jwt.verify(token, JWT_SECRET);
        const { rows } = await db.query(
            `SELECT id, username, email FROM users WHERE id = $1`,
            [payload.id]
        );
        const user = rows[0];
        if (!user) throw new Error("No such user");
        req.user = user;
        next();
    } catch (err) {
        return res.status(401).json({ message: "Invalid or expired token." });
    }
}

// ——— Routes: Registration, Login, Me —————————————————

// Register
app.post("/api/register", async (req, res) => {
    console.log("Register body →", req.body);
    try {
        const { username, email, password, name } = req.body;
        if (!username || !email || !password || !name) {
            return res.status(400).json({ message: "All fields required." });
        }
        // check dupes
        const { rows: existsRows } = await db.query(
            `SELECT id FROM users WHERE username = $1 OR email = $2`,
            [username, email]
        );
        if (existsRows.length > 0) {
            return res
                .status(400)
                .json({ message: "Username or email taken." });
        }
        // hash & insert
        const hash = await bcrypt.hash(password, 10);
        await db.query(
            `INSERT INTO users (username, email, password, name) VALUES ($1, $2, $3, $4)`,
            [username, email, hash, name]
        );
        res.status(201).json({ success: true });
    } catch (err) {
        handleError(res, err);
    }
});

// Login
app.post("/api/login", async (req, res) => {
    console.log("Login body →", req.body);
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res
                .status(400)
                .json({ message: "Email & password required." });
        }
        const { rows } = await db.query(
            `SELECT id, password FROM users WHERE email = $1`,
            [email]
        );
        const user = rows[0];
        if (!user)
            return res.status(400).json({ message: "Invalid credentials." });

        const ok = await bcrypt.compare(password, user.password);
        if (!ok)
            return res.status(400).json({ message: "Invalid credentials." });

        const token = jwt.sign({ id: user.id }, JWT_SECRET, {
            expiresIn: "1h",
        });
        res.json({ token });
    } catch (err) {
        handleError(res, err);
    }
});

// Get current user
app.get("/api/me", authenticateToken, (req, res) => {
    res.json(req.user);
});

// List all ideas
app.get("/api/ideas", authenticateToken, async (req, res) => {
    try {
        const { rows: ideas } = await db.query(`
      SELECT i.id, i.title, i.description, i.short_description, i.area, i.status, i.created_at,
             u.id AS user_id, u.username
        FROM ideas i
        JOIN users u ON i.user_id = u.id
        ORDER BY i.created_at DESC
    `);
        res.json(ideas);
    } catch (err) {
        handleError(res, err);
    }
});

// List my ideas
app.get("/api/my-ideas", authenticateToken, async (req, res) => {
    try {
        const { rows: ideas } = await db.query(
            `SELECT id, title, description, short_description, area, status, created_at FROM ideas WHERE user_id = $1 ORDER BY created_at DESC`,
            [req.user.id]
        );
        res.json(ideas);
    } catch (err) {
        handleError(res, err);
    }
});

// Get one idea
app.get("/api/ideas/:id", authenticateToken, async (req, res) => {
    try {
        const { rows } = await db.query(
            `
      SELECT i.id, i.title, i.description, i.short_description, i.area, i.status, i.created_at,
             u.id AS user_id, u.name, u.username
        FROM ideas i
        INNER JOIN users u ON i.user_id = u.id
        WHERE i.id = $1
    `,
            [req.params.id]
        );
        const idea = rows[0];
        if (!idea) {
            return res.status(404).json({ message: "Idea not found." });
        }
        res.json(idea);
    } catch (err) {
        handleError(res, err);
    }
});

// Create idea
app.post(
    "/api/ideas",
    authenticateToken,
    upload.single("file"),
    async (req, res) => {
        const { title, area, description, status, short_description } =
            req.body;
        if (!title) return res.status(400).json({ message: "Title required." });

        await db.query(
            `INSERT INTO ideas (title, description, short_description, area, status, user_id, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [
                title,
                description,
                short_description,
                area,
                status,
                req.user.id,
                new Date(),
            ]
        );
        res.status(201).json({ success: true });
    }
);

// Update idea
app.patch("/api/ideas/:id", authenticateToken, async (req, res) => {
    try {
        const {
            short_description = "",
            description = "",
            status = "",
        } = req.body;
        const fields = [];
        const values = [];
        let idx = 1;
        if (short_description !== undefined) {
            fields.push(`short_description = $${idx++}`);
            values.push(short_description);
        }
        if (description !== undefined) {
            fields.push(`description = $${idx++}`);
            values.push(description);
        }
        if (status !== undefined) {
            fields.push(`status = $${idx++}`);
            values.push(status);
        }
        if (fields.length === 0) {
            return res.status(400).json({ message: "No fields to update." });
        }
        values.push(req.params.id);
        const query = `UPDATE ideas SET ${fields.join(
            ", "
        )} WHERE id = $${idx} RETURNING *`;
        console.log("Update query →", query, values);
        const { rows } = await db.query(query, values);
        res.json(rows[0]);
    } catch (err) {
        handleError(res, err);
    }
});

// Delete idea
app.delete("/api/ideas/:id", authenticateToken, async (req, res) => {
    try {
        const { rows: existingRows } = await db.query(
            "SELECT user_id FROM ideas WHERE id = $1",
            [req.params.id]
        );
        const existing = existingRows[0];
        if (!existing || existing.user_id !== req.user.id) {
            return res.status(403).json({ message: "Not your idea." });
        }
        await db.query("DELETE FROM ideas WHERE id = $1", [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        handleError(res, err);
    }
});

// Post Comment
app.post("/api/ideas/:id/comments", authenticateToken, async (req, res) => {
    try {
        const { comment, parentId } = req.body;
        if (!comment)
            return res.status(400).json({ message: "Comment required." });

        const { rows } = await db.query(
            `INSERT INTO comments (idea_id, user_id, username, comment, created_at, parent_id ) 
            VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
            [
                req.params.id,
                req.user.id,
                req.user.username,
                comment,
                new Date(),
                parentId,
            ]
        );
        res.status(201).json(rows[0]);
    } catch (err) {
        handleError(res, err);
    }
});

// Get Comments
app.get("/api/ideas/:id/comments", authenticateToken, async (req, res) => {
    try {
        const { rows: comments } = await db.query(
            `SELECT * FROM comments WHERE idea_id = $1 
                ORDER BY created_at DESC`,
            [req.params.id]
        );
        return res.json(comments);
    } catch (err) {
        handleError(res, err);
    }
});

app.delete("/api/comments/:id", authenticateToken, async (req, res) => {
    try {
        const { rows } = await db.query(
            "SELECT * FROM comments WHERE id = $1",
            [req.params.id]
        );
        const comment = rows[0];
        if (!comment) {
            return res.status(404).json({ message: "Comment not found." });
        }
        if (comment.user_id !== req.user.id) {
            return res.status(403).json({ message: "Not your comment." });
        }
        if (comment.parent_id) {
            await db.query("DELETE FROM comments WHERE id = $1", [
                req.params.id,
            ]);
        } else {
            await db.query("DELETE FROM comments WHERE parent_id = $1", [
                req.params.id,
            ]);
            await db.query("DELETE FROM comments WHERE id = $1", [
                req.params.id,
            ]);
        }
        res.json({ success: true });
    } catch (err) {
        handleError(res, err);
    }
});

app.post("/api/feedback", async (req, res) => {
    try {
        const { email, feedback } = req.body;
        if (!feedback) {
            return res
                .status(400)
                .json({ message: "Email & feedback required." });
        }
        const fields = [],
            values = [],
            idx = [];
        fields.push(`feedback`);
        values.push(feedback);
        idx.push(1);
        if (email !== undefined) {
            fields.push(`email`);
            values.push(email);
            idx.push(idx.length + 1);
        }
        const query = `INSERT INTO feedback (${fields.join(
            ", "
        )}) VALUES ($${idx.join(", $")}) RETURNING *`;

        await db.query(query, values);
        res.status(201).json({ success: true, message: "Feedback submitted." });
    } catch (err) {
        handleError(res, err);
    }
});

// ---- Create Tables ---

api.get("/api/create_table_users", async (req, res) => {
    try {
        await db.query("DROP TABLE IF EXISTS users");
        await db.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                name TEXT NOT NULL
            )
        `);
        res.json({ message: "Users table created." });
    } catch (err) {
        console.error("Error creating users table:", err);
        res.status(500).json({ message: "Error creating users table." });
    }
});

api.get("/api/create_table_ideas", async (req, res) => {
    try {
        await db.query("DROP TABLE IF EXISTS ideas");
        await db.query(`
            CREATE TABLE IF NOT EXISTS ideas (
                id SERIAL PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT,
                short_description TEXT,
                area TEXT,
                status TEXT DEFAULT 'New',
                user_id INTEGER NOT NULL REFERENCES users(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        res.json({ message: "Users table created." });
    } catch (err) {
        console.error("Error creating users table:", err);
        res.status(500).json({ message: "Error creating users table." });
    }
});

api.get("/api/create_table_comments", async (req, res) => {
    try {
        await db.query("DROP TABLE IF EXISTS comments");
        await db.query(`
            CREATE TABLE IF NOT EXISTS comments (
                id SERIAL PRIMARY KEY,
                idea_id INTEGER NOT NULL REFERENCES ideas(id),
                user_id INTEGER NOT NULL REFERENCES users(id),
                username TEXT NOT NULL,
                comment TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                parent_id INTEGER REFERENCES comments(id)
            )
        `);
        res.json({ message: "Comments table created." });
    } catch (err) {
        console.error("Error creating comments table:", err);
        res.status(500).json({ message: "Error creating comments table." });
    }
});

api.get("/api/create_table_feedback", async (req, res) => {
    try {
        await db.query("DROP TABLE IF EXISTS feedback");
        await db.query(`
            CREATE TABLE IF NOT EXISTS feedback (
                id SERIAL PRIMARY KEY,
                email TEXT,
                feedback TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        res.json({ message: "Feedback table created." });
    } catch (err) {
        console.error("Error creating feedback table:", err);
        res.status(500).json({ message: "Error creating feedback table." });
    }
});

// ——— Start server —
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Server listening on http://localhost:${PORT}`);
});

app.use((req, res) => {
    res.status(404).json({ message: "Route not found" });
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: "Something went wrong!" });
});
