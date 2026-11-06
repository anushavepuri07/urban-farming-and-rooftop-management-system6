
const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const session = require("express-session");
require("dotenv").config();

const db = require("./db");

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        secret: process.env.SESSION_SECRET || "urban-farming-local-secret",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: false,
            maxAge: 24 * 60 * 60 * 1000
        }
    })
);

// Serve frontend files
app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ================= REGISTER =================

app.post("/api/register", async (req, res) => {
    try {
        const { name, email, phone, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: "Name, email and password are required"
            });
        }

        if (password.length < 6) {
            return res.status(400).json({
                message: "Password must contain at least 6 characters"
            });
        }

        const [existingUsers] = await db.query(
            "SELECT id FROM users WHERE email = ?",
            [email]
        );

        if (existingUsers.length > 0) {
            return res.status(409).json({
                message: "Email already registered"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const [result] = await db.query(
            "INSERT INTO users (name, email, phone, password_hash) VALUES (?, ?, ?, ?)",
            [name, email, phone || null, hashedPassword]
        );

        req.session.userId = result.insertId;

        res.status(201).json({
            message: "Registration successful",
            user: {
                id: result.insertId,
                name,
                email,
                phone: phone || null
            }
        });

    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({
            message: "Registration failed"
        });
    }
});

// ================= LOGIN =================

app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required"
            });
        }

        const [users] = await db.query(
            "SELECT * FROM users WHERE email = ?",
            [email]
        );

        if (users.length === 0) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const user = users[0];

        const passwordMatch = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatch) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        req.session.userId = user.id;

        res.json({
            message: "Login successful",
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone
            }
        });

    } catch (error) {
        console.error("Login error:", error);
        res.status(500).json({
            message: "Login failed"
        });
    }
});

// ================= CHECK LOGIN =================

app.get("/api/me", async (req, res) => {
    try {
        if (!req.session.userId) {
            return res.status(401).json({
                message: "Not logged in"
            });
        }

        const [users] = await db.query(
            "SELECT id, name, email, phone FROM users WHERE id = ?",
            [req.session.userId]
        );

        if (users.length === 0) {
            return res.status(401).json({
                message: "User not found"
            });
        }

        res.json({ user: users[0] });

    } catch (error) {
        console.error("Session check error:", error);
        res.status(500).json({
            message: "Unable to check login"
        });
    }
});

// ================= LOGOUT =================

app.post("/api/logout", (req, res) => {
    req.session.destroy((error) => {
        if (error) {
            return res.status(500).json({
                message: "Logout failed"
            });
        }

        res.clearCookie("connect.sid", {
            httpOnly: true,
            sameSite: "lax",
            secure: false
        });

        res.json({
            message: "Logout successful"
        });
    });
});

// ================= LOGIN PROTECTION =================

function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({
            message: "Please login first"
        });
    }

    next();
}

// All remaining API routes require login
app.use("/api", requireLogin);

// ================= PLANT MANAGEMENT =================

app.get("/api/plants", async (req, res) => {
    try {
        const [rows] = await db.query("SELECT * FROM plants ORDER BY id DESC");
        res.json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to load plants" });
    }
});

app.post("/api/plants", async (req, res) => {
    try {
        const { name, type, water_requirement, sunlight_requirement } = req.body;

        const [result] = await db.query(
            "INSERT INTO plants (name, type, water_requirement, sunlight_requirement) VALUES (?, ?, ?, ?)",
            [name, type, water_requirement || null, sunlight_requirement || null]
        );

        res.status(201).json({
            message: "Plant added successfully",
            id: result.insertId
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to add plant" });
    }
});

app.put("/api/plants/:id", async (req, res) => {
    try {
        const { name, type, water_requirement, sunlight_requirement } = req.body;

        await db.query(
            "UPDATE plants SET name = ?, type = ?, water_requirement = ?, sunlight_requirement = ? WHERE id = ?",
            [name, type, water_requirement || null, sunlight_requirement || null, req.params.id]
        );

        res.json({ message: "Plant updated successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to update plant" });
    }
});

app.delete("/api/plants/:id", async (req, res) => {
    try {
        await db.query("DELETE FROM plants WHERE id = ?", [req.params.id]);
        res.json({ message: "Plant deleted successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to delete plant" });
    }
});

// ================= GARDEN MANAGEMENT =================

app.get("/api/gardens", async (req, res) => {
    try {
        const [rows] = await db.query("SELECT * FROM gardens ORDER BY id DESC");
        res.json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to load gardens" });
    }
});

app.post("/api/gardens", async (req, res) => {
    try {
        const { name, area, location } = req.body;

        const [result] = await db.query(
            "INSERT INTO gardens (name, area, location) VALUES (?, ?, ?)",
            [name, area || null, location || null]
        );

        res.status(201).json({
            message: "Garden added successfully",
            id: result.insertId
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to add garden" });
    }
});

app.put("/api/gardens/:id", async (req, res) => {
    try {
        const { name, area, location } = req.body;

        await db.query(
            "UPDATE gardens SET name = ?, area = ?, location = ? WHERE id = ?",
            [name, area || null, location || null, req.params.id]
        );

        res.json({ message: "Garden updated successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to update garden" });
    }
});

app.delete("/api/gardens/:id", async (req, res) => {
    try {
        await db.query("DELETE FROM gardens WHERE id = ?", [req.params.id]);
        res.json({ message: "Garden deleted successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to delete garden" });
    }
});

// ================= TASK MANAGEMENT =================

app.get("/api/tasks", async (req, res) => {
    try {
        const [rows] = await db.query("SELECT * FROM tasks ORDER BY id DESC");
        res.json(rows);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to load tasks" });
    }
});

app.post("/api/tasks", async (req, res) => {
    try {
        const { title, description, due_date, status } = req.body;

        const [result] = await db.query(
            "INSERT INTO tasks (title, description, due_date, status) VALUES (?, ?, ?, ?)",
            [title, description || null, due_date || null, status || "Pending"]
        );

        res.status(201).json({
            message: "Task added successfully",
            id: result.insertId
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to add task" });
    }
});

app.put("/api/tasks/:id", async (req, res) => {
    try {
        const { title, description, due_date, status } = req.body;

        await db.query(
            "UPDATE tasks SET title = ?, description = ?, due_date = ?, status = ? WHERE id = ?",
            [title, description || null, due_date || null, status, req.params.id]
        );

        res.json({ message: "Task updated successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to update task" });
    }
});

app.delete("/api/tasks/:id", async (req, res) => {
    try {
        await db.query("DELETE FROM tasks WHERE id = ?", [req.params.id]);
        res.json({ message: "Task deleted successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to delete task" });
    }
});

// ================= DASHBOARD =================

app.get("/api/dashboard", async (req, res) => {
    try {
        const [[plants]] = await db.query(
            "SELECT COUNT(*) AS totalPlants FROM plants"
        );

        const [[gardens]] = await db.query(
            "SELECT COUNT(*) AS totalGardens FROM gardens"
        );

        const [[tasks]] = await db.query(
            "SELECT COUNT(*) AS totalTasks FROM tasks"
        );

        const [[completed]] = await db.query(
            "SELECT COUNT(*) AS completedTasks FROM tasks WHERE status = 'Completed'"
        );

        res.json({
            totalPlants: plants.totalPlants,
            totalGardens: gardens.totalGardens,
            totalTasks: tasks.totalTasks,
            completedTasks: completed.completedTasks
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Unable to load dashboard" });
    }
});

// ================= START SERVER =================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
