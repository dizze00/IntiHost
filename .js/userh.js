import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const router = express.Router();
const app = express();

// Middleware for userh
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type']
}));
app.use(express.json());

// In-memory user storage (replace with database in production)
const users = new Map();

// Mount routes on the app
app.use('/', router);

// User routes
router.post('/register', (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (users.has(username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        users.set(username, {
            password, // Note: In production, hash the password
            servers: []
        });

        res.json({ success: true });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// User login
router.post('/login', (req, res) => {
    try {
        const { username, password } = req.body;
        const user = users.get(username);

        if (!user || user.password !== password) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: 'Failed to log in' });
    }
});

// Get user's servers
router.get('/:username/servers', (req, res) => {
    try {
        const user = users.get(req.params.username);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user.servers);
    } catch (error) {
        console.error('Error fetching user servers:', error);
        res.status(500).json({ error: 'Failed to fetch servers' });
    }
});

// Add server access for user
router.post('/:username/servers', (req, res) => {
    try {
        const { servername } = req.body;
        const user = users.get(req.params.username);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (!user.servers.includes(servername)) {
            user.servers.push(servername);
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error adding server access:', error);
        res.status(500).json({ error: 'Failed to add server access' });
    }
});

// Start server with dynamic port
const port = process.argv[2] || 3002;
app.listen(port, () => {
    console.log(`🚀 User Handler running on http://localhost:${port}`);
});

export { router };

// User Handler implementation
export class UserHandler {
    constructor() {
        this.users = new Map();
    }

    // Convert methods to arrow functions to preserve 'this' context
    login = async (req, res) => {
        try {
            const { username, password } = req.body;
            // Add login logic here
            res.json({ success: true, message: 'Login successful' });
        } catch (error) {
            res.status(500).json({ success: false, message: error.message });
        }
    }

    register = async (req, res) => {
        try {
            const { username, email, password } = req.body;
            // Add registration logic here
            res.json({ success: true, message: 'Registration successful' });
        } catch (error) {
            res.status(500).json({ success: false, message: error.message });
        }
    }

    getProfile = async (req, res) => {
        try {
            // Add profile retrieval logic here
            res.json({ success: true, data: {} });
        } catch (error) {
            res.status(500).json({ success: false, message: error.message });
        }
    }

    updateProfile = async (req, res) => {
        try {
            const { username, email } = req.body;
            // Add profile update logic here
            res.json({ success: true, message: 'Profile updated' });
        } catch (error) {
            res.status(500).json({ success: false, message: error.message });
        }
    }

    logout = async (req, res) => {
        try {
            // Add logout logic here
            res.json({ success: true, message: 'Logout successful' });
        } catch (error) {
            res.status(500).json({ success: false, message: error.message });
        }
    }
} 