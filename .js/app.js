import express from 'express';
import path from 'path';
import cors from 'cors';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { router as serverRoutes } from './serverh.js';
import { UserHandler } from './userh.js';
import { Router } from 'express';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// Adjust path to go up one directory for public folder
const publicPath = path.join(__dirname, '..', 'public');

const app = express();
const userHandler = new UserHandler();

// Create user routes
const userRoutes = Router();

// Define user routes
userRoutes.post('/login', userHandler.login);
userRoutes.post('/register', userHandler.register);
userRoutes.get('/profile', userHandler.getProfile);
userRoutes.post('/update', userHandler.updateProfile);
userRoutes.get('/logout', userHandler.logout);

// Middleware setup
app.use(cors({
    origin: '*', // Be more specific in production
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type']
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(publicPath));

// Debug middleware to log requests
app.use((req, res, next) => {
    console.log(`📥 ${new Date().toISOString()} - ${req.method} ${req.url}`);
    next();
});

// Mount routes
app.use('/api/docker', serverRoutes);
app.use('/api/users', userRoutes);

// Basic routes
app.get('/', (req, res) => {
    res.sendFile(path.join(publicPath, 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(publicPath, 'login.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('❌ Error:', err);
    res.status(500).json({ error: 'Something broke!' });
});

// Start server
const port = process.argv[2] || 3000;  // Changed to 3000
app.listen(port, () => {
    console.log(`🚀 API Server running on http://localhost:${port}`);
});

// Handle server errors
app.on('error', (error) => {
    if (error.code === 'EADDRINUSE') {
        console.error(`Port ${port} is already in use`);
    } else {
        console.error('Server error:', error);
    }
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

export default app;
        