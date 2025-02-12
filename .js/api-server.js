import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const router = express.Router();
const app = express();
const PORT = 3001;

// Middleware setup
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type']
}));

app.use(express.json());

// API Routes
router.get('/status', (req, res) => {
    res.json({ status: 'API is running' });
});

// Mount router
app.use('/api', router);

// Error handling
app.use((err, req, res, next) => {
    console.error('API Error:', err);
    res.status(500).json({ error: 'API Error occurred' });
});

// Start API server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 API Server running on http://localhost:${PORT}`);
});

export { router }; 