import express from 'express';
import cors from 'cors';
import Dockerode from 'dockerode';

const app = express();
const docker = new Dockerode();

// Enable CORS for all routes
app.use(cors({
    origin: ['http://localhost:5500', 'http://127.0.0.1:5500'],
    methods: ['GET'],
    credentials: true
}));

// JSON middleware
app.use(express.json());

// Docker stats endpoint
app.get('/api/docker/stats', (req, res) => {
    console.log('Stats endpoint hit at:', new Date().toISOString());
    
    // Force JSON content type
    res.setHeader('Content-Type', 'application/json');
    
    const testData = {
        timestamp: new Date().toISOString(),
        activeContainers: 1,
        totalContainers: 2,
        cpuUsage: 5.5,
        memoryUsage: 1024,
        networkIO: 512,
        containers: [
            {
                name: "test-container",
                cpu: 5.5,
                memory: 1024
            }
        ],
        statusCounts: {
            running: 1,
            stopped: 1,
            other: 0
        }
    };

    console.log('Sending response:', testData);
    res.json(testData);
});

// Test endpoint
app.get('/api/test', (req, res) => {
    res.json({ status: 'ok', time: new Date().toISOString() });
});

// Start server on port 3001
const PORT = 3001;
app.listen(PORT, () => {
    console.log(`API Server running on http://localhost:${PORT}`);
    console.log('Available endpoints:');
    console.log(`- http://localhost:${PORT}/api/docker/stats`);
    console.log(`- http://localhost:${PORT}/api/test`);
}); 