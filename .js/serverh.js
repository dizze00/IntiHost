import express from 'express';
import Docker from 'dockerode';
import net from 'net';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const router = express.Router();
const app = express();
const PORT = process.argv[2] || 3003;

// Middleware for serverh
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type']
}));
app.use(express.json());

// Initialize Docker
const docker = new Docker({
    socketPath: '/var/run/docker.sock'
});

// Test port availability
function testPort(port) {
    return new Promise((resolve) => {
        const tester = net.createServer()
            .once('error', (err) => {
                if (err.code === 'EADDRINUSE') {
                    console.error(`❌ Port ${port} is already in use`);
                    resolve(false);
                }
            })
            .once('listening', () => {
                tester.once('close', () => resolve(true))
                    .close();
            })
            .listen(port);
    });
}

// Start server function
async function startServerH() {
    try {
        // Test Docker connection
        await docker.ping();
        console.log('✅ Docker connection successful');

        // Check port availability
        const portOk = await testPort(PORT);
        if (!portOk) {
            throw new Error(`Port ${PORT} is not available`);
        }

        // Mount routes on the app
        app.use('/', router);

        // Start server
        app.listen(PORT, '0.0.0.0', () => {
            console.log(`🚀 Server Handler running on http://localhost:${PORT}`);
        });

    } catch (error) {
        console.error('❌ Failed to start Server Handler:', error.message);
        process.exit(1);
    }
}

// Start the server
startServerH();

// Add error handling middleware
router.use((req, res, next) => {
    res.on('error', (error) => {
        console.error('Response error:', error);
    });
    next();
});

// Test Docker connection on startup
async function testDockerConnection() {
    try {
        await docker.ping();
        console.log('Successfully connected to Docker daemon');
    } catch (error) {
        console.error('Failed to connect to Docker daemon:', error);
    }
}
testDockerConnection();

// List all containers
router.get('/containers', async (req, res) => {
    try {
        console.log('Fetching containers...');
        const containers = await docker.listContainers({ all: true });
        console.log('Raw containers data:', containers);

        const containerDetails = containers.map(container => {
            const name = container.Names[0].replace('/', '');
            const status = container.State === 'running' ? 
                `Up ${container.Status.replace('Up ', '')}` : 
                `Stopped (${container.Status})`;

            return {
                id: container.Id,
                name: name,
                status: status,
                state: container.State,
                image: container.Image
            };
        });

        console.log('Sending container details:', containerDetails);
        res.json(containerDetails);
    } catch (error) {
        console.error('Error listing containers:', error);
        res.status(500).json({ error: 'Failed to list containers: ' + error.message });
    }
});

// Get container logs
router.get('/logs/:name', async (req, res) => {
    try {
        console.log('Fetching logs for container:', req.params.name);
        const containers = await docker.listContainers({ all: true });
        const container = containers.find(c => c.Names.includes('/' + req.params.name));
        
        if (!container) {
            throw new Error('Container not found');
        }

        const containerInstance = docker.getContainer(container.Id);
        const logs = await containerInstance.logs({
            stdout: true,
            stderr: true,
            tail: 100,
            follow: false
        });

        res.send(logs);
    } catch (error) {
        console.error('Error fetching logs:', error);
        res.status(500).json({ error: 'Failed to fetch logs: ' + error.message });
    }
});

// Start container
router.post('/start/:name', async (req, res) => {
    try {
        console.log('Starting container:', req.params.name);
        const container = docker.getContainer(req.params.name);
        await container.start();
        res.json({ success: true });
    } catch (error) {
        console.error('Error starting container:', error);
        res.status(500).json({ error: 'Failed to start container: ' + error.message });
    }
});

// Stop container
router.post('/stop/:name', async (req, res) => {
    try {
        console.log('Stopping container:', req.params.name);
        const container = docker.getContainer(req.params.name);
        await container.stop();
        res.json({ success: true });
    } catch (error) {
        console.error('Error stopping container:', error);
        res.status(500).json({ error: 'Failed to stop container: ' + error.message });
    }
});

// Restart container
router.post('/restart/:name', async (req, res) => {
    try {
        console.log('Restarting container:', req.params.name);
        const container = docker.getContainer(req.params.name);
        await container.restart();
        res.json({ success: true });
    } catch (error) {
        console.error('Error restarting container:', error);
        res.status(500).json({ error: 'Failed to restart container: ' + error.message });
    }
});

// Execute command in container
router.post('/exec/:name', async (req, res) => {
    try {
        console.log('Executing command in container:', req.params.name);
        const containers = await docker.listContainers({ all: true });
        const container = containers.find(c => c.Names.includes('/' + req.params.name));
        
        if (!container) {
            throw new Error('Container not found');
        }

        const containerInstance = docker.getContainer(container.Id);
        const command = req.body.command;

        const exec = await containerInstance.exec({
            Cmd: ['sh', '-c', command],
            AttachStdout: true,
            AttachStderr: true
        });

        const stream = await exec.start();
        let output = '';
        
        stream.on('data', (chunk) => {
            output += chunk.toString();
        });

        stream.on('end', () => {
            res.json({ output });
        });
    } catch (error) {
        console.error('Error executing command:', error);
        res.status(500).json({ error: 'Failed to execute command: ' + error.message });
    }
});

export { router }; 