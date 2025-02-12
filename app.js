import express from 'express';
import Dockerode from 'dockerode';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import cors from 'cors';
import session from 'express-session';
import fs from 'fs/promises';
import Database from 'better-sqlite3';
import multer from 'multer';
import path from 'path';
import { exec } from 'child_process';

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Initialize Express and Docker
const app = express();
const docker = new Dockerode();
const db = new Database('users.db');

// Initialize database
const initDb = db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        profile_image TEXT,
        isAdmin BOOLEAN DEFAULT 0
    )
`);
initDb.run();

// Update or add IntiHost123 as admin
const addAdminUser = db.prepare(`
    INSERT OR REPLACE INTO users (username, password, email, isAdmin)
    VALUES (?, ?, ?, 1)
`);

try {
    addAdminUser.run('IntiHost123', 'intipintypoo', 'intihost@example.com');
    console.log('Admin user IntiHost123 added successfully');
} catch (error) {
    console.error('Error adding admin user:', error);
}

// Add session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // set to true if using https
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: 'uploads/profile-images/',
    filename: function(req, file, cb) {
        cb(null, req.session.username + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// Updated CORS configuration
app.use(cors({
    origin: 'http://127.0.0.1:5500',  // or http://localhost:5500
    credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Load users from file
let users = [];
const USERS_FILE = 'users.json';

// Load users function
async function loadUsers() {
    try {
        const data = await fs.readFile(USERS_FILE, 'utf8');
        users = JSON.parse(data);
        console.log('Loaded users:', users); // Debug log
    } catch (error) {
        console.log('No existing users file, starting with empty user list');
        users = [];
    }
}

// Load users on startup
await loadUsers();

// Updated Authentication middleware
const requireAuth = (req, res, next) => {
    if (!req.session.authenticated) {
        return res.redirect('/login.html');
    }
    next();
};

// New Admin middleware
const requireAdmin = (req, res, next) => {
    if (!req.session.authenticated) {
        return res.redirect('/login.html');
    }
    if (!req.session.isAdmin) {
        return res.redirect('/dashboard.html');
    }
    next();
};

// Signup endpoint
app.post('/signup', async (req, res) => {
    console.log('Received signup request:', req.body);
    
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
        return res.status(400).json({
            success: false,
            message: 'All fields are required'
        });
    }
    
    if (users.some(user => user.username === username)) {
        return res.status(400).json({
            success: false,
            message: 'Username already exists'
        });
    }
    
    if (users.some(user => user.email === email)) {
        return res.status(400).json({
            success: false,
            message: 'Email already exists'
        });
    }
    
    const newUser = {
        username,
        email,
        password,
        isAdmin: false
    };
    
    users.push(newUser);
    
    try {
        await fs.writeFile(USERS_FILE, JSON.stringify(users, null, 2));
        console.log('Updated users list:', users); // Debug log
        res.json({ success: true, message: 'Account created successfully' });
    } catch (error) {
        console.error('Error saving user:', error);
        res.status(500).json({
            success: false,
            message: 'Error creating account'
        });
    }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        console.log('Login attempt:', { username, password });

        // Check for user in database
        const stmt = db.prepare('SELECT * FROM users WHERE username = ?');
        const user = stmt.get(username);
        
        // Debug log to check user data
        console.log('Found user:', { ...user, isAdmin: Boolean(user?.isAdmin) });

        if (user && user.password === password) {
            req.session.username = user.username;
            req.session.isAdmin = Boolean(user.isAdmin);  // Ensure boolean conversion
            res.json({ 
                success: true, 
                isAdmin: Boolean(user.isAdmin),  // Ensure boolean conversion
                message: 'Login successful',
                debug: { isAdmin: Boolean(user.isAdmin) }  // Debug info
            });
        } else {
            console.log('Login failed - Invalid credentials');
            res.status(401).json({ 
                success: false, 
                message: 'Invalid username or password' 
            });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ 
            success: false, 
            message: 'Error during login' 
        });
    }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ message: 'Error during logout' });
        }
        res.json({ success: true, message: 'Logged out successfully' });
    });
});

// Protected admin routes using requireAdmin middleware
app.get('/a_dashboard.html', requireAdmin, (req, res) => {
    res.sendFile(join(__dirname, 'public', 'a_dashboard.html'));
});

app.get('/a_servers.html', requireAdmin, (req, res) => {
    res.sendFile(join(__dirname, 'public', 'a_servers.html'));
});

app.get('/servform.html', requireAdmin, (req, res) => {
    res.sendFile(join(__dirname, 'public', 'servform.html'));
});

// Protected user routes using requireAuth middleware
app.get('/dashboard.html', requireAuth, (req, res) => {
    res.sendFile(join(__dirname, 'public', 'dashboard.html'));
});

// Get user profile data
app.get('/api/user/profile', requireAuth, async (req, res) => {
    try {
        const stmt = db.prepare('SELECT username, email, profile_image FROM users WHERE username = ?');
        const user = stmt.get(req.session.username);
        
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        
        res.json({
            username: user.username,
            email: user.email,
            profileImage: user.profile_image || null
        });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ message: 'Error fetching profile data' });
    }
});

// User profile update endpoint
app.post('/api/user/update', requireAuth, async (req, res) => {
    try {
        const { username, email, currentPassword, newPassword } = req.body;
        
        // Verify current password
        const stmt = db.prepare('SELECT password FROM users WHERE username = ?');
        const user = stmt.get(req.session.username);
        
        if (!user || user.password !== currentPassword) {
            return res.status(401).json({ message: 'Current password is incorrect' });
        }
        
        // Update user information
        const updateStmt = db.prepare(`
            UPDATE users 
            SET username = ?, 
                email = ?, 
                password = ? 
            WHERE username = ?
        `);
        
        updateStmt.run(
            username || req.session.username,
            email,
            newPassword || currentPassword,
            req.session.username
        );
        
        // Update session if username changed
        if (username) {
            req.session.username = username;
        }
        
        res.json({ 
            success: true, 
            message: 'Profile updated successfully' 
        });
        
    } catch (error) {
        console.error('Error updating profile:', error);
        res.status(500).json({ 
            success: false,
            message: 'Error updating profile' 
        });
    }
});

// Handle profile image upload
app.post('/api/user/profile-image', requireAuth, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        const imagePath = '/uploads/profile-images/' + req.file.filename;
        
        // Update the user's profile_image in database
        const stmt = db.prepare('UPDATE users SET profile_image = ? WHERE username = ?');
        stmt.run(imagePath, req.session.username);
        
        res.json({ 
            success: true, 
            message: 'Profile image updated',
            imagePath: imagePath 
        });
    } catch (error) {
        console.error('Error uploading image:', error);
        res.status(500).json({ message: 'Error uploading image' });
    }
});

// Serve static files from public directory
app.get('/', (req, res) => {
    res.sendFile(join(__dirname, 'public', 'index.html'));
});

// Docker containers endpoint
app.get('/api/docker/containers', (req, res) => {
    exec('docker ps -a --format "{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"', (error, stdout, stderr) => {
        if (error) {
            console.error('Error fetching Docker containers:', error);
            return res.status(500).json({ message: 'Failed to fetch Docker containers' });
        }

        try {
            // Handle empty response
            if (!stdout.trim()) {
                return res.json([]);
            }

            // Parse the Docker output into objects
            const containers = stdout.trim().split('\n').map(line => {
                const [id, name, status, ports] = line.split('\t');
                return {
                    id: id || '',
                    name: name || '',
                    status: status || '',
                    ports: ports || ''
                };
            });

            console.log('Found containers:', containers); // Debug log
            res.json(containers);
        } catch (parseError) {
            console.error('Error parsing Docker output:', parseError);
            res.status(500).json({ message: 'Failed to parse Docker output' });
        }
    });
});

// Create server endpoint
app.post('/create-server', async (req, res) => {
    try {
        const { serverName, serverType, maxPlayers, serverPort } = req.body;
        
        // Create container configuration
        const containerConfig = {
            Image: 'itzg/minecraft-server',
            name: serverName,
            Env: [
                'EULA=TRUE',
                `TYPE=${serverType}`,
                `MAX_PLAYERS=${maxPlayers}`,
                'MEMORY=2G'
            ],
            ExposedPorts: {
                '25565/tcp': {}
            },
            HostConfig: {
                PortBindings: {
                    '25565/tcp': [{ HostPort: serverPort.toString() }]
                }
            }
        };

        // Create and start the container
        const container = await docker.createContainer(containerConfig);
        await container.start();

        res.json({ success: true, message: 'Server created successfully' });
    } catch (error) {
        console.error('Error creating server:', error);
        res.status(500).json({ error: 'Failed to create server' });
    }
});

// Serve uploaded files statically
app.use('/uploads', express.static('uploads'));

// Add a session check endpoint
app.get('/api/check-session', (req, res) => {
    if (req.session.username) {
        res.json({
            loggedIn: true,
            username: req.session.username,
            isAdmin: req.session.isAdmin || false
        });
    } else {
        res.json({
            loggedIn: false
        });
    }
});

// Add a debug endpoint to check users in database
app.get('/api/debug/users', async (req, res) => {
    try {
        const stmt = db.prepare('SELECT username, password FROM users');
        const users = stmt.all();
        console.log('All users:', users);
        res.json({ users });
    } catch (error) {
        console.error('Debug error:', error);
        res.status(500).json({ error: 'Error fetching users' });
    }
});

// Also add a debug endpoint to check user status
app.get('/api/debug/user-status', (req, res) => {
    if (req.session.username) {
        res.json({
            username: req.session.username,
            isAdmin: req.session.isAdmin,
            sessionData: req.session
        });
    } else {
        res.json({ loggedIn: false });
    }
});

// Store servers in memory (or connect to your database if you have one)
let servers = [];

// Add these new routes for server management
app.get('/api/servers', (req, res) => {
    res.json(servers);
});

app.post('/api/servers', async (req, res) => {
    console.log('Received request:', req.body); // Add logging
    
    try {
        const { name, type, port } = req.body;
        
        // Validate required fields
        if (!name || !type || !port) {
            return res.status(400).json({
                message: 'Server name, type, and port are required'
            });
        }

        // Create new server object
        const newServer = {
            id: Date.now().toString(),
            name,
            type,
            port: parseInt(port),
            status: 'initializing',
            created: new Date().toISOString()
        };

        // If it's a Minecraft server, run the Docker command
        if (type === 'minecraft') {
            const dockerCommand = `docker run -d --name ${name} -p ${port}:25565 -v /var/lib/docker/volumes/${name}/data -e EULA=TRUE itzg/minecraft-server`;

            try {
                const { stdout, stderr } = await new Promise((resolve, reject) => {
                    exec(dockerCommand, (error, stdout, stderr) => {
                        if (error) reject(error);
                        else resolve({ stdout, stderr });
                    });
                });

                newServer.containerId = stdout.trim();
                newServer.status = 'running';
                console.log('Docker container created:', newServer.containerId);
            } catch (error) {
                console.error('Docker error:', error);
                return res.status(500).json({
                    message: 'Failed to create Minecraft server: ' + error.message
                });
            }
        }

        // Add to servers array
        servers.push(newServer);
        console.log('Server created:', newServer);

        // Return success response
        return res.status(201).json(newServer);

    } catch (error) {
        console.error('Server creation error:', error);
        return res.status(500).json({
            message: 'Internal server error: ' + error.message
        });
    }
});

app.get('/api/servers/stats', (req, res) => {
    const activeServers = servers.filter(s => s.status === 'running').length;
    res.json({
        activeServers,
        totalServers: servers.length
    });
});

// Add route to stop server
app.post('/api/servers/:id/stop', (req, res) => {
    try {
        const server = servers.find(s => s.id === req.params.id);
        if (!server) {
            return res.status(404).json({ message: 'Server not found' });
        }

        if (server.type === 'minecraft' && server.containerId) {
            exec(`docker stop ${server.name}`, (error) => {
                if (error) {
                    console.error('Error stopping Docker container:', error);
                    return res.status(500).json({
                        message: 'Failed to stop Minecraft server'
                    });
                }
                server.status = 'stopped';
                res.json({ message: 'Server stopped successfully' });
            });
        } else {
            server.status = 'stopped';
            res.json({ message: 'Server stopped successfully' });
        }
    } catch (error) {
        console.error('Error stopping server:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Server start endpoint
app.post('/api/servers/:name/start', (req, res) => {
    const { name } = req.params;
    
    exec(`docker start ${name}`, (error, stdout, stderr) => {
        if (error) {
            console.error('Error starting server:', error);
            return res.status(500).json({ error: 'Failed to start server' });
        }
        res.json({ message: 'Server started successfully' });
    });
});

// Server stop endpoint
app.post('/api/servers/:name/stop', (req, res) => {
    const { name } = req.params;
    console.log('Received stop request for server:', name); // Debug log
    
    exec(`docker stop ${name}`, (error, stdout, stderr) => {
        if (error) {
            console.error('Error stopping server:', error);
            console.error('stderr:', stderr); // Debug log
            return res.status(500).json({ error: 'Failed to stop server', details: error.message });
        }
        console.log('Server stopped successfully:', stdout); // Debug log
        res.json({ message: 'Server stopped successfully' });
    });
});

// Serve index.html for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'servform.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        message: 'Something broke!',
        error: err.message
    });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Server is ready to accept requests');
});

// Add basic error handling
process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (err) => {
    console.error('Unhandled Rejection:', err);
});

// Close database on exit
process.on('exit', () => db.close());
process.on('SIGHUP', () => process.exit(128 + 1));
process.on('SIGINT', () => process.exit(128 + 2));
process.on('SIGTERM', () => process.exit(128 + 15));

// Add CORS middleware
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// Add these new endpoints for bulk actions
app.post('/api/docker/start-all', (req, res) => {
    exec('docker start $(docker ps -a -q)', (error, stdout, stderr) => {
        if (error) {
            console.error('Error starting all containers:', error);
            return res.status(500).json({ message: 'Failed to start containers' });
        }
        res.json({ message: 'All containers started' });
    });
});

app.post('/api/docker/stop-all', (req, res) => {
    exec('docker stop $(docker ps -q)', (error, stdout, stderr) => {
        if (error) {
            console.error('Error stopping all containers:', error);
            return res.status(500).json({ message: 'Failed to stop containers' });
        }
        res.json({ message: 'All containers stopped' });
    });
});

app.post('/api/docker/restart-all', (req, res) => {
    exec('docker restart $(docker ps -a -q)', (error, stdout, stderr) => {
        if (error) {
            console.error('Error restarting all containers:', error);
            return res.status(500).json({ message: 'Failed to restart containers' });
        }
        res.json({ message: 'All containers restarted' });
    });
});

// Server console endpoint
app.get('/api/servers/:name/console', (req, res) => {
    const { name } = req.params;
    exec(`docker logs ${name}`, (error, stdout, stderr) => {
        if (error) {
            console.error('Error fetching console output:', error);
            return res.status(500).send('Failed to fetch console output');
        }
        res.send(stdout || stderr || 'No console output available');
    });
});

// Server info endpoint
app.get('/api/servers/:name/info', (req, res) => {
    const { name } = req.params;
    exec(`docker inspect ${name}`, (error, stdout, stderr) => {
        if (error) {
            console.error('Error fetching server info:', error);
            return res.status(500).json({ error: 'Failed to fetch server info' });
        }
        
        try {
            const data = JSON.parse(stdout)[0];
            const state = data.State;
            const status = state.Running ? 'Running' : 'Stopped';
            const startTime = new Date(state.StartedAt);
            const uptime = state.Running ? formatUptime(Date.now() - startTime) : 'Not running';
            
            res.json({ status, uptime });
        } catch (error) {
            console.error('Error parsing server info:', error);
            res.status(500).json({ error: 'Failed to parse server info' });
        }
    });
});

// Server users endpoints
app.get('/api/servers/:name/users', (req, res) => {
    const { name } = req.params;
    // Implement your user access logic here
    // This is a placeholder that returns an empty array
    res.json([]);
});

app.post('/api/servers/:name/users', (req, res) => {
    const { name } = req.params;
    const { username } = req.body;
    // Implement your user access logic here
    res.json({ message: 'User access added' });
});

app.delete('/api/servers/:name/users/:username', (req, res) => {
    const { name, username } = req.params;
    // Implement your user access logic here
    res.json({ message: 'User access removed' });
});

// Helper function to format uptime
function formatUptime(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
}

// Language settings endpoint
app.post('/api/settings/language', (req, res) => {
    const { language } = req.body;
    
    // Add your language setting logic here
    // For example, save to user preferences in database
    
    res.json({ message: 'Language updated successfully' });
});

// Update Docker action endpoints
app.post('/api/docker/stop/:name', (req, res) => {
    const { name } = req.params;
    console.log('Stopping container:', name); // Debug log
    
    exec(`docker stop ${name}`, (error, stdout, stderr) => {
        if (error) {
            console.error('Error stopping container:', error);
            console.error('stderr:', stderr);
            return res.status(500).json({ error: 'Failed to stop container' });
        }
        console.log('Stop output:', stdout); // Debug log
        res.json({ message: 'Container stopped successfully' });
    });
});

app.post('/api/docker/start/:name', (req, res) => {
    const { name } = req.params;
    console.log('Starting container:', name); // Debug log
    
    exec(`docker start ${name}`, (error, stdout, stderr) => {
        if (error) {
            console.error('Error starting container:', error);
            console.error('stderr:', stderr);
            return res.status(500).json({ error: 'Failed to start container' });
        }
        console.log('Start output:', stdout); // Debug log
        res.json({ message: 'Container started successfully' });
    });
});

app.post('/api/docker/restart/:name', (req, res) => {
    const { name } = req.params;
    console.log('Restarting container:', name); // Debug log
    
    exec(`docker restart ${name}`, (error, stdout, stderr) => {
        if (error) {
            console.error('Error restarting container:', error);
            console.error('stderr:', stderr);
            return res.status(500).json({ error: 'Failed to restart container' });
        }
        console.log('Restart output:', stdout); // Debug log
        res.json({ message: 'Container restarted successfully' });
    });
});

// Update the container info endpoint
app.get('/api/containers/:name/info', async (req, res) => {
    const { name } = req.params;
    console.log('Fetching info for container:', name);
    
    try {
        const inspectCmd = await new Promise((resolve, reject) => {
            exec(`docker inspect ${name}`, (error, stdout, stderr) => {
                if (error) {
                    console.error('Docker inspect error:', error);
                    reject(error);
                    return;
                }
                resolve(stdout);
            });
        });
        
        const containerInfo = JSON.parse(inspectCmd)[0];
        const state = containerInfo.State;
        
        const response = {
            status: state.Running ? 'running' : 'stopped',
            uptime: state.Running ? calculateUptime(state.StartedAt) : 'Not running'
        };
        
        console.log('Sending response:', response);
        res.json(response);
        
    } catch (error) {
        console.error('Error getting container info:', error);
        res.status(500).json({
            status: 'unknown',
            uptime: 'Unknown',
            error: error.message
        });
    }
});

// Helper function to calculate uptime
function calculateUptime(startTime) {
    const started = new Date(startTime);
    const now = new Date();
    const uptimeMs = now - started;
    
    const seconds = Math.floor(uptimeMs / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);
    
    if (days > 0) return `${days}d ${hours % 24}h`;
    if (hours > 0) return `${hours}h ${minutes % 60}m`;
    if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
    return `${seconds}s`;
}

// Update the status endpoint to always return JSON
app.get('/api/status/:name', (req, res) => {
    // Set JSON content type
    res.setHeader('Content-Type', 'application/json');
    
    const { name } = req.params;
    console.log('Getting status for:', name);
    
    exec(`docker inspect ${name}`, (error, stdout, stderr) => {
        if (error) {
            console.error('Docker inspect error:', error);
            return res.status(500).json({
                status: 'unknown',
                uptime: 'Unknown',
                error: error.message
            });
        }
        
        try {
            const data = JSON.parse(stdout)[0];
            const state = data.State;
            const running = state.Running;
            
            const response = {
                status: running ? 'running' : 'stopped',
                uptime: running ? getUptime(state.StartedAt) : 'Not running'
            };
            
            console.log('Sending response:', response);
            res.json(response);
            
        } catch (error) {
            console.error('Error parsing docker inspect:', error);
            res.status(500).json({
                status: 'unknown',
                uptime: 'Unknown',
                error: 'Failed to parse container info'
            });
        }
    });
});

// Keep the getUptime helper function as is

// Update the Docker stats endpoint
const apiRouter = express.Router();

apiRouter.get('/docker/stats', async (req, res) => {
    console.log('Stats endpoint hit at:', new Date().toISOString());  // Timestamp debug log
    
    // Set proper headers
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Cache-Control', 'no-cache');
    
    try {
        // Test response
        const testStats = {
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

        console.log('Sending response:', JSON.stringify(testStats, null, 2)); // Pretty print debug log
        return res.status(200).json(testStats);
        
    } catch (error) {
        console.error('Error in /api/docker/stats:', error);
        return res.status(500).json({
            error: 'Failed to get Docker statistics',
            message: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// Add a test endpoint to verify API routing
apiRouter.get('/test', (req, res) => {
    res.json({ message: 'API is working', timestamp: new Date().toISOString() });
});

// Mount the API router BEFORE static files
app.use('/api', apiRouter);

// Serve static files after API routes
app.use(express.static('public'));

// Catch-all route handler
app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        res.status(404).json({ error: 'API endpoint not found' });
    } else {
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: err.message
    });
});

export default app;
        