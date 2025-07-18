import express from 'express';
import cors from 'cors';
import Dockerode from 'dockerode';
import session from 'express-session';
import { exec } from 'child_process';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const app = express();
const docker = new Dockerode();

// Initialize database
const dbFile = new JSONFile('db.json');
const db = new Low(dbFile, { users: [] });

// Load database
await db.read();
console.log('Loaded users from database:', db.data.users);

// Enable CORS for all routes
app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            'http://127.0.0.1:5500',
            'http://localhost:5500',
            'http://localhost:3000',
            'http://localhost:3001',
            'http://localhost:3002',
            'http://localhost:5004',
            'http://localhost:5005',
            'http://192.168.0.110:5500',
            'http://192.168.0.110:3000',
            'http://192.168.0.110:80',
            'http://192.168.0.110',
            'http://83.191.172.196:5500',
            'http://83.191.172.196:3000',
            'http://83.191.172.196:80',
            'http://83.191.172.196'
        ];
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// JSON middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: true,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
        sameSite: 'lax'
    },
    name: 'intihost_session'
}));

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (!req.session.authenticated) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    next();
};

const requireAdmin = (req, res, next) => {
    console.log('requireAdmin middleware - Session data:', req.session);
    console.log('Authenticated:', req.session.authenticated);
    console.log('Is Admin:', req.session.isAdmin);
    
    if (!req.session.authenticated) {
        console.log('Not authenticated, returning 401');
        return res.status(401).json({ error: 'Not authenticated' });
    }
    if (!req.session.isAdmin) {
        console.log('Not admin, returning 403');
        return res.status(403).json({ error: 'Not authorized' });
    }
    console.log('Admin check passed, proceeding');
    next();
};

// Activity tracking
const activities = [];
const trackActivity = (type, message, data = {}) => {
    const activity = {
        id: Date.now(),
        type,
        message,
        data,
        timestamp: new Date().toISOString()
    };
    activities.unshift(activity);
    if (activities.length > 50) {
        activities.splice(50);
    }
};

const getRecentActivity = () => {
    return activities.slice(0, 10);
};

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        console.log('Login attempt:', { username, password });

        const user = db.data.users.find(u => u.username === username);
        console.log('Found user:', user);

        if (user && user.password === password) {
            req.session.username = user.username;
            req.session.isAdmin = Boolean(user.isAdmin);
            req.session.authenticated = true;
            
            trackActivity('user_login', `User "${user.username}" logged in`, { 
                username: user.username,
                isAdmin: Boolean(user.isAdmin)
            });
            
            res.json({ 
                success: true, 
                isAdmin: Boolean(user.isAdmin),
                message: 'Login successful'
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

// Session check endpoint
app.get('/api/session', (req, res) => {
    console.log('Session check - Session data:', req.session);
    if (req.session.authenticated) {
        res.json({
            authenticated: true,
            username: req.session.username,
            isAdmin: req.session.isAdmin
        });
    } else {
        res.status(401).json({
            authenticated: false,
            message: 'Not authenticated'
        });
    }
});

// Logout endpoint
app.post('/api/logout', (req, res) => {
    const username = req.session.username;
    
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ message: 'Error during logout' });
        }
        
        if (username) {
            trackActivity('user_logout', `User "${username}" logged out`, { username });
        }
        
        res.json({ success: true, message: 'Logged out successfully' });
    });
});

// Docker container routes
app.get('/api/docker/containers', (req, res) => {
    exec('docker ps -a --no-trunc', (error, stdout, stderr) => {
        if (error) return res.status(500).json({ error: 'Failed to fetch containers' });
        try {
            if (!stdout.trim()) return res.json([]);
            
            // Parse the docker ps output manually
            const lines = stdout.trim().split('\n');
            const containers = [];
            
            // Skip the header lines
            let i = 0;
            while (i < lines.length && (lines[i].includes('CONTAINER ID') || lines[i].trim() === '')) {
                i++;
            }
            
            // Process the actual container data
            for (; i < lines.length; i++) {
                const line = lines[i].trim();
                if (!line) continue;
                
                // Use regex to extract the container ID and name
                const idMatch = line.match(/^([a-f0-9]{12})/);
                const nameMatch = line.match(/([a-zA-Z0-9_-]+)$/);
                
                if (idMatch && nameMatch) {
                    const id = idMatch[1];
                    const name = nameMatch[1];
                    
                    // Extract status (everything between the last timestamp and the name)
                    const statusMatch = line.match(/(\d+ \w+ ago)\s+(.+?)\s+([a-zA-Z0-9_-]+)$/);
                    const status = statusMatch ? statusMatch[2].trim() : 'Unknown';
                    
                    containers.push({ id, name, status, ports: '' });
                }
            }

            const dbServers = db.data.servers || [];
            
            // Process containers and get port information for stopped containers
            const processContainers = async () => {
                const enrichedContainers = [];
                
                for (const container of containers) {
                    let finalPorts = container.ports;
                    
                    // If ports are empty or show "None", try to get them from container inspection
                    if (!container.ports || container.ports.trim() === '' || container.ports === 'None') {
                        try {
                            const portInfo = await new Promise((resolve, reject) => {
                                exec(`docker inspect ${container.id} --format "{{json .HostConfig.PortBindings}}"`, (error, stdout) => {
                                    if (error) reject(error);
                                    else resolve(stdout.trim());
                                });
                            });
                            
                            if (portInfo && portInfo !== 'null') {
                                const portBindings = JSON.parse(portInfo);
                                const portEntries = Object.entries(portBindings);
                                if (portEntries.length > 0) {
                                    const [containerPort, hostBindings] = portEntries[0];
                                    const hostPort = hostBindings[0]?.HostPort;
                                    if (hostPort) {
                                        finalPorts = `${hostPort}->${containerPort}`;
                                    }
                                }
                            }
                        } catch (inspectError) {
                            console.log(`Could not get port info for container ${container.name}:`, inspectError.message);
                        }
                    }
                    
                    const dbServer = dbServers.find(server => server.name === container.name);
                    enrichedContainers.push({
                        ...container,
                        ports: finalPorts,
                        createdBy: dbServer ? dbServer.createdBy : 'Unknown',
                        description: dbServer ? dbServer.description : '',
                        version: dbServer ? dbServer.version : 'Unknown',
                        type: dbServer ? dbServer.type : 'Unknown'
                    });
                }
                
                return enrichedContainers;
            };
            
            processContainers().then(enrichedContainers => {
                res.json(enrichedContainers);
            }).catch(error => {
                res.status(500).json({ error: 'Failed to process containers' });
            });
            
        } catch (error) {
            res.status(500).json({ error: 'Failed to parse Docker output' });
        }
    });
});

// Docker container management routes
app.post('/api/docker/remove/:name', (req, res) => {
    const { name } = req.params;
    console.log('Removing container:', name);
    
    exec(`docker rm -f ${name}`, (error, stdout, stderr) => {
        if (error) {
            console.error('Error removing container:', error);
            return res.status(500).json({ error: 'Failed to remove container' });
        }
        res.json({ message: 'Container removed successfully' });
    });
});

app.post('/api/docker/stop/:name', (req, res) => {
    const { name } = req.params;
    exec(`docker stop ${name}`, (error, stdout, stderr) => {
        if (error) return res.status(500).json({ error: 'Failed to stop container' });
        
        trackActivity('server_stopped', `Server "${name}" stopped`, { serverName: name });
        
        res.json({ message: 'Container stopped successfully' });
    });
});

app.post('/api/docker/start/:name', (req, res) => {
    const { name } = req.params;
    exec(`docker start ${name}`, (error, stdout, stderr) => {
        if (error) return res.status(500).json({ error: 'Failed to start container' });
        
        trackActivity('server_started', `Server "${name}" started`, { serverName: name });
        
        res.json({ message: 'Container started successfully' });
    });
});

app.post('/api/docker/restart/:name', (req, res) => {
    const { name } = req.params;
    exec(`docker restart ${name}`, (error, stdout, stderr) => {
        if (error) return res.status(500).json({ error: 'Failed to restart container' });
        
        trackActivity('server_restarted', `Server "${name}" restarted`, { serverName: name });
        
        res.json({ message: 'Container restarted successfully' });
    });
});

// Dashboard stats endpoint
app.get('/api/dashboard/stats', requireAdmin, async (req, res) => {
    try {
        const containers = await new Promise((resolve, reject) => {
            exec('docker ps -a --format "{{.Names}}\t{{.Status}}"', (error, stdout, stderr) => {
                if (error) reject(error);
                else {
                    const containers = stdout.trim().split('\n').filter(line => line.trim());
                    resolve(containers);
                }
            });
        });

        const totalServers = containers.length;
        const activeServers = containers.filter(container => container.includes('Up')).length;
        const totalUsers = db.data.users.length;

        const stats = {
            totalServers,
            activeServers,
            totalUsers,
            systemLoad: `${Math.round((activeServers / totalServers) * 100)}%`,
            recentActivity: getRecentActivity()
        };

        res.json(stats);
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard stats' });
    }
});

// User Management API Endpoints
app.get('/api/users', requireAdmin, async (req, res) => {
    try {
        const users = db.data.users.map(user => ({
            username: user.username,
            email: user.email,
            isAdmin: user.isAdmin || false,
            status: 'active',
            createdAt: user.createdAt || new Date().toISOString()
        }));
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Error fetching users' });
    }
});

app.get('/api/users/:username', requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        const user = db.data.users.find(u => u.username === username);
        
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({
            username: user.username,
            email: user.email,
            isAdmin: user.isAdmin || false,
            status: 'active',
            createdAt: user.createdAt || new Date().toISOString()
        });
    } catch (error) {
        console.error('Error fetching user:', error);
        res.status(500).json({ error: 'Error fetching user' });
    }
});

app.post('/api/users', requireAdmin, async (req, res) => {
    try {
        const { username, email, password, isAdmin } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password are required' });
        }
        if (db.data.users.some(user => user.username === username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        if (db.data.users.some(user => user.email === email)) {
            return res.status(400).json({ error: 'Email already exists' });
        }
        const newUser = {
            username,
            email,
            password,
            isAdmin: isAdmin || false,
            createdAt: new Date().toISOString()
        };
        db.data.users.push(newUser);
        await db.write();
        res.json({ 
            success: true, 
            message: 'User created successfully',
            user: {
                username: newUser.username,
                email: newUser.email,
                isAdmin: newUser.isAdmin,
                status: 'active',
                createdAt: newUser.createdAt
            }
        });
    } catch (error) {
        console.error('Error creating user:', error);
        res.status(500).json({ error: 'Error creating user' });
    }
});

app.put('/api/users/:username', requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        const { email, isAdmin, password } = req.body;
        const userIndex = db.data.users.findIndex(u => u.username === username);
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        const user = db.data.users[userIndex];
        if (email) user.email = email;
        if (typeof isAdmin === 'boolean') user.isAdmin = isAdmin;
        if (password) user.password = password;
        await db.write();
        res.json({ 
            success: true, 
            message: 'User updated successfully',
            user: {
                username: user.username,
                email: user.email,
                isAdmin: user.isAdmin,
                status: 'active',
                createdAt: user.createdAt
            }
        });
    } catch (error) {
        console.error('Error updating user:', error);
        res.status(500).json({ error: 'Error updating user' });
    }
});

app.delete('/api/users/:username', requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        const adminUsers = db.data.users.filter(u => u.isAdmin);
        const userToDelete = db.data.users.find(u => u.username === username);
        if (adminUsers.length === 1 && userToDelete && userToDelete.isAdmin) {
            return res.status(400).json({ error: 'Cannot delete the last admin user' });
        }
        const userIndex = db.data.users.findIndex(u => u.username === username);
        if (userIndex === -1) {
            return res.status(404).json({ error: 'User not found' });
        }
        db.data.users.splice(userIndex, 1);
        await db.write();
        res.json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ error: 'Error deleting user' });
    }
});

// Server requests endpoints
app.post('/api/server-requests', requireAuth, async (req, res) => {
    try {
        console.log('Server request received:', req.body);
        console.log('Session data:', req.session);
        console.log('User authenticated:', req.session.authenticated);
        console.log('Username:', req.session.username);

        const { serverName, serverVersion, serverType, description, additionalUsers } = req.body;
        
        // Validate required fields
        if (!serverName || !serverType) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Create new request
        const newRequest = {
            id: Date.now().toString(),
            serverName,
            serverVersion: serverVersion || 'N/A',
            serverType,
            description: description || '',
            additionalUsers: additionalUsers || [],
            requestedBy: req.session.username,
            status: 'pending',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        console.log('Creating new request:', newRequest);

        // Add to database
        if (!db.data.serverRequests) {
            db.data.serverRequests = [];
        }
        db.data.serverRequests.push(newRequest);
        await db.write();

        console.log('Request saved successfully');
        res.status(201).json(newRequest);
    } catch (error) {
        console.error('Error creating server request:', error);
        res.status(500).json({ error: 'Error creating server request' });
    }
});

app.get('/api/server-requests', requireAdmin, async (req, res) => {
    console.log('Server requests endpoint hit - Session data:', req.session);
    console.log('User authenticated:', req.session.authenticated);
    console.log('User is admin:', req.session.isAdmin);
    
    try {
        const requests = db.data.serverRequests || [];
        console.log('Found requests:', requests);
        res.json(requests);
    } catch (error) {
        console.error('Error fetching server requests:', error);
        res.status(500).json({ error: 'Error fetching server requests' });
    }
});

app.post('/api/server-requests/:id/approve', requireAdmin, async (req, res) => {
    console.log('Approve request endpoint hit - Session data:', req.session);
    console.log('User authenticated:', req.session.authenticated);
    console.log('User is admin:', req.session.isAdmin);
    console.log('Username:', req.session.username);
    
    try {
        const { id } = req.params;
        const requests = db.data.serverRequests || [];
        const requestIndex = requests.findIndex(r => r.id === id);
        
        if (requestIndex === -1) {
            return res.status(404).json({ error: 'Request not found' });
        }

        const request = requests[requestIndex];
        request.status = 'approved';
        request.updatedAt = new Date().toISOString();
        request.approvedBy = req.session.username;

        const newServer = {
            id: Date.now().toString(),
            name: request.serverName,
            version: request.serverVersion,
            type: request.serverType,
            description: request.description,
            createdBy: request.requestedBy,
            users: [request.requestedBy, ...request.additionalUsers],
            status: 'stopped',
            port: Math.floor(Math.random() * 10000) + 25565,
            createdAt: new Date().toISOString()
        };

        if (!db.data.servers) {
            db.data.servers = [];
        }
        db.data.servers.push(newServer);

        requests[requestIndex] = request;
        db.data.serverRequests = requests;
        await db.write();

        res.json({ message: 'Request approved and server created', server: newServer });
    } catch (error) {
        console.error('Error approving request:', error);
        res.status(500).json({ error: 'Error approving request' });
    }
});

app.post('/api/server-requests/:id/reject', requireAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { reason } = req.body;
        const requests = db.data.serverRequests || [];
        const requestIndex = requests.findIndex(r => r.id === id);
        
        if (requestIndex === -1) {
            return res.status(404).json({ error: 'Request not found' });
        }

        const request = requests[requestIndex];
        request.status = 'rejected';
        request.updatedAt = new Date().toISOString();
        request.rejectedBy = req.session.username;
        request.rejectionReason = reason || '';

        requests[requestIndex] = request;
        db.data.serverRequests = requests;
        await db.write();

        res.json({ message: 'Request rejected' });
    } catch (error) {
        console.error('Error rejecting request:', error);
        res.status(500).json({ error: 'Error rejecting request' });
    }
});

// Docker stats endpoint (original)
app.get('/api/docker/stats', (req, res) => {
    console.log('Stats endpoint hit at:', new Date().toISOString());
    
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

// RCON endpoint for executing commands
app.post('/api/servers/:serverName/rcon', requireAuth, async (req, res) => {
    try {
        const { serverName } = req.params;
        const { command } = req.body;
        
        if (!command) {
            return res.status(400).json({ error: 'Command is required' });
        }
        
        console.log(`Executing RCON command for ${serverName}: ${command}`);
        
        // Execute the command using child_process
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error('RCON command error:', error);
                return res.status(500).json({ 
                    error: 'Failed to execute command',
                    details: error.message 
                });
            }
            
            if (stderr) {
                console.warn('RCON command stderr:', stderr);
            }
            
            console.log('RCON command output:', stdout);
            
            res.json({ 
                success: true, 
                output: stdout,
                stderr: stderr || null
            });
        });
        
    } catch (error) {
        console.error('RCON endpoint error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// User profile endpoint
app.get('/api/user/profile', requireAuth, async (req, res) => {
    try {
        const user = db.data.users.find(u => u.username === req.session.username);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        res.json({
            username: user.username,
            email: user.email || 'No email set',
            isAdmin: Boolean(user.isAdmin)
        });
    } catch (error) {
        console.error('Error fetching user profile:', error);
        res.status(500).json({ error: 'Error fetching user profile' });
    }
});

// User servers endpoint
app.get('/api/user/servers', requireAuth, async (req, res) => {
    try {
        const servers = db.data.servers || [];
        // Filter servers that the user has access to
        const userServers = servers.filter(server => 
            server.users && server.users.includes(req.session.username)
        );
        
        res.json(userServers);
    } catch (error) {
        console.error('Error fetching user servers:', error);
        res.status(500).json({ error: 'Error fetching user servers' });
    }
});

// Server control endpoints
app.post('/api/server/:serverId/start', requireAuth, async (req, res) => {
    try {
        const { serverId } = req.params;
        const servers = db.data.servers || [];
        const serverIndex = servers.findIndex(s => s.id === serverId);
        
        if (serverIndex === -1) {
            return res.status(404).json({ error: 'Server not found' });
        }
        
        const server = servers[serverIndex];
        // Check if user has access to this server
        if (!server.users || !server.users.includes(req.session.username)) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        // Update server status
        server.status = 'running';
        server.updatedAt = new Date().toISOString();
        
        servers[serverIndex] = server;
        db.data.servers = servers;
        await db.write();
        
        res.json({ message: 'Server started successfully', server });
    } catch (error) {
        console.error('Error starting server:', error);
        res.status(500).json({ error: 'Error starting server' });
    }
});

app.post('/api/server/:serverId/stop', requireAuth, async (req, res) => {
    try {
        const { serverId } = req.params;
        const servers = db.data.servers || [];
        const serverIndex = servers.findIndex(s => s.id === serverId);
        
        if (serverIndex === -1) {
            return res.status(404).json({ error: 'Server not found' });
        }
        
        const server = servers[serverIndex];
        // Check if user has access to this server
        if (!server.users || !server.users.includes(req.session.username)) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        // Update server status
        server.status = 'stopped';
        server.updatedAt = new Date().toISOString();
        
        servers[serverIndex] = server;
        db.data.servers = servers;
        await db.write();
        
        res.json({ message: 'Server stopped successfully', server });
    } catch (error) {
        console.error('Error stopping server:', error);
        res.status(500).json({ error: 'Error stopping server' });
    }
});

// Delete server endpoint
app.delete('/api/server/:serverId', requireAuth, async (req, res) => {
    try {
        const { serverId } = req.params;
        const servers = db.data.servers || [];
        const serverIndex = servers.findIndex(s => s.id === serverId);
        
        if (serverIndex === -1) {
            return res.status(404).json({ error: 'Server not found' });
        }
        
        const server = servers[serverIndex];
        // Check if user has access to this server
        if (!server.users || !server.users.includes(req.session.username)) {
            return res.status(403).json({ error: 'Access denied' });
        }
        
        // Remove server from array
        servers.splice(serverIndex, 1);
        db.data.servers = servers;
        await db.write();
        
        res.json({ message: 'Server deleted successfully' });
    } catch (error) {
        console.error('Error deleting server:', error);
        res.status(500).json({ error: 'Error deleting server' });
    }
});

// Test endpoint
app.get('/api/test', (req, res) => {
    res.json({ status: 'ok', time: new Date().toISOString() });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: err.message
    });
});

// Start server on port 3001
const PORT = 3001;
app.listen(PORT, () => {
    console.log(`API Server running on http://localhost:${PORT}`);
    console.log('Available endpoints:');
    console.log(`- http://localhost:${PORT}/api/docker/stats`);
    console.log(`- http://localhost:${PORT}/api/test`);
    console.log(`- http://localhost:${PORT}/api/users`);
    console.log(`- http://localhost:${PORT}/api/docker/containers`);
    console.log(`- http://localhost:${PORT}/api/dashboard/stats`);
    console.log(`- http://localhost:${PORT}/api/server-requests`);
    console.log(`- http://localhost:${PORT}/api/login`);
    console.log(`- http://localhost:${PORT}/api/logout`);
}); 