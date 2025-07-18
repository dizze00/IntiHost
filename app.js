import express from 'express';
import Dockerode from 'dockerode';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import cors from 'cors';
import session from 'express-session';
import fs from 'fs/promises';
import multer from 'multer';
import path from 'path';
import { exec } from 'child_process';
import { Low } from 'lowdb'
import { JSONFile } from 'lowdb/node'

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Initialize Express and Docker
const app = express();
const docker = new Dockerode();
const dbFile = new JSONFile('db.json')
const db = new Low(dbFile, { users: [] })

// Global variables for tracking
const servers = [];
const activities = [];

// Activity tracking functions
const trackActivity = (type, message, data = {}) => {
    const activity = {
        id: Date.now(),
        type,
        message,
        data,
        timestamp: new Date().toISOString()
    };
    activities.unshift(activity); // Add to beginning
    
    // Keep only last 50 activities
    if (activities.length > 50) {
        activities.splice(50);
    }
};

const getRecentActivity = async () => {
    return activities.slice(0, 10); // Return last 10 activities
};

// Configure multer for file uploads
const storage = multer.diskStorage({
    destination: 'uploads/profile-images/',
    filename: function(req, file, cb) {
        cb(null, req.session.username + path.extname(file.originalname));
    }
});
const upload = multer({ storage: storage });

// 1. Essential middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors({
    origin: [
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
    ],
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type']
}));

// Session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Move these middleware definitions to the top, after the initial setup but before routes
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
        if (req.path.startsWith('/api/')) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        return res.redirect('/login.html');
    }
    if (!req.session.isAdmin) {
        if (req.path.startsWith('/api/')) {
            return res.status(403).json({ error: 'Not authorized' });
        }
        return res.redirect('/dashboard.html');
    }
    next();
};

// 2. Create API Router
const apiRouter = express.Router();

// Test endpoint
apiRouter.get('/test', (req, res) => {
    console.log('Test endpoint called');
    res.json({ message: 'API is working!', timestamp: new Date().toISOString() });
});

// Docker container routes
apiRouter.get('/docker/containers', (req, res) => {
    exec('docker ps -a', (error, stdout, stderr) => {
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

            // Get server information from database to add creator info
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
apiRouter.post('/docker/remove/:name', (req, res) => {
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

apiRouter.post('/docker/stop/:name', (req, res) => {
    const { name } = req.params;
    exec(`docker stop ${name}`, (error, stdout, stderr) => {
        if (error) return res.status(500).json({ error: 'Failed to stop container' });
        
        // Track activity
        trackActivity('server_stopped', `Server "${name}" stopped`, { serverName: name });
        
        res.json({ message: 'Container stopped successfully' });
    });
});

apiRouter.post('/docker/start/:name', (req, res) => {
    const { name } = req.params;
    exec(`docker start ${name}`, (error, stdout, stderr) => {
        if (error) return res.status(500).json({ error: 'Failed to start container' });
        
        // Track activity
        trackActivity('server_started', `Server "${name}" started`, { serverName: name });
        
        res.json({ message: 'Container started successfully' });
    });
});

apiRouter.post('/docker/restart/:name', (req, res) => {
    const { name } = req.params;
    exec(`docker restart ${name}`, (error, stdout, stderr) => {
        if (error) return res.status(500).json({ error: 'Failed to restart container' });
        
        // Track activity
        trackActivity('server_restarted', `Server "${name}" restarted`, { serverName: name });
        
        res.json({ message: 'Container restarted successfully' });
    });
});

// Get server IP address endpoint
apiRouter.get('/server/ip', (req, res) => {
    exec('hostname -I', (error, stdout, stderr) => {
        if (error) {
            // Fallback to localhost if hostname command fails
            return res.json({ ip: 'localhost' });
        }
        
        // Get the first IP address (usually the primary one)
        const ips = stdout.trim().split(' ').filter(ip => ip.trim());
        const primaryIP = ips[0] || 'localhost';
        
        res.json({ ip: primaryIP });
    });
});

// Docker statistics endpoint
apiRouter.get('/docker/stats', (req, res) => {
    console.log('Docker stats endpoint called');
    exec('docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"', (error, stdout, stderr) => {
        if (error) {
            console.error('Error fetching Docker stats:', error);
            return res.status(500).json({ error: 'Failed to fetch Docker statistics' });
        }
        
        try {
            const lines = stdout.trim().split('\n').filter(line => line.trim());
            if (lines.length <= 1) {
                // No containers running
                return res.json({
                    activeContainers: 0,
                    totalContainers: 0,
                    cpuUsage: 0,
                    memoryUsage: 0,
                    networkIO: 0,
                    containers: []
                });
            }
            
            // Skip header line and parse container stats
            const containers = lines.slice(1).map(line => {
                const [container, cpu, memory, netIO] = line.split('\t');
                return {
                    container: container.trim(),
                    cpu: parseFloat(cpu.replace('%', '')) || 0,
                    memory: memory.trim(),
                    netIO: netIO.trim()
                };
            });
            
            // Calculate totals
            const totalContainers = containers.length;
            const activeContainers = containers.length; // All containers in stats are running
            const totalCPU = containers.reduce((sum, c) => sum + c.cpu, 0);
            
            // Parse memory usage (format: "1.234MiB / 2.000GiB")
            const totalMemory = containers.reduce((sum, c) => {
                const memMatch = c.memory.match(/(\d+\.?\d*)/);
                return sum + (memMatch ? parseFloat(memMatch[1]) : 0);
            }, 0);
            
            // Parse network I/O (format: "1.23kB / 4.56MB")
            const totalNetwork = containers.reduce((sum, c) => {
                const netMatch = c.netIO.match(/(\d+\.?\d*)/);
                return sum + (netMatch ? parseFloat(netMatch[1]) : 0);
            }, 0);
            
            res.json({
                activeContainers,
                totalContainers,
                cpuUsage: totalCPU,
                memoryUsage: totalMemory,
                networkIO: totalNetwork,
                containers
            });
            
        } catch (parseError) {
            console.error('Error parsing Docker stats:', parseError);
            res.status(500).json({ error: 'Failed to parse Docker statistics' });
        }
    });
});

// Server management endpoints
apiRouter.get('/servers', (req, res) => {
    res.json(servers);
});

apiRouter.post('/servers', async (req, res) => {
    console.log('Received request:', req.body);
    
    try {
        const { name, type, port, version } = req.body;
        
        // Sanitize the server name
        const sanitizedName = name.toLowerCase().replace(/[^a-z0-9-]/g, '');
        
        console.log('Sanitized name:', sanitizedName);
        console.log('Version:', version);
        
        // First try to remove any existing container with the same name
        try {
            await new Promise((resolve) => {
                exec(`docker rm -f ${sanitizedName}`, () => resolve());
            });
        } catch (error) {
            console.log('No existing container to remove');
        }

        // Pull the latest image first
        console.log('Pulling latest minecraft-server image...');
        try {
            await new Promise((resolve, reject) => {
                exec('docker pull itzg/minecraft-server:latest', (error, stdout, stderr) => {
                    if (error) {
                        console.log('Image pull warning:', error.message);
                    }
                    resolve();
                });
            });
        } catch (error) {
            console.log('Image pull failed, continuing with existing image');
        }

        // Create the new container
        const versionEnv = version ? `-e VERSION=${version} ` : '';
        const dockerCommand = `docker run -d --name ${sanitizedName} -p ${port}:25565 -e EULA=TRUE -e MEMORY=1G -e TYPE=VANILLA ${versionEnv}itzg/minecraft-server:latest`;
        
        console.log('Executing Docker command:', dockerCommand);

        const { stdout, stderr } = await new Promise((resolve, reject) => {
            exec(dockerCommand, (error, stdout, stderr) => {
                if (error) {
                    console.error('Docker execution error:', error);
                    console.error('stderr:', stderr);
                    reject(new Error(stderr || error.message));
                } else {
                    resolve({ stdout, stderr });
                }
            });
        });

        // Create new server object
        const newServer = {
            id: Date.now().toString(),
            name: sanitizedName,
            type,
            port: parseInt(port),
            version: version || 'LATEST',
            status: 'running',
            containerId: stdout.trim(),
            created: new Date().toISOString()
        };

        // Add to servers array
        servers.push(newServer);
        console.log('Server created:', newServer);
        
        // Track activity for dashboard
        trackActivity('server_created', `Server "${sanitizedName}" created successfully`, {
            serverName: sanitizedName,
            serverType: type,
            version: version || 'LATEST'
        });

        return res.status(201).json({
            success: true,
            message: 'Server created successfully',
            server: newServer
        });

    } catch (error) {
        console.error('Server creation error:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to create server: ' + error.message
        });
    }
});

apiRouter.get('/servers/stats', (req, res) => {
    const activeServers = servers.filter(s => s.status === 'running').length;
    res.json({
        activeServers,
        totalServers: servers.length
    });
});

// Dashboard statistics endpoint
apiRouter.get('/dashboard/stats', async (req, res) => {
    try {
        console.log('Dashboard stats endpoint called');
        
        // Get real Docker container statistics
        const dockerStats = await new Promise((resolve, reject) => {
            exec('docker ps -a --format "{{.Names}}\t{{.Status}}"', (error, stdout, stderr) => {
                if (error) {
                    console.log('Docker command failed, using fallback:', error.message);
                    resolve({ containers: [], activeContainers: 0, totalContainers: 0 });
                    return;
                }
                
                console.log('Docker ps -a output:', stdout);
                
                try {
                    const lines = stdout.trim().split('\n').filter(line => line.trim());
                    console.log('Parsed lines:', lines);
                    
                    const containers = lines.map(line => {
                        const [name, status] = line.split('\t');
                        return { name: name.trim(), status: status.trim() };
                    });
                    
                    console.log('Parsed containers:', containers);
                    
                    const activeContainers = containers.filter(c => 
                        c.status.includes('Up') || c.status.includes('running')
                    ).length;
                    
                    const result = {
                        containers,
                        activeContainers,
                        totalContainers: containers.length
                    };
                    
                    console.log('Docker stats result:', result);
                    resolve(result);
                } catch (parseError) {
                    console.log('Error parsing Docker output:', parseError);
                    resolve({ containers: [], activeContainers: 0, totalContainers: 0 });
                }
            });
        });
        
        // Also check local servers array as fallback
        console.log('Local servers array:', servers);
        const localActiveServers = servers.filter(s => s.status === 'running').length;
        const localTotalServers = servers.length;
        
        // Use Docker stats if available, otherwise fall back to local array
        const finalActiveServers = dockerStats.totalContainers > 0 ? dockerStats.activeContainers : localActiveServers;
        const finalTotalServers = dockerStats.totalContainers > 0 ? dockerStats.totalContainers : localTotalServers;
        
        // Get real system load using CPU usage
        const systemLoad = await new Promise((resolve) => {
            exec('wmic cpu get loadpercentage /value', (error, stdout, stderr) => {
                if (error) {
                    console.log('CPU load command failed, using fallback');
                    resolve(25); // Fallback value
                    return;
                }
                
                try {
                    const match = stdout.match(/LoadPercentage=(\d+)/);
                    const load = match ? parseInt(match[1]) : 25;
                    resolve(load);
                } catch (parseError) {
                    console.log('Error parsing CPU load:', parseError);
                    resolve(25);
                }
            });
        });
        
        // Get user statistics
        const totalUsers = db.data.users.length;
        
        // Get recent activity
        const recentActivity = await getRecentActivity();
        
        // Format recent activity for frontend
        const formattedActivity = recentActivity.map(activity => {
            const timeAgo = getTimeAgo(new Date(activity.timestamp));
            let icon = 'fas fa-info-circle';
            let title = activity.message;
            
            // Set appropriate icons based on activity type
            if (activity.type === 'server_created') icon = 'fas fa-plus-circle';
            else if (activity.type === 'server_started') icon = 'fas fa-play-circle';
            else if (activity.type === 'server_stopped') icon = 'fas fa-stop-circle';
            else if (activity.type === 'server_restarted') icon = 'fas fa-redo';
            
            return {
                icon,
                title,
                timeAgo,
                type: activity.type,
                timestamp: activity.timestamp
            };
        });
        
        const stats = {
            activeServers: finalActiveServers,
            totalServers: finalTotalServers,
            totalUsers,
            systemLoad: `${systemLoad}%`,
            recentActivity: formattedActivity
        };
        
        console.log('Dashboard stats:', stats);
        res.json(stats);
        
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
    }
});

// Helper function to format time ago
function getTimeAgo(date) {
    const now = new Date();
    const diffInSeconds = Math.floor((now - date) / 1000);
    
    if (diffInSeconds < 60) return 'Just now';
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)}m ago`;
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)}h ago`;
    return `${Math.floor(diffInSeconds / 86400)}d ago`;
}



// Server details endpoints
apiRouter.get('/servers/:name/console', (req, res) => {
    const { name } = req.params;
    exec(`docker logs ${name} --tail 50`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: 'Failed to fetch console logs' });
        }
        res.send(stdout || 'No console output available');
    });
});

apiRouter.post('/servers/:name/command', (req, res) => {
    const { name } = req.params;
    const { command } = req.body;
    
    if (!command) {
        return res.status(400).json({ error: 'Command is required' });
    }
    
    exec(`docker exec ${name} ${command}`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: 'Failed to execute command' });
        }
        res.json({ output: stdout, error: stderr });
    });
});

apiRouter.get('/servers/:name/files', (req, res) => {
    const { name } = req.params;
    exec(`docker exec ${name} ls -la /data`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: 'Failed to fetch files' });
        }
        
        // Parse the ls output to create a file list
        const lines = stdout.split('\n').filter(line => line.trim());
        const files = lines.slice(1).map(line => {
            const parts = line.split(/\s+/);
            if (parts.length >= 9) {
                const permissions = parts[0];
                const isDirectory = permissions.startsWith('d');
                const fileName = parts.slice(8).join(' ');
                return {
                    name: fileName,
                    type: isDirectory ? 'directory' : 'file',
                    size: parts[4],
                    modified: `${parts[5]} ${parts[6]} ${parts[7]}`
                };
            }
            return null;
        }).filter(file => file && file.name !== '.' && file.name !== '..');
        
        res.json(files);
    });
});

apiRouter.get('/servers/:name/logs', (req, res) => {
    const { name } = req.params;
    exec(`docker logs ${name} --tail 100`, (error, stdout, stderr) => {
        if (error) {
            return res.status(500).json({ error: 'Failed to fetch logs' });
        }
        res.send(stdout || 'No logs available');
    });
});

apiRouter.get('/servers/:name/users', (req, res) => {
    // For now, return an empty array - you can implement user management later
    res.json([]);
});

apiRouter.post('/servers/:name/users', (req, res) => {
    // For now, just return success - you can implement user management later
    res.json({ success: true, message: 'User access added' });
});

apiRouter.delete('/servers/:name/users/:username', (req, res) => {
    // For now, just return success - you can implement user management later
    res.json({ success: true, message: 'User access removed' });
});

apiRouter.post('/servers/:name/files/upload', (req, res) => {
    // For now, just return success - you can implement file upload later
    res.json({ success: true, message: 'File uploaded successfully' });
});

// User routes
apiRouter.post('/user/profile-image', requireAuth, upload.single('image'), async (req, res) => {
    try {
        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        const imagePath = '/uploads/profile-images/' + req.file.filename;
        
        const userIndex = db.data.users.findIndex(u => u.username === req.session.username);
        db.data.users[userIndex].profile_image = imagePath;
        
        await db.write();
        
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

// 3. Mount API Router BEFORE static files
app.use('/api', apiRouter);

// 4. Static files
app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static('uploads'));

// 5. Catch-all route
app.get('*', (req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API endpoint not found' });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Load users from database
await db.read();
console.log('Loaded users from database:', db.data.users);

// Add initial activity if none exists
if (activities.length === 0) {
    trackActivity('system_started', 'IntiHost system started', { timestamp: new Date().toISOString() });
    trackActivity('user_login', 'Admin user logged in', { username: 'IntiHost123' });
}



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
    
    if (db.data.users.some(user => user.username === username)) {
        return res.status(400).json({
            success: false,
            message: 'Username already exists'
        });
    }
    
    if (db.data.users.some(user => user.email === email)) {
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
    
    db.data.users.push(newUser);
    
    try {
        await db.write();
        console.log('Updated users list:', db.data.users); // Debug log
        
        // Track activity for dashboard
        trackActivity('user_registered', `User "${username}" registered successfully`, {
            username: username,
            email: email
        });
        
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
        const user = db.data.users.find(u => u.username === username);
        
        console.log('Found user:', user);

        if (user && user.password === password) {
            req.session.username = user.username;
            req.session.isAdmin = Boolean(user.isAdmin);
            
            // Track login activity
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

// Logout endpoint
app.post('/api/logout', (req, res) => {
    const username = req.session.username;
    
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ message: 'Error during logout' });
        }
        
        // Track logout activity
        if (username) {
            trackActivity('user_logout', `User "${username}" logged out`, { username });
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

app.get('/a_users.html', requireAdmin, (req, res) => {
    res.sendFile(join(__dirname, 'public', 'a_users.html'));
});

app.get('/a_requests.html', requireAdmin, (req, res) => {
    res.sendFile(join(__dirname, 'public', 'a_requests.html'));
});

app.get('/a_statistics.html', requireAdmin, (req, res) => {
    res.sendFile(join(__dirname, 'public', 'a_statistics.html'));
});

app.get('/a_backups.html', requireAdmin, (req, res) => {
    res.sendFile(join(__dirname, 'public', 'a_backups.html'));
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
        const user = db.data.users.find(u => u.username === req.session.username);
        
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

// Get user servers
app.get('/api/user/servers', requireAuth, async (req, res) => {
    try {
        const userServers = db.data.servers ? db.data.servers.filter(server => 
            server.users && server.users.includes(req.session.username)
        ) : [];
        
        res.json(userServers);
    } catch (error) {
        console.error('Error fetching user servers:', error);
        res.status(500).json({ error: 'Error fetching user servers' });
    }
});

// User profile update endpoint
app.post('/api/user/update', requireAuth, async (req, res) => {
    try {
        const { username, email, currentPassword, newPassword } = req.body;
        
        const userIndex = db.data.users.findIndex(u => u.username === req.session.username);
        const user = db.data.users[userIndex];
        
        if (!user || user.password !== currentPassword) {
            return res.status(401).json({ message: 'Current password is incorrect' });
        }
        
        // Update user information
        db.data.users[userIndex] = {
            ...user,
            username: username || user.username,
            email: email || user.email,
            password: newPassword || currentPassword
        };
        
        await db.write();
        
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
        const users = db.data.users;
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

// Debug endpoint to check servers array
app.get('/api/debug/servers', (req, res) => {
    res.json({
        servers: servers,
        totalServers: servers.length,
        activeServers: servers.filter(s => s.status === 'running').length
    });
});

// Test endpoint to check if user management endpoints are accessible
app.get('/api/test-users', (req, res) => {
    res.json({
        message: 'User management endpoints are accessible',
        session: {
            authenticated: req.session.authenticated,
            username: req.session.username,
            isAdmin: req.session.isAdmin
        },
        timestamp: new Date().toISOString()
    });
});

// Server Request System API Endpoints
app.post('/api/server-requests', async (req, res) => {
    try {
        if (!req.session.authenticated) {
            return res.status(401).json({ error: 'Not authenticated' });
        }

        const { serverName, serverVersion, serverType, description, additionalUsers } = req.body;
        
        // Validate required fields
        if (!serverName || !serverVersion || !serverType) {
            return res.status(400).json({ error: 'Missing required fields' });
        }

        // Create new request
        const newRequest = {
            id: Date.now().toString(),
            serverName,
            serverVersion,
            serverType,
            description: description || '',
            additionalUsers: additionalUsers || [],
            requestedBy: req.session.username,
            status: 'pending',
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };

        // Add to database
        if (!db.data.serverRequests) {
            db.data.serverRequests = [];
        }
        db.data.serverRequests.push(newRequest);
        await db.write();

        res.status(201).json(newRequest);
    } catch (error) {
        console.error('Error creating server request:', error);
        res.status(500).json({ error: 'Error creating server request' });
    }
});

app.get('/api/server-requests', requireAdmin, async (req, res) => {
    try {
        const requests = db.data.serverRequests || [];
        res.json(requests);
    } catch (error) {
        console.error('Error fetching server requests:', error);
        res.status(500).json({ error: 'Error fetching server requests' });
    }
});

app.post('/api/server-requests/:id/approve', requireAdmin, async (req, res) => {
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

        // Create the actual server
        const newServer = {
            id: Date.now().toString(),
            name: request.serverName,
            version: request.serverVersion,
            type: request.serverType,
            description: request.description,
            createdBy: request.requestedBy,
            users: [request.requestedBy, ...request.additionalUsers],
            status: 'stopped',
            port: Math.floor(Math.random() * 10000) + 25565, // Random port
            createdAt: new Date().toISOString()
        };

        // Add server to database
        if (!db.data.servers) {
            db.data.servers = [];
        }
        db.data.servers.push(newServer);

        // Update request
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

// User Management API Endpoints
app.get('/api/users', requireAdmin, async (req, res) => {
    try {
        const users = db.data.users.map(user => ({
            username: user.username,
            email: user.email,
            isAdmin: user.isAdmin || false,
            status: 'active', // You can add more status logic here
            createdAt: user.createdAt || new Date().toISOString()
        }));
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ error: 'Error fetching users' });
    }
});

app.post('/api/users', requireAdmin, async (req, res) => {
    try {
        const { username, email, password, isAdmin } = req.body;
        // Validate required fields
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password are required' });
        }
        // Check if user already exists
        if (db.data.users.some(user => user.username === username)) {
            return res.status(400).json({ error: 'Username already exists' });
        }
        if (db.data.users.some(user => user.email === email)) {
            return res.status(400).json({ error: 'Email already exists' });
        }
        // Create new user
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
        // Update user fields
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
        // Prevent deleting the last admin user
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

// 6. Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: err.message
    });
});

// Start the server
const PORT = process.env.PORT || 5005;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

export default app;
        