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
        'http://localhost:8080',
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
        return res.redirect('/login.html');
    }
    if (!req.session.isAdmin) {
        return res.redirect('/dashboard.html');
    }
    next();
};

// 2. Create API Router
const apiRouter = express.Router();

// Docker container routes
apiRouter.get('/docker/containers', (req, res) => {
    exec('docker ps -a --format "{{.ID}}\t{{.Names}}\t{{.Status}}\t{{.Ports}}"', (error, stdout, stderr) => {
        if (error) return res.status(500).json({ error: 'Failed to fetch containers' });
        try {
            if (!stdout.trim()) return res.json([]);
            const containers = stdout.trim().split('\n').map(line => {
                const [id, name, status, ports] = line.split('\t');
                return { id, name, status, ports };
            });
            res.json(containers);
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
        // Get server statistics
        const activeServers = servers.filter(s => s.status === 'running').length;
        const totalServers = servers.length;
        
        // Get user statistics
        const totalUsers = db.data.users.length;
        
        // Get system load (simulated for now)
        const systemLoad = Math.floor(Math.random() * 30) + 20; // 20-50% range
        
        // Get recent activity
        const recentActivity = await getRecentActivity();
        
        res.json({
            activeServers,
            totalServers,
            totalUsers,
            systemLoad: `${systemLoad}%`,
            recentActivity
        });
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
    }
});



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

// 6. Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: 'Internal Server Error',
        message: err.message
    });
});

// Start the server
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});

export default app;
        