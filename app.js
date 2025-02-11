import express from 'express';
import Dockerode from 'dockerode';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import cors from 'cors';
import session from 'express-session';
import fs from 'fs/promises';

// Get __dirname equivalent in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Initialize Express and Docker
const app = express();
const docker = new Dockerode();

// Add session middleware
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false } // set to true if using https
}));

// Updated CORS configuration
app.use(cors({
    origin: 'http://127.0.0.1:5500', // Allow requests from live server
    credentials: true
}));

app.use(express.json());
app.use(express.static('public'));

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

// Authentication middleware
const requireAuth = (req, res, next) => {
    if (req.session.authenticated) {
        next();
    } else {
        res.redirect('/login.html');
    }
};

// Login endpoint
app.post('/login', async (req, res) => {
    console.log('Login attempt:', req.body);
    console.log('Current users:', users); // Debug log
    
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: 'Username and password are required'
        });
    }
    
    // Check admin credentials first
    if (username === 'IntiHostadmin123' && password === 'intipintypoo') {
        console.log('Admin login successful');
        return res.json({ success: true });
    }
    
    // Reload users before checking
    await loadUsers();
    
    // Check registered users
    const user = users.find(u => {
        console.log('Comparing with user:', u.username); // Debug log
        return u.username === username && u.password === password;
    });
    
    if (user) {
        console.log('User login successful:', username);
        return res.json({ success: true });
    }
    
    console.log('Login failed. No matching user found.');
    return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
    });
});

// Logout endpoint
app.post('/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Protect admin routes
app.get('/a_dashboard.html', requireAuth, (req, res) => {
    res.sendFile(join(__dirname, 'public', 'a_dashboard.html'));
});

app.get('/a_servers.html', requireAuth, (req, res) => {
    res.sendFile(join(__dirname, 'public', 'a_servers.html'));
});

app.get('/servform.html', requireAuth, (req, res) => {
    res.sendFile(join(__dirname, 'public', 'servform.html'));
});

// Serve static files from public directory
app.get('/', (req, res) => {
    res.sendFile(join(__dirname, 'public', 'index.html'));
});

// Docker containers endpoint
app.get('/api/docker/containers', async (req, res) => {
    try {
        const containers = await docker.listContainers({ all: true });
        res.json(containers);
    } catch (error) {
        console.error('Docker API error:', error);
        res.status(500).json({ error: 'Failed to fetch container data' });
    }
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

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Start server
const PORT = process.env.PORT || 3002;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
