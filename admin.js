const express = require('express');
const fs = require('fs').promises;
const path = require('path');
const app = express();

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Get all servers
app.get('/api/servers', async (req, res) => {
    try {
        const serversPath = path.join(__dirname, 'servers');
        const serverFolders = await fs.readdir(serversPath);
        
        const servers = await Promise.all(serverFolders.map(async folder => {
            const serverPath = path.join(serversPath, folder);
            const propertiesPath = path.join(serverPath, 'server.properties');
            
            try {
                const stats = await fs.stat(serverPath);
                const properties = await parseProperties(propertiesPath);
                
                return {
                    id: folder,
                    name: properties['server-name'] || folder,
                    path: serverPath,
                    status: await checkServerStatus(serverPath),
                    ram: parseInt(properties['max-ram'] || '4'),
                    currentPlayers: await getCurrentPlayers(serverPath),
                    maxPlayers: parseInt(properties['max-players'] || '20'),
                    version: properties['version'] || 'Unknown'
                };
            } catch (error) {
                console.error(`Error reading server ${folder}:`, error);
                return null;
            }
        }));

        res.json(servers.filter(server => server !== null));
    } catch (error) {
        res.status(500).json({ error: 'Failed to load servers' });
    }
});

// Start server
app.post('/api/servers/:id/start', async (req, res) => {
    const serverId = req.params.id;
    try {
        // Implement server start logic here
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to start server' });
    }
});

// Stop server
app.post('/api/servers/:id/stop', async (req, res) => {
    const serverId = req.params.id;
    try {
        // Implement server stop logic here
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to stop server' });
    }
});

// Helper functions
async function parseProperties(propertiesPath) {
    try {
        const content = await fs.readFile(propertiesPath, 'utf8');
        const properties = {};
        content.split('\n').forEach(line => {
            const [key, value] = line.split('=').map(s => s.trim());
            if (key && value) properties[key] = value;
        });
        return properties;
    } catch {
        return {};
    }
}

async function checkServerStatus(serverPath) {
    // Implement server status check logic
    return 'offline'; // or 'online'
}

async function getCurrentPlayers(serverPath) {
    // Implement current players check logic
    return 0;
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});