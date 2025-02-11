const express = require('express');
const { exec } = require('child_process');  // Add this for running shell commands
const app = express();
const port = 3000;

// Add CORS headers
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
    }
    next();
});

// Middleware to parse JSON and serve static files
app.use(express.static('public'));
app.use(express.json());

app.post('/create-server', (req, res) => {
    try {
        // Log the incoming request
        console.log('Raw body:', req.body);

        // Destructure the data
        const { serverName, port } = req.body;
        console.log('Received:', { serverName, port });

        // Construct the Docker command
        const dockerCommand = `docker run -d \
            --name ${serverName} \
            -p ${port}:25565 \
            -v /var/lib/docker/volumes/${serverName}/data \
            -e EULA=TRUE \
            itzg/minecraft-server`;

        console.log('Executing command:', dockerCommand);

        // Execute the Docker command
        exec(dockerCommand, (error, stdout, stderr) => {
            if (error) {
                console.error('Error executing Docker command:', error);
                return res.status(500).json({ error: 'Failed to create Docker container' });
            }

            console.log('Docker container created:', stdout);
            
            if (stderr) {
                console.warn('Docker stderr:', stderr);
            }

            // Success response
            res.status(200).json({
                message: 'Minecraft server created successfully',
                data: { 
                    serverName, 
                    port: parseInt(port),
                    containerId: stdout.trim()
                }
            });
        });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});

// Add this route to handle the server creation