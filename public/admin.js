// Function to fetch Docker container data
async function updateServerStatus() {
    try {
        const response = await fetch('/api/docker/containers');
        const containers = await response.json();
        
        // Update total servers count
        const totalServers = containers.length;
        const activeServers = containers.filter(container => container.State === 'running').length;
        document.getElementById('total-servers').textContent = `${activeServers}/${totalServers}`;
        
        // Update progress bar
        const progressPercentage = (activeServers / totalServers) * 100;
        document.querySelector('.progress-fill').style.width = `${progressPercentage}%`;
        
        // Update server grid
        const serverGrid = document.querySelector('.server-grid');
        serverGrid.innerHTML = ''; // Clear existing servers
        
        // Add a random active container to display
        const activeContainer = containers.filter(container => container.State === 'running')[0];
        if (activeContainer) {
            const serverCard = `
                <div class="server-card">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
                        <h3>${activeContainer.Names[0].replace('/', '')}</h3>
                        <span class="status-badge status-online">Online</span>
                    </div>
                    <p>Container ID: ${activeContainer.Id.slice(0, 12)}</p>
                    <p>IP: ${activeContainer.NetworkSettings.IPAddress}</p>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: 100%;"></div>
                    </div>
                </div>
            `;
            serverGrid.innerHTML = serverCard;
        }
    } catch (error) {
        console.error('Error fetching Docker data:', error);
    }
}

// Update status every 30 seconds
updateServerStatus();
setInterval(updateServerStatus, 30000);

// Server management functions
async function loadServers() {
    try {
        const response = await fetch('/api/servers');
        const servers = await response.json();
        displayServers(servers);
    } catch (error) {
        console.error('Error loading servers:', error);
    }
}

function displayServers(servers) {
    const serverGrid = document.querySelector('.server-grid');
    serverGrid.innerHTML = '';

    servers.forEach(server => {
        const serverCard = createServerCard(server);
        serverGrid.appendChild(serverCard);
    });
}

function createServerCard(server) {
    const card = document.createElement('div');
    card.className = 'server-card';
    card.innerHTML = `
        <div class="server-header">
            <h3>${server.name}</h3>
            <span class="status ${server.status.toLowerCase()}">${server.status}</span>
        </div>
        <div class="server-info">
            <p><i class="fas fa-microchip"></i> CPU: ${server.cpu}%</p>
            <p><i class="fas fa-memory"></i> RAM: ${server.ram}%</p>
            <p><i class="fas fa-hdd"></i> Storage: ${server.storage}%</p>
        </div>
        <div class="server-actions">
            <button onclick="startServer('${server.id}')" class="button">Start</button>
            <button onclick="stopServer('${server.id}')" class="button">Stop</button>
            <button onclick="restartServer('${server.id}')" class="button">Restart</button>
        </div>
    `;
    return card;
}

// Server control functions
async function startServer(serverId) {
    try {
        await fetch(`/api/servers/${serverId}/start`, { method: 'POST' });
        loadServers(); // Refresh the server list
    } catch (error) {
        console.error('Error starting server:', error);
    }
}

async function stopServer(serverId) {
    try {
        await fetch(`/api/servers/${serverId}/stop`, { method: 'POST' });
        loadServers();
    } catch (error) {
        console.error('Error stopping server:', error);
    }
}

async function restartServer(serverId) {
    try {
        await fetch(`/api/servers/${serverId}/restart`, { method: 'POST' });
        loadServers();
    } catch (error) {
        console.error('Error restarting server:', error);
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', () => {
    loadServers();
    // Set up search functionality
    const searchInput = document.querySelector('.search-bar input');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            // Implement search functionality here
        });
    }
}); 