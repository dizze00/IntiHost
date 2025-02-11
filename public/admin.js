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