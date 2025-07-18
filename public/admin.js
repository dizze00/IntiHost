// API Server configuration
const API_BASE_URL = 'http://localhost:3001';

// Function to fetch Docker container data
async function updateServerStatus() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/docker/containers`, {
            credentials: 'include'
        });
        const containers = await response.json();
        
        // Only update if we're on a page with server elements
        const totalServersElement = document.getElementById('total-servers');
        const progressFillElement = document.querySelector('.progress-fill');
        const serverGrid = document.querySelector('.server-grid');
        
        if (totalServersElement) {
            const totalServers = containers.length;
            const activeServers = containers.filter(container => container.State === 'running').length;
            totalServersElement.textContent = `${activeServers}/${totalServers}`;
        }
        
        if (progressFillElement) {
            const totalServers = containers.length;
            const activeServers = containers.filter(container => container.State === 'running').length;
            const progressPercentage = totalServers > 0 ? (activeServers / totalServers) * 100 : 0;
            progressFillElement.style.width = `${progressPercentage}%`;
        }
        
        if (serverGrid) {
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
        }
    } catch (error) {
        console.error('Error fetching Docker data:', error);
    }
}

// Server status updates are now handled in the DOMContentLoaded event

// Server management functions
async function loadServers() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/servers`, {
            credentials: 'include'
        });
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
        await fetch(`${API_BASE_URL}/api/servers/${serverId}/start`, { 
            method: 'POST',
            credentials: 'include'
        });
        loadServers(); // Refresh the server list
    } catch (error) {
        console.error('Error starting server:', error);
    }
}

async function stopServer(serverId) {
    try {
        await fetch(`${API_BASE_URL}/api/servers/${serverId}/stop`, { 
            method: 'POST',
            credentials: 'include'
        });
        loadServers();
    } catch (error) {
        console.error('Error stopping server:', error);
    }
}

async function restartServer(serverId) {
    try {
        await fetch(`${API_BASE_URL}/api/servers/${serverId}/restart`, { 
            method: 'POST',
            credentials: 'include'
        });
        loadServers();
    } catch (error) {
        console.error('Error restarting server:', error);
    }
}

// User Management Functions
async function loadUsers() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/users`, {
            credentials: 'include'
        });
        if (!response.ok) {
            throw new Error('Failed to fetch users');
        }
        const users = await response.json();
        displayUsers(users);
        updateUserStats(users);
    } catch (error) {
        console.error('Error loading users:', error);
        showToast('Error loading users', 'error');
    }
}

function displayUsers(users) {
    const tableBody = document.getElementById('users-table-body');
    if (!tableBody) return;
    
    tableBody.innerHTML = '';
    
    users.forEach(user => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${user.username}</td>
            <td>${user.email}</td>
            <td>
                <span class="role-badge ${user.isAdmin ? 'admin' : 'user'}">
                    ${user.isAdmin ? 'Admin' : 'User'}
                </span>
            </td>
            <td>
                <span class="status-badge active">${user.status}</span>
            </td>
            <td>
                <div class="action-buttons">
                    <button class="button button-small" onclick="editUser('${user.username}')">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button class="button button-small button-danger" onclick="deleteUser('${user.username}')">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

function updateUserStats(users) {
    const totalUsers = users.length;
    const activeUsers = users.filter(user => user.status === 'active').length;
    
    const totalUsersElement = document.getElementById('total-users');
    const activeUsersElement = document.getElementById('active-users');
    
    if (totalUsersElement) totalUsersElement.textContent = totalUsers;
    if (activeUsersElement) activeUsersElement.textContent = activeUsers;
}

function addUser() {
    const username = prompt('Enter username:');
    if (!username) return;
    
    const email = prompt('Enter email:');
    if (!email) return;
    
    const password = prompt('Enter password:');
    if (!password) return;
    
    const isAdmin = confirm('Make this user an admin?');
    
    createUser({ username, email, password, isAdmin });
}

async function createUser(userData) {
    try {
        const response = await fetch(`${API_BASE_URL}/api/users`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify(userData)
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to create user');
        }
        
        const result = await response.json();
        showToast('User created successfully', 'success');
        loadUsers(); // Refresh the user list
    } catch (error) {
        console.error('Error creating user:', error);
        showToast(error.message, 'error');
    }
}

async function editUser(username) {
    const newEmail = prompt('Enter new email (leave empty to keep current):');
    if (newEmail === null) return; // User cancelled
    
    const isAdmin = confirm('Make this user an admin?');
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/users/${username}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({
                email: newEmail || undefined,
                isAdmin
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to update user');
        }
        
        showToast('User updated successfully', 'success');
        loadUsers(); // Refresh the user list
    } catch (error) {
        console.error('Error updating user:', error);
        showToast(error.message, 'error');
    }
}

async function deleteUser(username) {
    if (!confirm(`Are you sure you want to delete user "${username}"?`)) {
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/users/${username}`, {
            method: 'DELETE',
            credentials: 'include'
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to delete user');
        }
        
        showToast('User deleted successfully', 'success');
        loadUsers(); // Refresh the user list
    } catch (error) {
        console.error('Error deleting user:', error);
        showToast(error.message, 'error');
    }
}

// Session check function
async function checkSession() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/session`, {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            if (data.authenticated) {
                return data;
            }
        }
        return null;
    } catch (error) {
        console.error('Session check error:', error);
        return null;
    }
}

// Logout function
async function logout() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/logout`, {
            method: 'POST',
            credentials: 'include'
        });
        
        if (response.ok) {
            // Clear any local storage or session storage if needed
            localStorage.removeItem('user');
            sessionStorage.clear();
            
            // Redirect to login page
            window.location.href = '/login.html';
        } else {
            console.error('Logout failed');
            // Still redirect to login page even if logout fails
            window.location.href = '/login.html';
        }
    } catch (error) {
        console.error('Logout error:', error);
        // Redirect to login page even if there's an error
        window.location.href = '/login.html';
    }
}

// Toast notification function
function showToast(message, type = 'info') {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
        <div class="toast-content">
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        </div>
    `;
    
    // Add to page
    document.body.appendChild(toast);
    
    // Show toast
    setTimeout(() => toast.classList.add('show'), 100);
    
    // Remove toast after 3 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => document.body.removeChild(toast), 300);
    }, 3000);
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', async () => {
    // Check session first
    const session = await checkSession();
    if (!session) {
        // Not authenticated, redirect to login
        window.location.href = '/login.html';
        return;
    }
    
    if (window.location.pathname.includes('a_users.html')) {
        loadUsers();
        // Set up search functionality for users page
        const searchInput = document.querySelector('.search-bar input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                const searchTerm = e.target.value.toLowerCase();
                const rows = document.querySelectorAll('#users-table-body tr');
                rows.forEach(row => {
                    const username = row.cells[0].textContent.toLowerCase();
                    const email = row.cells[1].textContent.toLowerCase();
                    const role = row.cells[2].textContent.toLowerCase();
                    if (username.includes(searchTerm) || email.includes(searchTerm) || role.includes(searchTerm)) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                });
            });
        }
    } else {
        // Only run Docker/server code on non-users pages
        updateServerStatus();
        setInterval(updateServerStatus, 30000);
        loadServers();
        // Set up search functionality for servers page
        const searchInput = document.querySelector('.search-bar input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                // Implement search functionality here
            });
        }
    }
}); 