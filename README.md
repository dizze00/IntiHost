# IntiHost

IntiHost is a comprehensive server hosting management platform with user authentication, server management, and real-time monitoring capabilities.

## Features

### 🔐 Authentication System
- User registration and login with persistent sessions (30-day)
- Role-based access control (Admin/User)
- Secure password handling
- Session management with automatic logout

### 🖥️ Server Management
- Add, edit, and delete servers
- Real-time server status monitoring (Online/Offline)
- Server statistics and performance metrics
- Docker container management
- RCON console integration for Minecraft servers

### 👥 User Management
- Admin panel for user management
- Inline editing capabilities
- Role assignment and management
- User statistics and activity tracking

### 📊 Dashboard & Analytics
- Real-time server statistics
- User activity monitoring
- System performance metrics
- Interactive charts and graphs

### 🎨 Modern UI/UX
- Responsive design with smooth animations
- Toast notifications for user feedback
- Modal dialogs and popups
- Card-based layouts
- Custom dropdowns and form elements

## Project Structure

```
IntiHost/
├── api/
│   └── servers/
│       └── stats/          # Server statistics API
├── public/                 # Frontend assets
│   ├── admin/             # Admin panel pages
│   │   ├── a_dashboard.html
│   │   ├── a_requests.html
│   │   ├── a_secrets.html
│   │   ├── a_servers.html
│   │   ├── a_statistics.html
│   │   ├── a_users.html
│   │   └── a_userform.html
│   ├── dashboard.html     # User dashboard
│   ├── login.html         # Authentication
│   ├── signup.html        # User registration
│   ├── server_details.html # Server management
│   ├── servform.html      # Server creation form
│   ├── settings.html      # User settings
│   ├── admin.js           # Admin panel functionality
│   ├── styles.css         # Main stylesheet
│   └── animations.css     # Animation styles
├── api-server.js          # API server (port 3001)
├── app.js                 # Main application server (port 5005)
├── db.json               # Database file
└── package.json          # Dependencies and scripts
```

## Technologies Used

- **Backend**: Node.js, Express.js
- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Database**: JSON-based storage
- **Container Management**: Docker
- **Real-time Communication**: WebSocket-like polling
- **Authentication**: Session-based with persistent cookies

## Getting Started

### Prerequisites
- Node.js (v14 or higher)
- npm or yarn
- Docker (for server management)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/dizze00/IntiHost.git
   cd IntiHost
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start the servers**:
   ```bash
   # Start the main application server (port 5005)
   npm start
   
   # In a separate terminal, start the API server (port 3001)
   node api-server.js
   ```

4. **Access the application**:
   - Main application: http://localhost:5005
   - API server: http://localhost:3001

## Usage

### Authentication
1. Navigate to the signup page to create an account
2. Login with your credentials
3. Sessions persist for 30 days unless manually logged out

### User Dashboard
- View server statistics and performance metrics
- Monitor system resources
- Access server management tools

### Admin Panel
- **Dashboard**: Overview of all system metrics
- **Users**: Manage user accounts, roles, and permissions
- **Servers**: Add, edit, and monitor servers
- **Statistics**: Detailed analytics and reporting
- **Requests**: Handle user requests and support tickets
- **Secrets**: Manage sensitive configuration data

### Server Management
- **Add Servers**: Use the server form to add new servers
- **Monitor Status**: Real-time online/offline status
- **Console Access**: RCON integration for Minecraft servers
- **Statistics**: Performance metrics and resource usage

### User Management (Admin Only)
- **Inline Editing**: Click on user cards to edit information
- **Role Management**: Toggle between Admin and User roles
- **User Form**: Dedicated page for adding/editing users
- **Search & Filter**: Find users quickly with search functionality

## API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/signup` - User registration
- `POST /api/auth/logout` - User logout
- `GET /api/auth/session` - Check session status

### Users
- `GET /api/users` - Get all users
- `GET /api/users/:id` - Get specific user
- `POST /api/users` - Create new user
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user

### Servers
- `GET /api/servers` - Get all servers
- `GET /api/servers/:name` - Get specific server
- `POST /api/servers` - Create new server
- `PUT /api/servers/:name` - Update server
- `DELETE /api/servers/:name` - Delete server
- `POST /api/servers/:name/start` - Start server
- `POST /api/servers/:name/stop` - Stop server
- `POST /api/servers/:name/rcon` - Send RCON command

### Statistics
- `GET /api/stats` - Get system statistics
- `GET /api/servers/:name/stats` - Get server statistics

## Configuration

### Environment Variables
The application uses default configurations, but you can customize:
- Port numbers (default: 5005 for main app, 3001 for API)
- Session duration (default: 30 days)
- Database file location (default: db.json)

### Docker Integration
For Minecraft server management, ensure Docker is running and containers are properly configured with RCON enabled.

## Security Features

- Session-based authentication with secure cookies
- Role-based access control
- Input validation and sanitization
- CORS protection
- Secure password handling (no plain text storage)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support and questions, please open an issue on the GitHub repository or contact the development team.
