import { execSync } from 'child_process';
import Docker from 'dockerode';

console.log('Starting all servers...');

try {
    // Start each server synchronously
    console.log('Starting app server...');
    execSync('node .js/app.js 3000', { stdio: 'inherit' });
    
    console.log('Starting API server...');
    execSync('node .js/api-server.js 3001', { stdio: 'inherit' });
    
    console.log('Starting user handler...');
    execSync('node .js/userh.js 3002', { stdio: 'inherit' });
    
    console.log('Starting server handler...');
    execSync('node .js/serverh.js 3003', { stdio: 'inherit' });
    
    // Test Docker connection
    const docker = new Docker();
    docker.ping().then(() => {
        console.log('Successfully connected to Docker daemon');
        console.log('✅ Docker connection successful');
    });
} catch (error) {
    console.error('Error:', error.message);
    process.exit(1);
}