// Chat functionality
class Chat {
    constructor() {
        this.socket = io('http://localhost:3003'); // User Handler port
        this.conversations = new Map();
        this.currentChat = null;
    }

    // Initialize chat
    init() {
        this.socket.on('connect', () => {
            console.log('Connected to chat server');
        });

        this.socket.on('message', (data) => {
            this.handleNewMessage(data);
        });

        this.socket.on('chat-created', (chatData) => {
            this.addConversation(chatData);
        });
    }

    // Create a new chat
    async createChat(usernames) {
        try {
            const response = await fetch(`${serverUrls.user}/chat/create`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ usernames })
            });
            
            if (!response.ok) throw new Error('Failed to create chat');
            
            const chatData = await response.json();
            this.addConversation(chatData);
            return chatData;
        } catch (error) {
            console.error('Error creating chat:', error);
            throw error;
        }
    }

    // Send message
    sendMessage(chatId, message) {
        this.socket.emit('message', {
            chatId,
            message,
            timestamp: new Date().toISOString()
        });
    }

    // Handle incoming message
    handleNewMessage(data) {
        const { chatId, message, sender, timestamp } = data;
        if (this.conversations.has(chatId)) {
            const chat = this.conversations.get(chatId);
            chat.messages.push({ sender, message, timestamp });
            this.updateChatUI(chatId);
        }
    }

    // Update chat UI
    updateChatUI(chatId) {
        if (chatId === this.currentChat) {
            const chatContainer = document.getElementById('chat-messages');
            const chat = this.conversations.get(chatId);
            
            chatContainer.innerHTML = chat.messages.map(msg => `
                <div class="message ${msg.sender === currentUser ? 'sent' : 'received'}">
                    <span class="sender">${msg.sender}</span>
                    <p>${msg.message}</p>
                    <span class="timestamp">${new Date(msg.timestamp).toLocaleTimeString()}</span>
                </div>
            `).join('');
            
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }
    }
}