// Main JavaScript file
const API_BASE = window.location.hostname === 'localhost' 
    ? 'http://localhost:3001' 
    : '';

// Application state
let state = {
    user: null,
    token: null,
    currentChat: null,
    language: 'en',
    model: 'deepseek'
};

// Initialize app
async function initApp() {
    await checkAuth();
    setupEventListeners();
    loadUI();
}

// ... rest of JavaScript code
