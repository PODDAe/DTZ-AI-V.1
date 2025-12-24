const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { OpenAI } = require('openai');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const socketIo = require('socket.io');
const http = require('http');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Session
app.use(session({
    secret: process.env.SESSION_SECRET || 'your-session-secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000
    }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Initialize OpenAI with YOUR API KEY
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY // YOUR KEY HERE
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/ai-platform', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true, sparse: true },
    email: { type: String, unique: true, required: true },
    password: { type: String },
    googleId: { type: String, unique: true, sparse: true },
    displayName: { type: String },
    avatar: { type: String },
    language: { type: String, default: 'en' },
    provider: { type: String, default: 'local' },
    apiPreferences: {
        defaultModel: { type: String, default: 'deepseek' },
        chatgptModel: { type: String, default: 'gpt-3.5-turbo' }
    },
    createdAt: { type: Date, default: Date.now },
    lastLogin: { type: Date }
});

const User = mongoose.model('User', userSchema);

// Chat History Schema
const chatSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sessionId: { type: String, required: true },
    messages: [{
        role: { type: String, enum: ['user', 'assistant', 'system'], required: true },
        content: { type: String, required: true },
        language: { type: String, default: 'en' },
        timestamp: { type: Date, default: Date.now },
        model: { type: String, default: 'deepseek' }
    }],
    title: { type: String },
    model: { type: String, default: 'deepseek' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const Chat = mongoose.model('Chat', chatSchema);

// Configure Google OAuth
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3001/api/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ googleId: profile.id });
        
        if (!user) {
            user = await User.findOne({ email: profile.emails[0].value });
            
            if (user) {
                user.googleId = profile.id;
                user.provider = 'google';
            } else {
                user = new User({
                    googleId: profile.id,
                    email: profile.emails[0].value,
                    displayName: profile.displayName,
                    username: profile.emails[0].value.split('@')[0],
                    avatar: profile.photos[0]?.value,
                    provider: 'google',
                    language: 'en'
                });
            }
        }
        
        user.lastLogin = new Date();
        await user.save();
        
        return done(null, user);
    } catch (error) {
        return done(error, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error, null);
    }
});

// Authentication Middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Translation function
const translateText = async (text, targetLang) => {
    if (targetLang === 'en') return text;
    
    const translations = {
        'si': {
            'hello': 'හෙලෝ',
            'hi': 'ආයුබෝවන්',
            'how are you': 'ඔබට කෙසේද',
            'thank you': 'ස්තුතියි',
            'please': 'කරුණාකර',
            'yes': 'ඔව්',
            'no': 'නැත',
            'good morning': 'සුභ උදෑසනක්',
            'good night': 'සුභ රාත්‍රියක්',
            'what is your name': 'ඔබගේ නම කුමක්ද',
            'my name is': 'මගේ නම',
            'help': 'උදව්',
            'sorry': 'සමාවන්න',
            'welcome': 'ආයුබෝවන්',
            'goodbye': 'ආයුබෝවන්'
        }
    };

    const lowerText = text.toLowerCase();
    if (translations[targetLang] && translations[targetLang][lowerText]) {
        return translations[targetLang][lowerText];
    }

    return text;
};

// Routes
app.get('/', (req, res) => {
    res.json({ 
        message: 'AI Platform API is running!',
        apis: {
            deepseek: 'Active',
            chatgpt: 'Active',
            google_oauth: process.env.GOOGLE_CLIENT_ID ? 'Configured' : 'Not configured'
        }
    });
});

// Google OAuth Routes
app.get('/api/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/api/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        const token = jwt.sign(
            { 
                userId: req.user._id, 
                username: req.user.username,
                email: req.user.email,
                provider: req.user.provider 
            },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );
        
        const redirectUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/auth/callback?token=${token}`;
        res.redirect(redirectUrl);
    }
);

// Register
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password, language } = req.body;

        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new User({
            username,
            email,
            password: hashedPassword,
            language: language || 'en',
            provider: 'local'
        });

        await user.save();

        const token = jwt.sign(
            { 
                userId: user._id, 
                username: user.username,
                email: user.email,
                provider: user.provider 
            },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );

        res.status(201).json({
            message: 'User created successfully',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                language: user.language,
                provider: user.provider,
                apiPreferences: user.apiPreferences
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await User.findOne({ email, provider: 'local' });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        user.lastLogin = new Date();
        await user.save();

        const token = jwt.sign(
            { 
                userId: user._id, 
                username: user.username,
                email: user.email,
                provider: user.provider 
            },
            process.env.JWT_SECRET || 'your-secret-key',
            { expiresIn: '7d' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                language: user.language,
                provider: user.provider,
                apiPreferences: user.apiPreferences
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Profile
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ user });
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Update Profile
app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const { language, apiPreferences } = req.body;
        const updateData = {};
        
        if (language) updateData.language = language;
        if (apiPreferences) updateData.apiPreferences = apiPreferences;
        
        const user = await User.findByIdAndUpdate(
            req.user.userId,
            updateData,
            { new: true }
        ).select('-password');
        
        res.json({ message: 'Profile updated', user });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// DEEPSEEK CHAT WITH YOUR API KEY
app.post('/api/deepseek/chat', authenticateToken, async (req, res) => {
    try {
        const { message, language = 'en', sessionId } = req.body;
        const userId = req.user.userId;

        // Translate if needed
        let translatedMessage = message;
        if (language !== 'en') {
            translatedMessage = await translateText(message, 'en');
        }

        // USING YOUR DEEPSEEK API KEY
        const response = await fetch('https://api.deepseek.com/chat/completions', {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${process.env.DEEPSEEK_API_KEY}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'deepseek-chat',
                messages: [{ role: 'user', content: translatedMessage }],
                max_tokens: 1024,
                stream: false
            })
        });

        const data = await response.json();
        let aiResponse = data.choices?.[0]?.message?.content || 'No response from DeepSeek';

        // Translate back if needed
        if (language !== 'en') {
            aiResponse = await translateText(aiResponse, language);
        }

        // Save chat
        await saveChatMessage(userId, sessionId, message, aiResponse, 'deepseek', language);

        res.json({
            response: aiResponse,
            usage: data.usage,
            model: 'deepseek',
            sessionId: sessionId || `deepseek_${Date.now()}`
        });
    } catch (error) {
        console.error('DeepSeek Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// CHATGPT CHAT WITH YOUR API KEY
app.post('/api/chatgpt/chat', authenticateToken, async (req, res) => {
    try {
        const { message, language = 'en', sessionId, model = 'gpt-3.5-turbo' } = req.body;
        const userId = req.user.userId;

        // Translate if needed
        let translatedMessage = message;
        if (language !== 'en') {
            translatedMessage = await translateText(message, 'en');
        }

        // Get chat history
        let chatHistory = [];
        if (sessionId) {
            const existingChat = await Chat.findOne({ sessionId, userId });
            if (existingChat) {
                chatHistory = existingChat.messages.map(msg => ({
                    role: msg.role,
                    content: msg.content
                })).slice(-10);
            }
        }

        // Prepare messages
        const messages = [
            {
                role: 'system',
                content: `You are a helpful AI assistant. ${language === 'si' ? 'You can understand and respond in Sinhala when asked.' : 'Respond in English unless asked otherwise.'}`
            },
            ...chatHistory,
            {
                role: 'user',
                content: translatedMessage
            }
        ];

        // USING YOUR CHATGPT API KEY
        const completion = await openai.chat.completions.create({
            model: model,
            messages: messages,
            max_tokens: 1000,
            temperature: 0.7
        });

        let aiResponse = completion.choices[0].message.content;

        // Translate back if needed
        if (language !== 'en') {
            aiResponse = await translateText(aiResponse, language);
        }

        // Save chat
        await saveChatMessage(userId, sessionId, message, aiResponse, model, language);

        res.json({
            response: aiResponse,
            usage: completion.usage,
            model: model,
            sessionId: sessionId || `chatgpt_${Date.now()}`
        });
    } catch (error) {
        console.error('ChatGPT Error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Unified Chat
app.post('/api/chat', authenticateToken, async (req, res) => {
    try {
        const { message, language = 'en', sessionId, model: requestedModel } = req.body;
        const userId = req.user.userId;

        const user = await User.findById(userId);
        const defaultModel = requestedModel || user.apiPreferences?.defaultModel || 'deepseek';

        if (defaultModel === 'chatgpt') {
            const chatgptModel = user.apiPreferences?.chatgptModel || 'gpt-3.5-turbo';
            req.body.model = chatgptModel;
            
            // Translate if needed
            let translatedMessage = message;
            if (language !== 'en') {
                translatedMessage = await translateText(message, 'en');
            }

            // Get chat history
            let chatHistory = [];
            if (sessionId) {
                const existingChat = await Chat.findOne({ sessionId, userId });
                if (existingChat) {
                    chatHistory = existingChat.messages.map(msg => ({
                        role: msg.role,
                        content: msg.content
                    })).slice(-10);
                }
            }

            const messages = [
                {
                    role: 'system',
                    content: `You are a helpful AI assistant. Respond in ${language === 'si' ? 'Sinhala when asked, otherwise English' : 'English'}.`
                },
                ...chatHistory,
                { role: 'user', content: translatedMessage }
            ];

            // USING YOUR CHATGPT API KEY
            const completion = await openai.chat.completions.create({
                model: chatgptModel,
                messages: messages,
                max_tokens: 1000,
                temperature: 0.7
            });

            let aiResponse = completion.choices[0].message.content;

            // Translate if needed
            if (language !== 'en') {
                aiResponse = await translateText(aiResponse, language);
            }

            // Save chat
            await saveChatMessage(userId, sessionId, message, aiResponse, chatgptModel, language);

            res.json({
                response: aiResponse,
                usage: completion.usage,
                model: chatgptModel,
                sessionId: sessionId || `chatgpt_${Date.now()}`
            });
        } else {
            // USING YOUR DEEPSEEK API KEY
            const response = await fetch('https://api.deepseek.com/chat/completions', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${process.env.DEEPSEEK_API_KEY}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    model: 'deepseek-chat',
                    messages: [{ role: 'user', content: message }],
                    max_tokens: 1024,
                    stream: false
                })
            });

            const data = await response.json();
            let aiResponse = data.choices?.[0]?.message?.content || 'No response';

            // Translate if needed
            if (language !== 'en') {
                aiResponse = await translateText(aiResponse, language);
            }

            // Save chat
            await saveChatMessage(userId, sessionId, message, aiResponse, 'deepseek', language);

            res.json({
                response: aiResponse,
                usage: data.usage,
                model: 'deepseek',
                sessionId: sessionId || `deepseek_${Date.now()}`
            });
        }
    } catch (error) {
        console.error('Chat error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Voice Processing
app.post('/api/voice/process', authenticateToken, async (req, res) => {
    try {
        const { text, language = 'en', action = 'tts' } = req.body;
        
        if (action === 'stt') {
            res.json({
                text: text || "Voice input received",
                language
            });
        } else if (action === 'tts') {
            res.json({
                audioUrl: null,
                text: text,
                language,
                message: "Text-to-speech simulation"
            });
        }
    } catch (error) {
        console.error('Voice processing error:', error);
        res.status(500).json({ error: error.message });
    }
});

// Chat History
app.get('/api/chats', authenticateToken, async (req, res) => {
    try {
        const chats = await Chat.find({ userId: req.user.userId })
            .sort({ updatedAt: -1 })
            .select('sessionId title model createdAt updatedAt messages')
            .limit(50);
        
        res.json({ chats });
    } catch (error) {
        console.error('Get chats error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/chats/:sessionId', authenticateToken, async (req, res) => {
    try {
        const chat = await Chat.findOne({
            sessionId: req.params.sessionId,
            userId: req.user.userId
        });
        
        if (!chat) {
            return res.status(404).json({ error: 'Chat not found' });
        }
        
        res.json({ chat });
    } catch (error) {
        console.error('Get chat error:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/chats/:sessionId', authenticateToken, async (req, res) => {
    try {
        await Chat.findOneAndDelete({
            sessionId: req.params.sessionId,
            userId: req.user.userId
        });
        
        res.json({ message: 'Chat deleted successfully' });
    } catch (error) {
        console.error('Delete chat error:', error);
        res.status(500).json({ error: error.message });
    }
});

// API Status
app.get('/api/status', (req, res) => {
    res.json({
        deepseek: {
            available: !!process.env.DEEPSEEK_API_KEY,
            message: process.env.DEEPSEEK_API_KEY ? 'API Key configured ✓' : 'API Key missing'
        },
        chatgpt: {
            available: !!process.env.OPENAI_API_KEY,
            message: process.env.OPENAI_API_KEY ? 'API Key configured ✓' : 'API Key missing'
        },
        google_oauth: {
            available: !!process.env.GOOGLE_CLIENT_ID,
            message: process.env.GOOGLE_CLIENT_ID ? 'OAuth configured ✓' : 'OAuth not configured'
        },
        mongodb: {
            available: mongoose.connection.readyState === 1,
            message: mongoose.connection.readyState === 1 ? 'Connected ✓' : 'Disconnected'
        }
    });
});

// Helper function to save chat
async function saveChatMessage(userId, sessionId, userMessage, aiResponse, model, language) {
    let chat;
    if (sessionId) {
        chat = await Chat.findOne({ sessionId, userId });
    }

    if (!chat) {
        chat = new Chat({
            userId,
            sessionId: sessionId || `${model}_${Date.now()}`,
            title: userMessage.substring(0, 50) + '...',
            model: model,
            messages: []
        });
    }

    chat.messages.push({
        role: 'user',
        content: userMessage,
        language,
        model: model
    });

    chat.messages.push({
        role: 'assistant',
        content: aiResponse,
        language,
        model: model
    });

    chat.updatedAt = new Date();
    await chat.save();
}

// WebSocket
io.on('connection', (socket) => {
    console.log('New client connected');
    
    socket.on('join-chat', (sessionId) => {
        socket.join(sessionId);
    });
    
    socket.on('typing', ({ sessionId, isTyping }) => {
        socket.to(sessionId).emit('user-typing', { isTyping });
    });
    
    socket.on('disconnect', () => {
        console.log('Client disconnected');
    });
});

server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔑 DeepSeek API: ${process.env.DEEPSEEK_API_KEY ? 'Configured ✓' : 'Missing ✗'}`);
    console.log(`🤖 ChatGPT API: ${process.env.OPENAI_API_KEY ? 'Configured ✓' : 'Missing ✗'}`);
    console.log(`🔐 Google OAuth: ${process.env.GOOGLE_CLIENT_ID ? 'Configured ✓' : 'Missing ✗'}`);
    console.log(`🗄️  MongoDB: ${mongoose.connection.readyState === 1 ? 'Connected ✓' : 'Disconnected ✗'}`);
    console.log(`🌐 Frontend: ${process.env.FRONTEND_URL || 'http://localhost:3000'}`);
});
