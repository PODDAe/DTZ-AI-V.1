const Chat = require('../models/Chat');
const { processDeepSeekChat, processChatGPTChat } = require('../services/chatService');
const { translateText } = require('../utils/translate');

exports.chat = async (req, res) => {
    try {
        const { message, language = 'en', sessionId, model } = req.body;
        const userId = req.user._id;

        // Validate input
        if (!message || message.trim().length === 0) {
            return res.status(400).json({ error: 'Message is required' });
        }

        // Translate if needed
        let translatedMessage = message;
        if (language !== 'en') {
            translatedMessage = await translateText(message, 'en');
        }

        let aiResponse;
        let usedModel = model || req.user.apiPreferences.defaultModel;

        // Process based on selected model
        if (usedModel === 'deepseek') {
            aiResponse = await processDeepSeekChat(translatedMessage);
        } else {
            const chatgptModel = req.user.apiPreferences.chatgptModel || 'gpt-3.5-turbo';
            aiResponse = await processChatGPTChat(translatedMessage, chatgptModel, sessionId, userId);
        }

        // Translate back if needed
        if (language !== 'en') {
            aiResponse = await translateText(aiResponse, language);
        }

        // Save to chat history
        const chat = await saveChatMessage(userId, sessionId, message, aiResponse, usedModel, language);

        res.json({
            response: aiResponse,
            model: usedModel,
            sessionId: chat.sessionId,
            timestamp: new Date()
        });

    } catch (error) {
        console.error('Chat error:', error);
        res.status(500).json({ 
            error: 'Failed to process chat request',
            message: error.message 
        });
    }
};

exports.getChatHistory = async (req, res) => {
    try {
        const chats = await Chat.find({ userId: req.user._id })
            .sort({ updatedAt: -1 })
            .select('sessionId title model createdAt updatedAt')
            .limit(50);

        res.json({ chats });
    } catch (error) {
        console.error('Get chat history error:', error);
        res.status(500).json({ error: 'Failed to fetch chat history' });
    }
};

exports.getChatSession = async (req, res) => {
    try {
        const chat = await Chat.findOne({
            sessionId: req.params.sessionId,
            userId: req.user._id
        });

        if (!chat) {
            return res.status(404).json({ error: 'Chat not found' });
        }

        res.json({ chat });
    } catch (error) {
        console.error('Get chat session error:', error);
        res.status(500).json({ error: 'Failed to fetch chat session' });
    }
};

exports.deleteChatSession = async (req, res) => {
    try {
        await Chat.findOneAndDelete({
            sessionId: req.params.sessionId,
            userId: req.user._id
        });

        res.json({ message: 'Chat deleted successfully' });
    } catch (error) {
        console.error('Delete chat error:', error);
        res.status(500).json({ error: 'Failed to delete chat' });
    }
};

// Helper function
async function saveChatMessage(userId, sessionId, userMessage, aiResponse, model, language) {
    let chat;
    
    if (sessionId) {
        chat = await Chat.findOne({ sessionId, userId });
    }

    if (!chat) {
        chat = new Chat({
            userId,
            sessionId: sessionId || `${model}_${Date.now()}`,
            title: userMessage.substring(0, 50) + (userMessage.length > 50 ? '...' : ''),
            model,
            messages: []
        });
    }

    chat.messages.push({
        role: 'user',
        content: userMessage,
        language,
        model
    });

    chat.messages.push({
        role: 'assistant',
        content: aiResponse,
        language,
        model
    });

    chat.updatedAt = new Date();
    await chat.save();

    return chat;
}
