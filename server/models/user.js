const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
    username: {
        type: String,
        unique: true,
        sparse: true,
        trim: true,
        minlength: 3,
        maxlength: 30
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    password: {
        type: String,
        minlength: 6
    },
    googleId: {
        type: String,
        unique: true,
        sparse: true
    },
    displayName: {
        type: String,
        trim: true
    },
    avatar: {
        type: String
    },
    language: {
        type: String,
        default: 'en',
        enum: ['en', 'si']
    },
    provider: {
        type: String,
        default: 'local',
        enum: ['local', 'google']
    },
    apiPreferences: {
        defaultModel: {
            type: String,
            default: 'deepseek',
            enum: ['deepseek', 'chatgpt']
        },
        chatgptModel: {
            type: String,
            default: 'gpt-3.5-turbo',
            enum: ['gpt-3.5-turbo', 'gpt-4', 'gpt-4-turbo']
        }
    },
    isActive: {
        type: Boolean,
        default: true
    },
    lastLogin: {
        type: Date
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    updatedAt: {
        type: Date,
        default: Date.now
    }
}, {
    timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password') || !this.password) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    if (!this.password) return false;
    return await bcrypt.compare(candidatePassword, this.password);
};

// Virtual for user initials
userSchema.virtual('initials').get(function() {
    if (this.displayName) {
        return this.displayName.split(' ').map(n => n[0]).join('').toUpperCase();
    }
    if (this.username) {
        return this.username.charAt(0).toUpperCase();
    }
    return 'U';
});

// Method to get public profile
userSchema.methods.toPublicProfile = function() {
    const userObject = this.toObject();
    delete userObject.password;
    delete userObject.googleId;
    delete userObject.__v;
    return userObject;
};

const User = mongoose.model('User', userSchema);

module.exports = User;
