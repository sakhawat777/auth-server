const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const User = require('./models/User');
require('dotenv').config();
const bcrypt = require('bcrypt');

const app = express();
const PORT = process.env.PORT || 5000;

app.use(
	cors({
		origin: 'http://localhost:3000',
		credentials: true,
	})
);
app.use(express.json());

// MongoDB Connection
mongoose
	.connect(process.env.MONGO_URI, {
		useNewUrlParser: true,
		useUnifiedTopology: true,
	})
	.then(() => console.log('✅ Connected to MongoDB'))
	.catch((err) => {
		console.error('❌ MongoDB connection failed:', err.message);
	});

// 🔐 Sign In
app.post('/api/auth/signin', async (req, res) => {
	const { email, password } = req.body;

	if (!email || !password) {
		return res.status(400).json({ error: 'Email and password are required' });
	}

	try {
		const user = await User.findOne({ email });
		if (!user) {
			return res.status(401).json({ error: 'User not found' });
		}

		// Compare hashed password
		const isMatch = await bcrypt.compare(password, user.password);
		if (!isMatch) {
			return res.status(401).json({ error: 'Invalid password' });
		}

		// Return user (use carefully in production – exclude password)
		const { password: _, ...safeUser } = user.toObject();
		return res.status(200).json(safeUser);
	} catch (error) {
		console.error(error);
		return res.status(500).json({ error: 'Internal server error' });
	}
});

// 📝 Sign Up
app.post('/api/auth/signup', async (req, res) => {
	const { email, password } = req.body;

	try {
		const exists = await User.findOne({ email });
		if (exists) return res.status(409).json({ error: 'User already exists' });

		// Hash password
		const hashedPassword = await bcrypt.hash(password, 10);

		// Save user with hashed password
		await User.create({ email, password: hashedPassword });

		res.status(201).json({ message: 'User created successfully' });
	} catch (error) {
		console.error(error);
		res.status(500).json({ error: 'Internal server error' });
	}
});

app.get('/', (req, res) => {
	res.send('Auth API Running');
});

// Start server
app.listen(PORT, () => {
	console.log(`🚀 Server running on http://localhost:${PORT}`);
});
