import 'dotenv/config';
import express, { NextFunction, Request, Response } from 'express';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import OpenAI from 'openai';
import { ChatCompletionMessageParam } from 'openai/resources';

const app = express();

app.use(bodyParser.json());

const JWT_SECRET = process.env.JWT_SECRET!;
console.log(JWT_SECRET);

const MONGODB_URL = process.env.MONGODB_URL!;
mongoose.connect(MONGODB_URL);

mongoose.connection.on('connected', () => {
	console.log('Connected to MongoDB');
});

const userSchema = new mongoose.Schema({
	email: { type: String, required: true, unique: true },
	password: { type: String, required: true },
	created_at: { type: Date, required: true, default: Date.now },
});

const User = mongoose.model('User', userSchema);

const chatSessionSchema = new mongoose.Schema({
	user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
	messages: [
		{
			role: { type: String, required: true },
			content: { type: String, required: true },
			timestamp: { type: Date, required: true, default: Date.now },
		},
	],
});
const ChatSession = mongoose.model('ChatSession', chatSessionSchema);

const OPENAI_API_KEY = process.env.OPENAI_API_KEY!;
console.log(OPENAI_API_KEY);
const openai = new OpenAI({
	apiKey: OPENAI_API_KEY,
});

app.post('/chat', async (req: Request, res: Response) => {
	const { userId, message } = req.body;
	let sessionId = req.body.sessionId ?? null;

	try {
		let messagesPayload;
		if (sessionId) {
			const chatSession = await ChatSession.findOne({ _id: sessionId });
			if (!chatSession || chatSession.messages.length === 0) {
				//TODO: create new chat session and send new sessionId in response
				messagesPayload = [{ role: 'user', content: message }];
			} else {
				messagesPayload = chatSession.messages.map((msg) => {
					return {
						role: msg.role,
						content: msg.content,
					};
				});
				messagesPayload.push({ role: 'user', content: message });
			}
		} else {
			messagesPayload = [{ role: 'user', content: message }];
		}

		const botResponse = await openai.chat.completions.create({
			model: 'gpt-3.5-turbo',
			messages: messagesPayload as ChatCompletionMessageParam[],
		});
		const botMessage = botResponse.choices[0].message.content;

		//TODO: Append chat history to chat session in DB

		res.json({ sessionId, role: 'assistant', content: botMessage, timestamp: new Date() });
	} catch (error) {
		res.status(500).json({ error: 'Internal server error' });
	}
});

app.post('/register', async (req, res) => {
	const { email, password } = req.body;

	try {
		const existingUser = await User.findOne({ email });
		if (existingUser) {
			return res.status(400).json({ message: 'User already exists.' });
		}

		const hashedPassword = await bcrypt.hash(password, 10);

		const user = new User({
			email,
			password: hashedPassword,
		});

		await user.save();

		res.status(201).json({ message: 'User registered successfully.' });
	} catch (error) {
		res.status(500).json({ error });
	}
});

app.post('/login', async (req, res) => {
	const { email, password } = req.body;

	try {
		const user = await User.findOne({ email });
		if (!user) {
			return res.status(400).json({ message: 'Invalid credentials.' });
		}

		const isPasswordValid = await bcrypt.compare(password, user.password);
		if (!isPasswordValid) {
			return res.status(400).json({ message: 'Invalid credentials.' });
		}

		//TODO: check sub vs user._id
		const token = jwt.sign({ sub: user._id }, JWT_SECRET, { expiresIn: '12h' });

		res.json({ token });
	} catch (error) {
		res.status(500).json({ error });
	}
});

app.get('/me', AuthGuardJWT, async (req, res) => {
	//@ts-ignore
	return req.user;
});

function AuthGuardJWT(req: Request, res: Response, next: NextFunction) {
	const authHeader = req.headers.authorization;
	if (!authHeader) return res.status(401).send({ message: 'Unauthorized' });

	try {
		const token = authHeader.split(' ')[1];
		const decoded = jwt.verify(token, JWT_SECRET);

		jwt.verify(token, JWT_SECRET, (err, decoded) => {
			if (err || !decoded) {
				return res.status(401).send({ message: 'Unauthorized' });
			}
			User.findOne({ _id: decoded.sub }).then((user) => {
				if (!user) return res.status(401).send({ message: 'Unauthorized' });
				//@ts-ignore
				req.user = user;
				next();
			});
		});
	} catch (err) {
		res.status(401).send({ message: 'Unauthorized' });
	}
}

app.listen(3000, () => {
	console.log('Server started on port 3000');
});
