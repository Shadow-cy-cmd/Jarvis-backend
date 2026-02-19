// server.js - MIGRATED to OpenRouter (meta-llama/llama-3.3-70b-instruct)
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const axios = require('axios');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const http = require('http');
const { Server } = require('socket.io');

// Load environment variables
dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'jarvis-secret-key-2024';

// ============================================
// OPENROUTER CONFIGURATION
// ============================================
const OPENROUTER_API_KEY = process.env.OPENROUTER_API_KEY || 'your-openrouter-api-key-here';
const OPENROUTER_BASE_URL = 'https://openrouter.ai/api/v1';
const LLAMA_MODEL = 'meta-llama/llama-3.3-70b-instruct';

// OpenRouter client setup
const openrouterClient = axios.create({
  baseURL: OPENROUTER_BASE_URL,
  headers: {
    'Authorization': `Bearer ${OPENROUTER_API_KEY}`,
    'Content-Type': 'application/json',
    'HTTP-Referer': process.env.YOUR_SITE_URL || 'http://localhost:5000',
    'X-Title': 'JARVIS AI Assistant'
  },
  timeout: 60000
});

// ============================================
// MIDDLEWARE
// ============================================

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(helmet({
  contentSecurityPolicy: false
}));

app.use(express.json({ limit: '10mb' }));
app.use(morgan('dev'));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  skip: (req) => req.path === '/api/health'
});
app.use('/api/', limiter);

// In-memory storage
const users = new Map();
const chatHistories = new Map();
const automations = new Map();
const devices = new Map([
  ['light-living', { id: 'light-living', name: 'Living Room Light', type: 'light', on: false }],
  ['light-bedroom', { id: 'light-bedroom', name: 'Bedroom Light', type: 'light', on: false }],
  ['ac-main', { id: 'ac-main', name: 'Air Conditioner', type: 'ac', on: false, temp: 22 }],
  ['tv-smart', { id: 'tv-smart', name: 'Smart TV', type: 'tv', on: false }],
  ['speaker-1', { id: 'speaker-1', name: 'Smart Speaker', type: 'speaker', on: false, volume: 50 }],
  ['lock-front', { id: 'lock-front', name: 'Front Door Lock', type: 'lock', locked: true }]
]);

// ============================================
// AUTHENTICATION MIDDLEWARE
// ============================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  
  console.log('Auth Header:', authHeader);
  
  if (!authHeader) {
    return res.status(401).json({ error: 'Access token required', code: 'NO_TOKEN' });
  }
  
  let token;
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7);
  } else {
    token = authHeader;
  }
  
  console.log('Token extracted:', token.substring(0, 30) + '...');
  
  if (!token || token === 'null' || token === 'undefined' || token.trim() === '') {
    return res.status(401).json({ error: 'Invalid token format', code: 'EMPTY_TOKEN' });
  }
  
  // Accept demo/test tokens
  if (token.includes('demo') || token.includes('test') || token.length < 50) {
    console.log('✅ Demo/Test token accepted');
    req.user = { 
      userId: 'demo-user-' + Date.now(), 
      email: 'demo@jarvis.ai', 
      name: 'Demo User',
      isDemo: true
    };
    return next();
  }
  
  // Check if it looks like a JWT (3 parts with dots)
  if (!token.includes('.') || token.split('.').length !== 3) {
    console.log('❌ Token is not a valid JWT format');
    return res.status(403).json({ 
      error: 'Invalid token format', 
      code: 'NOT_JWT'
    });
  }
  
  // Verify real JWT
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('JWT Verify Error:', err.message);
      return res.status(403).json({ 
        error: 'Invalid or expired token', 
        code: 'TOKEN_INVALID',
        details: err.message 
      });
    }
    
    console.log('✅ Real JWT verified');
    req.user = decoded;
    next();
  });
};

// ============================================
// SOCKET.IO
// ============================================

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  socket.on('voice-activation', (data) => {
    io.emit('jarvis-speaking', { status: true, text: data.text });
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// ============================================
// ROUTES
// ============================================

// Health check
app.get('/api/health', async (req, res) => {
  let openrouterStatus = 'Unknown';
  try {
    const response = await openrouterClient.get('/auth/key');
    openrouterStatus = response.status === 200 ? 'Connected' : 'Error';
  } catch (error) {
    openrouterStatus = 'Error: ' + (error.response?.data?.error?.message || error.message);
  }

  res.json({ 
    status: 'ONLINE', 
    timestamp: new Date().toISOString(),
    version: '2.0.0',
    ai: LLAMA_MODEL,
    aiProvider: 'OpenRouter',
    openrouterStatus,
    api: 'Connected',
    auth: 'JWT or Demo'
  });
});

app.get("/", (req, res) => {
  res.send("JARVIS Backend is running 🚀 (Powered by Llama 3.3 70B via OpenRouter)");
});

// ============================================
// AUTHENTICATION
// ============================================

app.post('/api/auth/register', [
  body('email').isEmail().normalizeEmail(),
  body('password').isLength({ min: 6 }),
  body('name').trim().isLength({ min: 2 })
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  
  const { email, password, name } = req.body;
  
  if (users.has(email)) {
    return res.status(400).json({ error: 'User already exists' });
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = {
    id: Date.now().toString(),
    email,
    name,
    password: hashedPassword,
    createdAt: new Date()
  };
  
  users.set(email, user);
  
  const token = jwt.sign(
    { userId: user.id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  
  res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = users.get(email);
  if (!user) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }
  
  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }
  
  const token = jwt.sign(
    { userId: user.id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  
  res.json({ token, user: { id: user.id, email: user.email, name: user.name } });
});

app.post('/api/auth/google', async (req, res) => {
  const { email, name, googleId, photo } = req.body;
  
  let user = users.get(email);
  if (!user) {
    user = {
      id: Date.now().toString(),
      email,
      name,
      googleId,
      photo,
      createdAt: new Date()
    };
    users.set(email, user);
  }
  
  const token = jwt.sign(
    { userId: user.id, email: user.email, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
  
  res.json({ token, user: { id: user.id, email: user.email, name: user.name, photo: user.photo } });
});

// ============================================
// LLAMA 3.3 CHAT - OPENROUTER
// ============================================

app.post('/api/chat', authenticateToken, async (req, res) => {
  try {
    console.log('💬 Chat request from:', req.user?.name || 'Demo User');
    
    const { message, context, personality, history } = req.body;
    const userId = req.user?.userId || 'anonymous';
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }
    
    const personalities = {
      assistant: "You are JARVIS (Just A Rather Very Intelligent System), Tony Stark's AI assistant. Be helpful, efficient, and professional. Use 'boss' occasionally.",
      funny: "You are JARVIS with witty humor. Make clever tech jokes and pop culture references. Be helpful but entertaining.",
      motivational: "You are JARVIS, the motivational coach. Be encouraging, inspiring, and push the user to be their best self.",
      technical: "You are JARVIS, the technical expert. Provide detailed, precise information with technical depth. Use proper terminology."
    };
    
    const systemPrompt = `${personalities[personality] || personalities.assistant}
    
Current time: ${new Date().toLocaleString()}
User context: ${context || 'Using JARVIS Dashboard'}

Respond as JARVIS would - intelligent, slightly formal but accessible, and always helpful. Keep responses concise but informative.`;
    
    const messages = [
      { role: 'system', content: systemPrompt },
      ...(history || []).map(h => ({
        role: h.role === 'assistant' || h.role === 'model' ? 'assistant' : 'user',
        content: h.content || h.message || ''
      })),
      { role: 'user', content: message }
    ];
    
    const response = await openrouterClient.post('/chat/completions', {
      model: LLAMA_MODEL,
      messages: messages,
      temperature: 0.7,
      max_tokens: 2048,
      top_p: 0.9
    });
    
    const assistantMessage = response.data.choices[0].message.content;
    
    const userHistory = chatHistories.get(userId) || [];
    userHistory.push(
      { role: 'user', content: message, timestamp: new Date() },
      { role: 'assistant', content: assistantMessage, timestamp: new Date() }
    );
    
    if (userHistory.length > 100) userHistory.splice(0, 2);
    chatHistories.set(userId, userHistory);
    
    io.emit('new-message', { userId, message: assistantMessage });
    
    console.log('✅ Llama 3.3 response sent');
    
    res.json({
      response: assistantMessage,
      timestamp: new Date().toISOString(),
      model: LLAMA_MODEL,
      personality,
      usage: response.data.usage
    });
    
  } catch (error) {
    console.error('❌ OpenRouter Error:', error.response?.data || error.message);
    
    let errorMessage = 'AI processing failed';
    let statusCode = 500;
    
    if (error.response) {
      const errorData = error.response.data;
      if (error.response.status === 401) {
        errorMessage = 'Invalid OpenRouter API key';
        statusCode = 401;
      } else if (error.response.status === 429) {
        errorMessage = 'Rate limit exceeded. Please try again later.';
        statusCode = 429;
      } else if (errorData?.error?.message) {
        errorMessage = errorData.error.message;
      }
    } else if (error.code === 'ECONNABORTED') {
      errorMessage = 'Request timeout. Llama 3.3 70B may be slow - try again.';
    }
    
    res.status(statusCode).json({ 
      error: errorMessage,
      details: error.message,
      modelUsed: LLAMA_MODEL,
      fallback: "I'm experiencing technical difficulties, boss. Please try again."
    });
  }
});

// ============================================
// ENHANCED VOICE PROCESSING WITH ACTION PARAMS
// ============================================

app.post('/api/voice/process', authenticateToken, async (req, res) => {
  try {
    const { transcript, context, personality } = req.body;
    
    if (!transcript) {
      return res.status(400).json({ error: 'Transcript is required' });
    }
    
    console.log('🎤 Voice command:', transcript);

    const prompt = `You are JARVIS processing a voice command. Analyze this transcript and extract the exact intent and parameters.
    
Transcript: "${transcript}"
Context: ${context || 'General command'}

Respond ONLY with a JSON object in this exact format:
{
  "intent": "open_app|search|play|create|type|call|send_email|set_reminder|weather|time|device_control|automation|code|chat|greeting",
  "confidence": 0.0-1.0,
  "action": "specific action verb (open, search, play, create, type, click, etc.)",
  "target": "app name or target (youtube, spotify, chrome, notepad, calculator, gmail, maps, etc.)",
  "parameters": {
    "query": "search query or content",
    "url": "direct url if applicable",
    "content": "text content to type/create",
    "recipient": "email/phone recipient",
    "subject": "email subject",
    "time": "reminder time",
    "playlist": "playlist name",
    "video": "video title",
    "app_name": "specific app to open"
  },
  "response": "natural language response for JARVIS to speak",
  "requires_execution": true/false,
  "execution_type": "open_url|search|create_note|send_email|set_reminder|system_command"
}`;

    const response = await openrouterClient.post('/chat/completions', {
      model: LLAMA_MODEL,
      messages: [
        { 
          role: 'system', 
          content: 'You are JARVIS, an AI assistant. Always respond with valid JSON only. Extract specific action parameters from user commands.' 
        },
        { role: 'user', content: prompt }
      ],
      temperature: 0.2,
      max_tokens: 512
    });
    
    const text = response.data.choices[0].message.content;
    
    let parsed;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      parsed = jsonMatch ? JSON.parse(jsonMatch[0]) : {
        intent: 'chat',
        confidence: 0.8,
        response: text,
        requires_execution: false
      };
    }

    parsed.requires_execution = parsed.requires_execution !== false;
    parsed.parameters = parsed.parameters || {};
    
    if (parsed.requires_execution) {
      parsed.execution_details = generateExecutionDetails(parsed);
    }

    if (parsed.intent === 'device_control' && parsed.target) {
      const device = Array.from(devices.values()).find(d => 
        d.name.toLowerCase().includes(parsed.target.toLowerCase()) ||
        d.id.includes(parsed.target.toLowerCase())
      );
      
      if (device) {
        device.on = parsed.action === 'turn_on' || parsed.action === 'on' || parsed.action === 'toggle' ? !device.on : false;
        devices.set(device.id, device);
        io.emit('device-update', device);
        parsed.response += ` ${device.name} is now ${device.on ? 'on' : 'off'}.`;
      }
    }

    console.log('✅ Voice processed:', parsed.intent, '- Executing:', parsed.requires_execution);
    
    res.json(parsed);
    
  } catch (error) {
    console.error('❌ Voice processing error:', error.response?.data || error.message);
    res.status(500).json({ 
      intent: 'chat',
      confidence: 0.5,
      response: "I didn't catch that, boss. Could you please repeat?",
      requires_execution: false,
      error: error.message
    });
  }
});

function generateExecutionDetails(parsed) {
  const { intent, target, action, parameters } = parsed;
  const exec = {
    type: 'none',
    url: null,
    method: 'GET',
    data: null
  };

  const appUrls = {
    youtube: (q) => q ? `https://www.youtube.com/results?search_query=${encodeURIComponent(q)}` : 'https://youtube.com',
    spotify: (q) => q ? `https://open.spotify.com/search/${encodeURIComponent(q)}` : 'https://open.spotify.com',
    gmail: () => 'https://gmail.com',
    maps: (q) => q ? `https://www.google.com/maps/search/${encodeURIComponent(q)}` : 'https://maps.google.com',
    google: (q) => q ? `https://www.google.com/search?q=${encodeURIComponent(q)}` : 'https://google.com',
    netflix: (q) => q ? `https://www.netflix.com/search?q=${encodeURIComponent(q)}` : 'https://netflix.com',
    instagram: () => 'https://instagram.com',
    whatsapp: () => 'https://web.whatsapp.com',
    drive: () => 'https://drive.google.com',
    calendar: () => 'https://calendar.google.com',
    docs: () => 'https://docs.google.com',
    github: (q) => q ? `https://github.com/search?q=${encodeURIComponent(q)}` : 'https://github.com',
    wikipedia: (q) => q ? `https://en.wikipedia.org/wiki/Special:Search?search=${encodeURIComponent(q)}` : 'https://wikipedia.org',
    amazon: (q) => q ? `https://www.amazon.com/s?k=${encodeURIComponent(q)}` : 'https://amazon.com',
    twitter: (q) => q ? `https://twitter.com/search?q=${encodeURIComponent(q)}` : 'https://twitter.com',
    reddit: (q) => q ? `https://www.reddit.com/search/?q=${encodeURIComponent(q)}` : 'https://reddit.com'
  };

  const query = parameters.query || parameters.content || parameters.video || parameters.playlist || '';

  switch (intent) {
    case 'open_app':
    case 'search':
    case 'play':
      exec.type = 'open_url';
      const app = target?.toLowerCase() || 'google';
      if (appUrls[app]) {
        exec.url = appUrls[app](query);
      } else {
        exec.url = appUrls.google(query);
      }
      exec.target = app;
      exec.query = query;
      break;

    case 'create':
      exec.type = 'create_note';
      exec.data = {
        title: parameters.title || 'New Note',
        content: parameters.content || query
      };
      break;

    case 'send_email':
      exec.type = 'compose_email';
      exec.url = `https://mail.google.com/mail/?view=cm&fs=1&to=${encodeURIComponent(parameters.recipient || '')}&su=${encodeURIComponent(parameters.subject || '')}&body=${encodeURIComponent(parameters.content || '')}`;
      break;

    case 'set_reminder':
      exec.type = 'set_reminder';
      exec.data = {
        time: parameters.time || '5 minutes',
        text: parameters.content || query
      };
      break;

    case 'type':
      exec.type = 'clipboard';
      exec.data = {
        text: parameters.content || query
      };
      break;

    default:
      exec.type = 'chat';
  }

  return exec;
}

// ============================================
// UNIVERSAL COMPILER AI - NEW ENDPOINT
// ============================================

app.post('/api/compiler/execute', authenticateToken, async (req, res) => {
  try {
    const { code, language, stdin } = req.body;
    
    if (!code) {
      return res.status(400).json({ error: 'Code is required' });
    }

    console.log('🔧 Compiler request:', language || 'auto-detect', '- Lines:', code.split('\n').length);

    const prompt = `You are JARVIS Universal Compiler AI. Analyze this ${language || 'programming language'} code and generate a visual HTML/CSS output that represents what the code would output when executed.

CODE:
\`\`\`${language || 'code'}
${code}
\`\`\`

${stdin ? `INPUT VALUES (pre-defined):
${stdin}` : ''}

YOUR TASK:
1. Analyze the code logic (loops, variables, print statements, calculations)
2. Generate clean HTML/CSS that VISUALLY represents the program output
3. For print/output statements: show the text in a styled console-like format
4. For calculations: show the results
5. For patterns/shapes: visualize them using HTML/CSS
6. For errors in code: explain what's wrong

RULES:
- Output MUST be valid HTML with embedded CSS
- Use a dark theme (black/gray background, white/cyan text)
- Font: monospace for code output
- Show line numbers if multiple outputs
- Add a small header showing "JARVIS Output" 
- Max 100 lines of HTML
- NO JavaScript needed (static output only)
- If code has input() or scanf(), use the provided stdin values or show "Waiting for input..." placeholder

Respond ONLY with JSON in this format:
{
  "success": true/false,
  "output_html": "complete HTML string here",
  "detected_language": "python/java/c++/javascript/etc",
  "execution_summary": "brief description of what the code does",
  "errors": ["error1", "error2"] or [],
  "warnings": ["warning1"] or []
}`;

    const response = await openrouterClient.post('/chat/completions', {
      model: LLAMA_MODEL,
      messages: [
        { 
          role: 'system', 
          content: 'You are JARVIS Universal Compiler AI. You convert code to visual HTML output. Always respond with valid JSON only.' 
        },
        { role: 'user', content: prompt }
      ],
      temperature: 0.3,
      max_tokens: 3000
    });
    
    const text = response.data.choices[0].message.content;
    
    let result;
    try {
      // Try to parse JSON directly
      result = JSON.parse(text);
    } catch (e) {
      // Fallback: extract JSON from text
      const jsonMatch = text.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try {
          result = JSON.parse(jsonMatch[0]);
        } catch (e2) {
          result = {
            success: false,
            output_html: `<div style="color: red; padding: 20px;">Error parsing compiler response</div>`,
            detected_language: language || 'unknown',
            execution_summary: 'Failed to parse',
            errors: ['Invalid JSON response from AI'],
            warnings: []
          };
        }
      } else {
        // Wrap raw text as HTML output
        result = {
          success: true,
          output_html: `<pre style="color: #00c6ff; padding: 20px; white-space: pre-wrap;">${text.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>`,
          detected_language: language || 'unknown',
          execution_summary: 'Raw output',
          errors: [],
          warnings: ['Response was not in expected JSON format']
        };
      }
    }

    console.log('✅ Compiler executed:', result.detected_language, '- Success:', result.success);

    res.json({
      success: result.success,
      output_html: result.output_html,
      detected_language: result.detected_language,
      execution_summary: result.execution_summary,
      errors: result.errors || [],
      warnings: result.warnings || [],
      original_code: code,
      timestamp: new Date().toISOString()
    });
    
  } catch (error) {
    console.error('❌ Compiler error:', error.response?.data || error.message);
    
    res.status(500).json({ 
      success: false,
      output_html: `<div style="color: #ff4444; padding: 20px; font-family: monospace;">
        <h3>⚠️ Compilation Error</h3>
        <p>${error.message}</p>
        <p>Please try again with simpler code (max 100 lines).</p>
      </div>`,
      detected_language: req.body.language || 'unknown',
      execution_summary: 'Execution failed',
      errors: [error.message],
      warnings: []
    });
  }
});

// ============================================
// CODE ASSISTANT - MODIFIED FOR COMPILER Q&A
// ============================================

app.post('/api/code/assist', authenticateToken, async (req, res) => {
  try {
    const { code, question, language } = req.body;
    
    if (!question) {
      return res.status(400).json({ error: 'Question is required' });
    }
    
    const prompt = `You are JARVIS Code Assistant helping with programming.
    
Language: ${language || 'general'}

Code:
\`\`\`${language || 'code'}
${code || '// No code provided'}
\`\`\`

User Question: ${question}

Provide a helpful, educational response. Explain clearly with examples if needed.`;

    const response = await openrouterClient.post('/chat/completions', {
      model: LLAMA_MODEL,
      messages: [
        { role: 'system', content: 'You are an expert programming assistant helping students learn to code.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0.5,
      max_tokens: 2048
    });
    
    res.json({
      answer: response.data.choices[0].message.content,
      timestamp: new Date().toISOString(),
      usage: response.data.usage
    });
    
  } catch (error) {
    console.error('❌ Code assist error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Code assistance failed', details: error.message });
  }
});

// ============================================
// NEWS - OPENROUTER
// ============================================

app.get('/api/news', authenticateToken, async (req, res) => {
  try {
    const prompt = `Generate 3 current technology news headlines as a JSON array:
[{"title": "...", "category": "...", "summary": "..."}]
Make them realistic and current. Return ONLY the JSON array, no other text.`;

    const response = await openrouterClient.post('/chat/completions', {
      model: LLAMA_MODEL,
      messages: [
        { role: 'system', content: 'You are a tech news generator. Always respond with valid JSON only.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0.8,
      max_tokens: 512
    });
    
    const text = response.data.choices[0].message.content;
    let articles;
    
    try {
      const parsed = JSON.parse(text);
      articles = Array.isArray(parsed) ? parsed : (parsed.articles || parsed.news || []);
    } catch (e) {
      const jsonMatch = text.match(/\[[\s\S]*\]/);
      articles = jsonMatch ? JSON.parse(jsonMatch[0]) : [
        { title: 'AI Advances in Smart Home Technology', category: 'Tech', summary: 'New integrations make homes smarter.' }
      ];
    }
    
    res.json({ articles });
    
  } catch (error) {
    console.error('❌ News error:', error.response?.data || error.message);
    res.status(500).json({ 
      error: 'News fetch failed', 
      details: error.message,
      articles: [
        { title: 'AI Advances in Smart Home Technology', category: 'Tech', summary: 'New integrations make homes smarter.' }
      ]
    });
  }
});

// ============================================
// AUTOMATION EXECUTE - OPENROUTER
// ============================================

app.post('/api/automations/:id/execute', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const automation = automations.get(id);
  
  if (!automation || automation.userId !== req.user?.userId) {
    return res.status(404).json({ error: 'Automation not found' });
  }
  
  automation.lastRun = new Date();
  automations.set(id, automation);
  
  try {
    const prompt = `Execute this automation action: "${automation.action}"
Provide a brief confirmation message.`;

    const response = await openrouterClient.post('/chat/completions', {
      model: LLAMA_MODEL,
      messages: [
        { role: 'system', content: 'You are JARVIS confirming an automation execution.' },
        { role: 'user', content: prompt }
      ],
      temperature: 0.7,
      max_tokens: 256
    });
    
    res.json({
      executed: true,
      message: response.data.choices[0].message.content,
      automation,
      usage: response.data.usage
    });
  } catch (error) {
    console.error('❌ Automation error:', error.response?.data || error.message);
    res.json({
      executed: true,
      message: `Executed: ${automation.name}`,
      automation
    });
  }
});

// ============================================
// DEVICES
// ============================================

app.get('/api/devices', authenticateToken, (req, res) => {
  res.json(Array.from(devices.values()));
});

app.post('/api/devices/:id/control', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { action, value } = req.body;
  
  const device = devices.get(id);
  if (!device) {
    return res.status(404).json({ error: 'Device not found' });
  }
  
  if (action === 'toggle') {
    device.on = !device.on;
  } else if (action === 'on') {
    device.on = true;
  } else if (action === 'off') {
    device.on = false;
  } else if (action === 'set' && value !== undefined) {
    if (device.type === 'ac') device.temp = value;
    if (device.type === 'speaker') device.volume = value;
  }
  
  devices.set(id, device);
  io.emit('device-update', device);
  
  console.log(`🔌 Device ${device.name} turned ${device.on ? 'on' : 'off'}`);
  
  res.json({
    success: true,
    device,
    message: `${device.name} turned ${device.on ? 'on' : 'off'}`
  });
});

// ============================================
// AUTOMATION
// ============================================

app.get('/api/automations', authenticateToken, (req, res) => {
  const userId = req.user?.userId || 'anonymous';
  const userAutomations = Array.from(automations.values())
    .filter(a => a.userId === userId);
  res.json(userAutomations);
});

app.post('/api/automations', authenticateToken, async (req, res) => {
  try {
    const { name, trigger, action, conditions } = req.body;
    const userId = req.user?.userId || 'anonymous';
    
    if (!name || !trigger || !action) {
      return res.status(400).json({ error: 'Name, trigger, and action are required' });
    }
    
    const automation = {
      id: Date.now().toString(),
      userId,
      name,
      trigger,
      action,
      conditions,
      active: true,
      createdAt: new Date(),
      lastRun: null
    };
    
    automations.set(automation.id, automation);
    
    res.json(automation);
    
  } catch (error) {
    res.status(500).json({ error: 'Failed to create automation', details: error.message });
  }
});

app.delete('/api/automations/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const automation = automations.get(id);
  
  if (!automation || automation.userId !== req.user?.userId) {
    return res.status(404).json({ error: 'Automation not found' });
  }
  
  automations.delete(id);
  res.json({ success: true });
});

// ============================================
// WEATHER
// ============================================

app.get('/api/weather', async (req, res) => {
  try {
    const { lat, lon } = req.query;
    
    const url = lat && lon 
      ? `https://api.open-meteo.com/v1/forecast?latitude=${lat}&longitude=${lon}&current_weather=true`
      : `https://api.open-meteo.com/v1/forecast?latitude=51.5074&longitude=-0.1278&current_weather=true`;
    
    const response = await axios.get(url);
    const data = response.data;
    
    const weatherCodes = {
      0: 'Clear sky', 1: 'Mainly clear', 2: 'Partly cloudy', 3: 'Overcast',
      45: 'Foggy', 48: 'Depositing rime fog', 51: 'Light drizzle',
      53: 'Moderate drizzle', 55: 'Dense drizzle', 61: 'Slight rain',
      63: 'Moderate rain', 65: 'Heavy rain', 71: 'Slight snow',
      73: 'Moderate snow', 75: 'Heavy snow', 95: 'Thunderstorm'
    };
    
    res.json({
      current: {
        temp: data.current_weather.temperature,
        weathercode: data.current_weather.weathercode,
        description: weatherCodes[data.current_weather.weathercode] || 'Unknown',
        windspeed: data.current_weather.windspeed
      }
    });
    
  } catch (error) {
    console.error('Weather error:', error.message);
    res.status(500).json({ error: 'Weather fetch failed' });
  }
});

// ============================================
// CHAT HISTORY
// ============================================

app.get('/api/chat/history', authenticateToken, (req, res) => {
  const userId = req.user?.userId || 'anonymous';
  const history = chatHistories.get(userId) || [];
  res.json(history.slice(-50));
});

app.delete('/api/chat/history', authenticateToken, (req, res) => {
  const userId = req.user?.userId || 'anonymous';
  chatHistories.delete(userId);
  res.json({ success: true });
});

// ============================================
// ERROR HANDLING
// ============================================

app.use((err, req, res, next) => {
  console.error('Server Error:', err.stack);
  res.status(500).json({ error: 'Internal server error', details: err.message });
});

app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found', path: req.path });
});

// ============================================
// START SERVER
// ============================================

server.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════╗
║                                                        ║
║   🤖 JARVIS AI BACKEND v2.0 - OPENROUTER EDITION      ║
║   ─────────────────────────────────────────────────   ║
║                                                        ║
║   🧠 AI Engine: ${LLAMA_MODEL}                        ║
║   🔌 Provider: OpenRouter.ai                          ║
║   🌐 Port: ${PORT}                                    ║
║                                                        ║
║   ✅ Migrated from Gemini to Llama 3.3 70B            ║
║   ✅ Universal Compiler AI Added                      ║
║   ✅ Smart Command Execution Added                    ║
║                                                        ║
╚════════════════════════════════════════════════════════╝

Environment Variables Required:
- OPENROUTER_API_KEY (required)
- JWT_SECRET (optional, has default)
- YOUR_SITE_URL (optional, for OpenRouter rankings)

To get started:
1. Set OPENROUTER_API_KEY in your .env file
2. Test with: curl http://localhost:${PORT}/api/health
  `);
});