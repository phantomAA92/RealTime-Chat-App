const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
const server = http.createServer(app);

// Enable CORS
app.use(cors({
  origin: 'http://localhost:3000',
  credentials: true
}));

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = 'public/uploads/';
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const mimetype = filetypes.test(file.mimetype);
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    
    if (mimetype && extname) {
      return cb(null, true);
    }
    cb(new Error('Only image files are allowed!'));
  }
});

app.use(express.json());
app.use(express.static('public'));

const io = new Server(server, {
  cors: {
    origin: "http://localhost:3000",
    methods: ["GET", "POST"]
  }
});

const JWT_SECRET = 'your_jwt_secret_key';
const SALT_ROUNDS = 10;

// In-memory database
const usersDB = {};
const messagesDB = [];
const privateMessagesDB = {};

// Middleware to verify JWT
const authenticateJWT = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = decoded;
    next();
  });
};

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Authentication error'));

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return next(new Error('Authentication error'));
    socket.user = decoded;
    next();
  });
});

io.on('connection', (socket) => {
  console.log('User connected:', socket.user.username);

  // Initialize user in DB if not exists
  if (!usersDB[socket.user.username]) {
    usersDB[socket.user.username] = {
      username: socket.user.username,
      online: false,
      socketId: null,
      profileImage: null
    };
  }

  // Update user status
  usersDB[socket.user.username].online = true;
  usersDB[socket.user.username].socketId = socket.id;
  
  // Notify all users about new connection
  io.emit('userList', Object.values(usersDB));

  // Send initial messages
  socket.emit('initialMessages', messagesDB);
  
  if (privateMessagesDB[socket.user.username]) {
    socket.emit('initialPrivateMessages', privateMessagesDB[socket.user.username]);
  }

  // Handle group messages
  socket.on('chatMessage', (msg) => {
    const message = {
      id: Date.now().toString(),
      user: socket.user.username,
      text: msg.text,
      timestamp: new Date().toISOString(),
      type: 'text',
      ...(msg.image && { image: msg.image, type: 'image' })
    };
    
    messagesDB.push(message);
    io.emit('message', message);
  });

  // Handle private messages
  socket.on('privateMessage', ({ to, message: msg }, callback) => {
    const recipient = usersDB[to];
    
    if (!recipient) {
      return callback({ error: 'User not found' });
    }

    const privateMsg = {
      id: Date.now().toString(),
      from: socket.user.username,
      to: to,
      text: msg.text,
      type: msg.type || 'text',
      timestamp: new Date().toISOString(),
      ...(msg.image && { image: msg.image, type: 'image' })
    };

    // Store message for both users
    if (!privateMessagesDB[socket.user.username]) {
      privateMessagesDB[socket.user.username] = [];
    }
    if (!privateMessagesDB[to]) {
      privateMessagesDB[to] = [];
    }
    
    privateMessagesDB[socket.user.username].push(privateMsg);
    privateMessagesDB[to].push(privateMsg);

    // Send to recipient if online
    if (recipient.online && recipient.socketId) {
      io.to(recipient.socketId).emit('privateMessage', privateMsg);
    }
    
    // Send to sender
    callback({ success: true, message: privateMsg });
  });

  // Handle message deletion
  socket.on('deleteMessage', ({ messageId, isPrivate }, callback) => {
    if (isPrivate) {
      // Delete private message
      let deleted = false;
      for (const user in privateMessagesDB) {
        privateMessagesDB[user] = privateMessagesDB[user].filter(msg => {
          if (msg.id === messageId) {
            // Only allow deletion if sender is the current user
            if (msg.from === socket.user.username) {
              deleted = true;
              return false;
            }
          }
          return true;
        });
      }
      
      if (deleted) {
        // Notify both users
        io.emit('messageDeleted', { messageId, isPrivate: true });
        callback({ success: true });
      } else {
        callback({ error: 'Message not found or unauthorized' });
      }
    } else {
      // Delete group message
      const index = messagesDB.findIndex(msg => msg.id === messageId);
      if (index !== -1 && messagesDB[index].user === socket.user.username) {
        messagesDB.splice(index, 1);
        io.emit('messageDeleted', { messageId, isPrivate: false });
        callback({ success: true });
      } else {
        callback({ error: 'Message not found or unauthorized' });
      }
    }
  });

  // Handle disconnection
  socket.on('disconnect', () => {
    console.log('User disconnected:', socket.user.username);
    if (usersDB[socket.user.username]) {
      usersDB[socket.user.username].online = false;
      usersDB[socket.user.username].socketId = null;
      io.emit('userList', Object.values(usersDB));
    }
  });
});

// Register endpoint
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  if (usersDB[username]) {
    return res.status(400).json({ error: 'Username already exists' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    
    usersDB[username] = {
      username,
      password: hashedPassword,
      profileImage: null,
      online: false,
      socketId: null
    };
    
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    
    res.json({ 
      success: true,
      token,
      username,
      profileImage: null
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  
  const user = usersDB[username];
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  try {
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '1h' });
    
    res.json({ 
      success: true,
      token,
      username,
      profileImage: user.profileImage
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Profile image upload endpoint
app.post('/upload-profile', authenticateJWT, upload.single('profileImage'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const username = req.user.username;
  const profileImagePath = '/uploads/' + req.file.filename;

  // Update user profile
  if (!usersDB[username]) {
    usersDB[username] = { username };
  }
  usersDB[username].profileImage = profileImagePath;

  // Notify all clients about the profile change
  io.emit('userList', Object.values(usersDB));

  res.json({ 
    success: true,
    profileImage: profileImagePath
  });
});

// Get users endpoint
app.get('/users', authenticateJWT, (req, res) => {
  const currentUser = req.user.username;
  const users = Object.values(usersDB)
    .filter(user => user.username !== currentUser)
    .map(user => ({
      username: user.username,
      profileImage: user.profileImage,
      online: user.online || false
    }));
  
  res.json({ success: true, users });
});

// Search users endpoint
app.get('/search-users', authenticateJWT, (req, res) => {
  const query = req.query.query?.toLowerCase() || '';
  const currentUser = req.user.username;
  
  const users = Object.values(usersDB)
    .filter(user => 
      user.username !== currentUser && 
      user.username.toLowerCase().includes(query)
    )
    .map(user => ({
      username: user.username,
      profileImage: user.profileImage,
      online: user.online || false
    }));
  
  res.json({ success: true, users });
});

server.listen(3001, () => {
  console.log('Server running on port 3001');
});
