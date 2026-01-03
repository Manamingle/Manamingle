// server.js — PRODUCTION READY FOR manamingle.site
const MAX_USERS = 300; // Maximum concurrent users
const MAX_QUEUE_SIZE = 100; // Maximum users in queue
const RATE_LIMIT_WINDOW = 60000; // 1 minute in milliseconds
const RATE_LIMIT_MAX = 100; // Max requests per window

const express = require("express");
const http = require("http");
const cors = require("cors");
const path = require("path");
const helmet = require("helmet");
const { Server } = require("socket.io");
const fs = require("fs").promises;
const rateLimit = require("express-rate-limit");
const compression = require("compression");
require("dotenv").config(); // Load environment variables

const app = express();

/* ================= CONFIG ================= */
const PORT = process.env.PORT || 3000;
const HOST = "0.0.0.0";
const NODE_ENV = process.env.NODE_ENV || "development";
const DOMAIN = process.env.DOMAIN || "manamingle.site";

// Admin credentials from environment variables
const ADMIN_CREDENTIALS = {
  username: process.env.ADMIN_USER || "admin",
  password: process.env.ADMIN_PASS || "ChangeMe123!",
  adminKey: process.env.ADMIN_KEY || "secure-admin-key-2024"
};

// Validate required environment variables
if (NODE_ENV === "production") {
  const requiredVars = ["ADMIN_USER", "ADMIN_PASS", "ADMIN_KEY"];
  for (const varName of requiredVars) {
    if (!process.env[varName]) {
      console.error(`❌ ERROR: ${varName} is required in production!`);
      process.exit(1);
    }
  }
}

/* ================= PATHS ================= */
const publicPath = path.join(__dirname, "public");
const logsPath = path.join(__dirname, "logs");

/* ================= LOGGING SETUP ================= */
async function setupLogging() {
  try {
    await fs.mkdir(logsPath, { recursive: true });
    console.log("✅ Logs directory ready");
  } catch (error) {
    console.error("❌ Failed to create logs directory:", error);
  }
}

async function logToFile(filename, data) {
  try {
    const logFile = path.join(logsPath, filename);
    const timestamp = new Date().toISOString();
    const logEntry = `${timestamp} - ${JSON.stringify(data)}\n`;
    await fs.appendFile(logFile, logEntry);
  } catch (error) {
    console.error("Failed to write log:", error);
  }
}

/* ================= MIDDLEWARE ================= */
// Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.socket.io"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", "wss:", "ws:", "https:"],
      imgSrc: ["'self'", "data:", "https:"],
    }
  },
  crossOriginEmbedderPolicy: false,
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));


// Rate limiting for API endpoints
const apiLimiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW,
  max: RATE_LIMIT_MAX,
  message: { error: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

// CORS configuration
const corsOptions = {
  origin: NODE_ENV === "production" 
    ? [`https://${DOMAIN}`, `https://www.${DOMAIN}`]
    : true,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
};

app.use(cors(corsOptions));
app.use(compression()); // Enable gzip compression
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));
app.use(express.static(publicPath, { 
  maxAge: NODE_ENV === "production" ? "1d" : "0",
  setHeaders: (res, path) => {
    if (path.endsWith(".html")) {
      res.setHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    }
  }
}));

/* ================= ADMIN AUTH MIDDLEWARE ================= */
function authenticateAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Authentication required" });
  }
  
  const token = authHeader.substring(7);
  if (token !== ADMIN_CREDENTIALS.adminKey) {
    return res.status(403).json({ error: "Invalid admin key" });
  }
  
  next();
}

/* ================= ROUTES ================= */
// Health check endpoint
app.get("/health", (req, res) => {
  const memoryUsage = process.memoryUsage();
  res.json({
    status: "healthy",
    uptime: process.uptime(),
    timestamp: Date.now(),
    memory: {
      heapUsed: Math.round(memoryUsage.heapUsed / 1024 / 1024) + "MB",
      heapTotal: Math.round(memoryUsage.heapTotal / 1024 / 1024) + "MB",
      rss: Math.round(memoryUsage.rss / 1024 / 1024) + "MB"
    },
    connections: state.users.size,
    environment: NODE_ENV
  });
});

// Admin panel (protected)
app.get("/admin", authenticateAdmin, (req, res) => {
  res.sendFile(path.join(publicPath, "admin.html"));
});


app.post("/admin/login", apiLimiter, (req, res) => {

  const { username, password } = req.body;

  if (username === ADMIN_CREDENTIALS.username && 
      password === ADMIN_CREDENTIALS.password) {
    res.json({ 
      success: true, 
      token: ADMIN_CREDENTIALS.adminKey,
      expiresIn: "24h"
    });
  } else {
    res.status(401).json({ 
      success: false, 
      error: "Invalid credentials" 
    });
  }
});

// Admin API endpoints (protected)
app.get("/admin/stats", authenticateAdmin, (req, res) => {
  res.json(getPublicStateForAdmin());
});

app.post("/admin/ban", authenticateAdmin, apiLimiter, (req, res) => {
  const { type, value, reason } = req.body;
  
  if (!type || !value) {
    return res.status(400).json({ error: "Missing type or value" });
  }
  
  switch (type) {
    case "user":
      state.blockedUsers.add(value);
      break;
    case "ip":
      state.blockedIPs.add(value);
      break;
    case "token":
      state.blockedTokens.add(value);
      break;
    default:
      return res.status(400).json({ error: "Invalid ban type" });
  }
  
  logAdminAction(req.ip, "BAN_ADDED", { type, value, reason });
  res.json({ success: true, message: `Banned ${type}: ${value}` });
});

app.delete("/admin/ban/:type/:value", authenticateAdmin, (req, res) => {
  const { type, value } = req.params;
  
  switch (type) {
    case "user":
      state.blockedUsers.delete(value);
      break;
    case "ip":
      state.blockedIPs.delete(value);
      break;
    case "token":
      state.blockedTokens.delete(value);
      break;
    default:
      return res.status(400).json({ error: "Invalid ban type" });
  }
  
  logAdminAction(req.ip, "BAN_REMOVED", { type, value });
  res.json({ success: true, message: `Unbanned ${type}: ${value}` });
});

// Main page
app.get("/", (req, res) => {
  res.sendFile(path.join(publicPath, "manamingle.html"));
});

// 404 handler
app.use((req, res) => {
  res.status(404).sendFile(path.join(publicPath, "404.html"));
});

// Error handler
app.use((err, req, res, next) => {
  console.error("Server error:", err);
  res.status(500).json({ 
    error: NODE_ENV === "production" ? "Internal server error" : err.message 
  });
});

/* ================= SERVER SETUP ================= */
const server = http.createServer(app);

const io = new Server(server, {
  transports: ["websocket", "polling"],
  pingInterval: 25000,
  pingTimeout: 20000,
  connectTimeout: 30000,
  maxHttpBufferSize: 1e6, // 1MB max message size
  cors: corsOptions,
  allowEIO3: true,
  serveClient: false
});

/* ================= GLOBAL STATE ================= */
const state = {
  waiting: {
    text: new Map(),
    video: new Map(),
    audio: new Map(),
    group_text: new Map(),
    group_video: new Map()
  },
  
  rooms: new Map(),
  users: new Map(),
  reports: [],
  
  blockedUsers: new Set(),
  blockedIPs: new Set(),
  blockedTokens: new Set(),
  
  admins: new Set(),
  securityLogs: [],
  
  // Rate limiting per socket
  socketRateLimits: new Map(),
  
  // Queue system for when server is full
  connectionQueue: []
};

// Room size limits (as per your requirements)
const ROOM_MAX_SIZE = {
  text: 2,
  video: 2,
  audio: 2,
  group_text: 6,    // Group text chat: 6 users
  group_video: 4    // Group video chat: 4 users
};

// Room timeout configurations (in milliseconds)
const ROOM_TIMEOUTS = {
  text: 30 * 60 * 1000,      // 30 minutes
  video: 60 * 60 * 1000,     // 1 hour
  audio: 60 * 60 * 1000,     // 1 hour
  group_text: 120 * 60 * 1000, // 2 hours
  group_video: 90 * 60 * 1000  // 1.5 hours
};

/* ================= HELPER FUNCTIONS ================= */
function generateRoomId() {
  return `room_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

function generateUserId() {
  return `usr_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`;
}

function getUserIP(socket) {
  const forwardedFor = socket.handshake.headers['x-forwarded-for'];
  return forwardedFor 
    ? forwardedFor.split(',')[0].trim() 
    : socket.handshake.address;
}

function isRateLimited(socketId, type = "message") {
  const now = Date.now();
  const userLimits = state.socketRateLimits.get(socketId) || {};
  
  if (!userLimits[type]) {
    userLimits[type] = { count: 1, firstRequest: now };
    state.socketRateLimits.set(socketId, userLimits);
    return false;
  }
  
  const limit = userLimits[type];
  
  // Reset if window has passed
  if (now - limit.firstRequest > 60000) { // 1 minute window
    limit.count = 1;
    limit.firstRequest = now;
    return false;
  }
  
  // Check limits based on type
  const maxRequests = {
    message: 60, // 60 messages per minute
    join: 10,
    skip: 20,
    signal: 200
  };
  
  
  limit.count++;
  
  if (limit.count > (maxRequests[type] || 30)) {
    logSecurityEvent('RATE_LIMIT_EXCEEDED', { socketId, type, count: limit.count });
    return true;
  }
  
  return false;
}

function logSecurityEvent(event, details = {}) {
  const log = {
    timestamp: Date.now(),
    event,
    ...details,
    environment: NODE_ENV
  };
  
  state.securityLogs.unshift(log);
  
  // Keep only last 2000 logs in memory
  if (state.securityLogs.length > 2000) {
    state.securityLogs.pop();
  }
  
  // Log to file in production
  if (NODE_ENV === "production") {
    logToFile("security.log", log);
  }
  
  console.log(`🔒 ${event}`, Object.keys(details).length > 0 ? details : "");
}

function logAdminAction(adminId, action, details = {}) {
  const log = {
    timestamp: Date.now(),
    adminId,
    action,
    ...details
  };
  
  console.log(`👮 ADMIN: ${action} by ${adminId}`);
  
  // Emit to all admins
  io.to('admins').emit('admin-action-log', log);
  
  // Log to file
  logToFile("admin.log", log);
}

function isUserBlocked(userId, ip, token) {
  if (state.blockedUsers.has(userId)) return true;
  if (state.blockedIPs.has(ip)) return true;
  if (token && state.blockedTokens.has(token)) return true;
  return false;
}

function hasCommonInterest(userTags = [], roomTags = []) {
  if (!userTags.length || !roomTags.length) return false;
  const roomTagSet = new Set(roomTags.map(t => t.toLowerCase()));
  return userTags.some(tag => roomTagSet.has(tag.toLowerCase()));
}

function findMatchForUser(selfSocketId, mode, userTags = []) {
  const waitingUsers = Array.from(state.waiting[mode].entries());
  
  if (waitingUsers.length === 0) {
    return null;
  }
  
  // For group modes, we need to find/create a group
  
  
  // For 1-on-1 modes (text, video, audio)
  // FIRST: Try to find interest match (fast priority)
  let bestInterestMatch = null;
  let bestInterestScore = -1;
  
  // SECOND: Fallback to random match
  let randomMatch = null;
  
  for (const [socketId, userData] of waitingUsers) {
    if (socketId === selfSocketId) continue;
    
    // Calculate tag similarity for interest matching
    if (userTags.length > 0 && userData.tags && userData.tags.length > 0) {
      const userTagSet = new Set(userTags.map(t => t.toLowerCase()));
      const otherTagSet = new Set(userData.tags.map(t => t.toLowerCase()));
      
      let matchScore = 0;
      const commonTags = [];
      
      for (const tag of userTagSet) {
        if (otherTagSet.has(tag)) {
          matchScore += 2;
          commonTags.push(tag);
        }
      }
      
      // Found interest match - prioritize this
      if (matchScore > 0 && matchScore > bestInterestScore) {
        bestInterestScore = matchScore;
        bestInterestMatch = { 
          socketId, 
          userData: { ...userData, commonTags },
          matchScore 
        };
      }
    }
    
    // Also collect random match candidates
    if (!randomMatch) {
      randomMatch = { socketId, userData };
    }
  }
  
  // Return interest match if found, otherwise random match
  if (bestInterestMatch && bestInterestScore > 0) {
    return bestInterestMatch;
  }
  
  // Return random match if available
  if (randomMatch) {
    return randomMatch;
  }
  
  // Last resort: pick any waiting user
  if (waitingUsers.length > 1) {
    const randomIndex = Math.floor(Math.random() * waitingUsers.length);
    const randomUser = waitingUsers[randomIndex];
    if (randomUser[0] !== selfSocketId) {
      return { socketId: randomUser[0], userData: randomUser[1] };
    }
  }
  
  return null;
}

function findGroupForUser(selfSocketId, mode, userTags = []) {

  // 1️⃣ First: try to find an existing active group with space
  for (const [roomId, room] of state.rooms) {
    if (
      room.mode === mode &&
      room.status === "active" &&
      !room.isBanned &&
      room.users.size < ROOM_MAX_SIZE[mode]
    ) {
      // Optional interest matching
      if (
        userTags.length === 0 ||
        hasCommonInterest(userTags, room.tags || [])
      ) {
        return { roomId, room };
      }
    }
  }

  // 2️⃣ No group found → CREATE A NEW GROUP WITH THIS USER ONLY
  return {
    newGroup: true,
    members: [] // 👈 empty means group starts with 1 user
  };
}


function createRoom(mode, creatorSocketId, creatorData, ...otherUsers) {
  const roomId = generateRoomId();
  const allUsers = [{ socketId: creatorSocketId, data: creatorData }, ...otherUsers];
  
  // Collect all tags
  const allTags = [];
  const allTokens = [];
  const participants = [];
  
  for (const user of allUsers) {
    allTags.push(...(user.data.tags || []));
    if (user.data.token) allTokens.push(user.data.token);
    
    participants.push({
      id: user.socketId,
      userId: user.data.id,
      name: user.data.name || 'Anonymous',
      tags: user.data.tags || [],
      joinedAt: Date.now()
    });
  }
  
  const roomTags = [...new Set(allTags)];
  
  state.rooms.set(roomId, {
    id: roomId,
    mode: mode,
    users: new Set(allUsers.map(u => u.socketId)),
    participants: participants,
    tags: roomTags,
    tokens: allTokens,
    createdAt: Date.now(),
    lastActivity: Date.now(),
    status: "active",
    isBanned: false,
    timeout: setTimeout(() => {
      // Auto-end room after timeout
      endRoom(roomId, "timeout");
    }, ROOM_TIMEOUTS[mode] || 3600000)
  });
  
  return roomId;
}

function addUserToRoom(socketId, roomId, userData) {
  const room = state.rooms.get(roomId);
  if (!room) return false;
  
  // Check room capacity
  const maxSize = ROOM_MAX_SIZE[room.mode];
  if (room.users.size >= maxSize) {
    return false;
  }
  
  room.users.add(socketId);
  room.participants.push({
    id: socketId,
    userId: userData.id,
    name: userData.name || 'Anonymous',
    tags: userData.tags || [],
    joinedAt: Date.now()
  });
  
  if (userData.token) room.tokens.push(userData.token);
  
  // Update last activity
  room.lastActivity = Date.now();
  
  return true;
}

function removeUserFromRoom(socketId, roomId, reason = "left") {
  const room = state.rooms.get(roomId);
  if (!room) return false;
  
  room.users.delete(socketId);
  
  // Remove participant
  const participantIndex = room.participants.findIndex(p => p.id === socketId);
  if (participantIndex !== -1) {
    room.participants.splice(participantIndex, 1);
  }
  
  // Update room status based on remaining users
  if (room.users.size === 0) {
    endRoom(roomId, reason);
  } else if (room.mode.startsWith('group_') && room.users.size === 1) {
    // If group has only 1 user left, notify them
    const remainingUser = Array.from(room.users)[0];
    const remainingSocket = io.sockets.sockets.get(remainingUser);
    if (remainingSocket) {
      remainingSocket.emit("group-emptying", { roomId });
    }
  }
  
  // Update last activity
  room.lastActivity = Date.now();
  
  return true;
}

function endRoom(roomId, reason = "ended") {
  const room = state.rooms.get(roomId);
  if (!room) return;
  
  // Clear timeout
  if (room.timeout) {
    clearTimeout(room.timeout);
  }
  
  room.status = 'ended';
  room.endedAt = Date.now();
  room.endReason = reason;
  setTimeout(() => {
    state.rooms.delete(roomId);
  }, 1000);
  
  // Notify all users in room
  const roomSockets = io.in(roomId);
  roomSockets.emit("room-ended", { reason, roomId });
  
  // Force disconnect all sockets from room
  roomSockets.socketsLeave(roomId);
  
  logSecurityEvent('ROOM_ENDED', {
    roomId,
    mode: room.mode,
    reason,
    participantCount: room.participants.length,
    duration: room.endedAt - room.createdAt
  });
}

function getRoomStats() {
  const stats = {
    total: state.rooms.size,
    active: 0,
    text: 0,
    video: 0,
    audio: 0,
    group_text: 0,
    group_video: 0,
    banned: 0,
    ended: 0,
    waiting: {
      text: state.waiting.text.size,
      video: state.waiting.video.size,
      audio: state.waiting.audio.size,
      group_text: state.waiting.group_text.size,
      group_video: state.waiting.group_video.size
    }
  };
  
  for (const room of state.rooms.values()) {
    if (room.status === 'active') stats.active++;
    if (room.status === 'ended') stats.ended++;
    if (room.isBanned) stats.banned++;
    
    stats[room.mode] = (stats[room.mode] || 0) + 1;
  }
  
  return stats;
}

function getPublicStateForAdmin() {
  const roomsArray = [];
  
  for (const [roomId, room] of state.rooms) {
    roomsArray.push({
      id: roomId,
      mode: room.mode,
      status: room.status,
      isBanned: room.isBanned,
      participants: room.participants,
      userCount: room.users.size,
      maxSize: ROOM_MAX_SIZE[room.mode],
      tags: room.tags,
      tokens: room.tokens.length,
      createdAt: room.createdAt,
      lastActivity: room.lastActivity,
      endedAt: room.endedAt,
      duration: room.endedAt 
        ? room.endedAt - room.createdAt 
        : Date.now() - room.createdAt
    });
  }
  
  roomsArray.sort((a, b) => b.createdAt - a.createdAt);
  
  return {
    serverInfo: {
      domain: DOMAIN,
      environment: NODE_ENV,
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      nodeVersion: process.version
    },
    rooms: roomsArray.slice(0, 100),
    reports: state.reports.slice(0, 50),
    online: state.users.size,
    stats: getRoomStats(),
    blockedCounts: {
      users: state.blockedUsers.size,
      ips: state.blockedIPs.size,
      tokens: state.blockedTokens.size
    },
    waiting: getRoomStats().waiting,
    securityLogs: state.securityLogs.slice(0, 50)
  };
}

/* ================= QUEUE MANAGEMENT ================= */
function processQueue() {
  // Process queue when space becomes available
  while (state.connectionQueue.length > 0 && state.users.size < MAX_USERS)
    {
    const queuedSocket = state.connectionQueue.shift();
    
    if (queuedSocket && queuedSocket.connected && !state.users.has(queuedSocket.id)) {
      acceptConnection(queuedSocket);
    }
    
  }
  
  // Update queue positions
  state.connectionQueue.forEach((queuedSocket, index) => {
    if (queuedSocket && queuedSocket.connected) {
      queuedSocket.emit("queue-position", {
        position: index + 1,
        totalInQueue: state.connectionQueue.length,
        estimatedWait: Math.ceil((index + 1) * 2) // Rough estimate: 2 seconds per person
      });
    }
  });
}

function acceptConnection(socket) {
  state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);

  const wasQueued = Boolean(socket.queued);

  socket.queued = false;
  socket.queuedAt = null;

  const userIP = getUserIP(socket);
  const userId = generateUserId();

  // Initialize user state
  state.users.set(socket.id, {
    id: userId,
    ip: userIP,
    name: 'Anonymous',
    mode: null,
    tags: [],
    token: null,
    rooms: new Set(),
    connectedAt: Date.now(),
    userAgent: socket.handshake.headers['user-agent'],
    queuedAt: null
  });

  socket.emit("queue-accepted", {
    message: "You're now connected!",
    userId
  });

  io.emit("online_count", { count: state.users.size });

  logSecurityEvent('USER_CONNECTED', { 
    socketId: socket.id, 
    userId, 
    ip: userIP,
    userAgent: socket.handshake.headers['user-agent'],
    wasQueued
  });
}


/* ================= SOCKET.IO EVENT HANDLERS ================= */
io.on('connection', (socket) => {
  // 🚦 USER LIMIT ENFORCEMENT WITH QUEUE
  if (state.users.size >= MAX_USERS) {

    // Queue full → reject
    if (state.connectionQueue.length >= MAX_QUEUE_SIZE) {
      socket.emit("server-full", {
        max: MAX_USERS,
        queueFull: true,
        message: "Server and queue are full. Please try again later."
      });
      socket.disconnect(true);
      return;
    }
  
    // Add to queue
    const queuePosition = state.connectionQueue.length + 1;
    
    socket.queued = true;
socket.queuedAt = Date.now();
 state.connectionQueue.push(socket);
  
    socket.emit("server-full", {
      max: MAX_USERS,
      queued: true,
      position: queuePosition,
      totalInQueue: state.connectionQueue.length,
      estimatedWait: Math.ceil(queuePosition * 2),
      message: `Server is full. You are #${queuePosition} in queue.`
    });
  
    logSecurityEvent('USER_QUEUED', {
      socketId: socket.id,
      position: queuePosition,
      totalInQueue: state.connectionQueue.length
    });
  
    socket.on('disconnect', () => {
      state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);
      processQueue();
    });
  
    return;
  }
  
  socket.queued = false;
socket.queuedAt = null;

  // Server has space, accept connection immediately
  acceptConnection(socket);
  state.connectionQueue = state.connectionQueue.filter(s => s.id !== socket.id);


  /* ===== JOIN CHAT EVENT ===== */
  socket.on("join_chat", (data) => {
    const userData = state.users.get(socket.id);
    if (!userData) return;
    if (userData.mode) return;
  
    
    const { mode = 'text', nickname, tags = [], token, userAgent } = data;
    
    
    if (!userData) {
      socket.emit('error', { message: 'User session not found' });
      return;
    }
    
    // Validate mode
    const validModes = ['text', 'video', 'audio', 'group_text', 'group_video'];
    const validMode = validModes.includes(mode) ? mode : 'text';
    
    // Get user IP and ID
    const userIP = getUserIP(socket);
    const userId = userData?.id || generateUserId();
    
    // Check if user is blocked
    if (isUserBlocked(userId, userIP, token)) {
      socket.emit('error', { 
        message: 'Your account has been blocked. Contact support if you believe this is an error.' 
      });
      socket.disconnect();
      return;
    }
    
    // Validate nickname
    const cleanNickname = (nickname || 'Anonymous')
      .toString()
      .slice(0, 30)
      .replace(/[<>]/g, ''); // Basic XSS protection
    
    // Validate tags
    const cleanTags = Array.isArray(tags) 
      ? tags.slice(0, 10).map(tag => tag.toString().slice(0, 20).toLowerCase())
      : [];
    
    // Update user data
    userData.name = cleanNickname;
    userData.tags = cleanTags;
    userData.token = token;
    userData.mode = validMode;
    userData.userAgent = userAgent;
    
    // Remove from any existing waiting queue
    for (const m of validModes) {
      state.waiting[m].delete(socket.id);
    }
    
    // Find or create match/group
    if (validMode.startsWith('group_')) {
      handleGroupJoin(socket, validMode, userData);
    }
     else {
      handleOneOnOneJoin(socket, validMode, userData);
    }
    
    // Update admin panel
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
  });
  
  function handleOneOnOneJoin(socket, mode, userData) {
    // Try to find match immediately
    const match = findMatchForUser(socket.id, mode, userData.tags);
  
    if (match) {
      const matchedUserData = match.userData;
      const isInterestMatch = match.matchScore > 0;
      const commonTags = matchedUserData.commonTags || [];
  
      // Create room
      const roomId = createRoom(mode, socket.id, userData, {
        socketId: match.socketId,
        data: matchedUserData
      });
  
      // Remove both users from waiting queue
      state.waiting[mode].delete(socket.id);
      state.waiting[mode].delete(match.socketId);
  
      // Track rooms
      userData.rooms.add(roomId);
      const matchedUser = state.users.get(match.socketId);
      if (matchedUser) {
        matchedUser.rooms.add(roomId);
      }
  
      // Join sockets to room
      socket.join(roomId);
      const matchedSocket = io.sockets.sockets.get(match.socketId);
      if (matchedSocket) {
        matchedSocket.join(roomId);
      }
  
      // Country flags (client-side detection preferred)
      const userCountry = getUserCountry(socket);
      const partnerCountry = getUserCountry(matchedSocket);
  
      // =========================
      // 🔥 INITIATOR ASSIGNMENT
      // =========================
      // Rule:
      // - socket (current joiner) → INITIATOR
      // - matchedSocket → RECEIVER
  
      // Send to initiator
      socket.emit("matched", {
        roomId,
        partner: matchedUserData.name,
        partnerName: matchedUserData.name,
        partnerId: matchedUserData.id,
        mode,
        tags: matchedUserData.tags || [],
        partnerTags: matchedUserData.tags || [],
        matchType: isInterestMatch ? "interest" : "random",
        partnerCountry,
        commonTags,
        isInitiator: true
      });
  
      // Send to receiver
      if (matchedSocket) {
        matchedSocket.emit("matched", {
          roomId,
          partner: userData.name,
          partnerName: userData.name,
          partnerId: userData.id,
          mode,
          tags: userData.tags || [],
          partnerTags: userData.tags || [],
          matchType: isInterestMatch ? "interest" : "random",
          partnerCountry: userCountry,
          commonTags,
          isInitiator: false
        });
      }
  
      logSecurityEvent("USERS_MATCHED", {
        roomId,
        user1: { id: userData.id, name: userData.name },
        user2: { id: matchedUserData.id, name: matchedUserData.name },
        mode,
        isInterestMatch
      });
  
    } else {
      // No match → add to waiting queue
      state.waiting[mode].set(socket.id, userData);
      userData.waitingSince = Date.now();
  
      socket.emit("waiting", {
        mode,
        estimatedWait: Math.max(2, state.waiting[mode].size * 1)
      });
  
      logSecurityEvent("USER_WAITING", {
        userId: userData.id,
        mode,
        name: userData.name,
        waitingCount: state.waiting[mode].size
      });
    }
  }
  
  
  function getUserCountry(socket) {
    if (!socket) return null;
    try {
      // Try to get country from IP (simplified - in production use proper geolocation)
      const forwardedFor = socket.handshake.headers['x-forwarded-for'];
      const ip = forwardedFor ? forwardedFor.split(',')[0].trim() : socket.handshake.address;
      // For now, return null - client will detect their own country
      return null;
    } catch (e) {
      return null;
    }
  }
  
  function handleGroupJoin(socket, mode, userData) {
    const group = findGroupForUser(socket.id, mode, userData.tags);
    let roomId;
  
    if (group?.roomId) {
      // Join existing group
      roomId = group.roomId;
      addUserToRoom(socket.id, roomId, userData);
    } else if (group?.newGroup) {
      // Create new group with single user
      roomId = createRoom(mode, socket.id, userData);
    } else {
      // Should never happen now, but keep fallback
      state.waiting[mode].set(socket.id, userData);
      socket.emit("waiting", { mode });
      return;
    }
  
    // ✅ SINGLE join + SINGLE room add
    state.waiting[mode].delete(socket.id);
    userData.rooms.add(roomId);
    socket.join(roomId);
  
    const room = state.rooms.get(roomId);
  
    socket.emit("group-joined", {
      roomId,
      mode,
      participants: room.participants.map(p => p.name),
      participantCount: room.users.size,
      maxSize: ROOM_MAX_SIZE[mode]
    });
  
    socket.to(roomId).emit("user-joined", {
      userId: userData.id,
      nickname: userData.name,
      userName: userData.name,
      participantCount: room.users.size
    });
  
    logSecurityEvent('GROUP_JOINED', {
      roomId,
      userId: userData.id,
      userName: userData.name,
      mode,
      groupSize: room.users.size
    });
  }
  
  
  /* ===== MESSAGE HANDLING ===== */
  socket.on("send_message", (data) => {
    if (isRateLimited(socket.id, "message")) {
      socket.emit('error', { 
        message: 'Message rate limit exceeded. Please slow down.' 
      });
      return;
    }
    
    const { room, roomId, message, type = "text" } = data;
    const targetRoomId = room || roomId;
    const userData = state.users.get(socket.id);
    
    if (!targetRoomId || !message || !userData) return;
    
    const roomData = state.rooms.get(targetRoomId);
    if (!roomData || !roomData.users.has(socket.id)) {
      socket.emit('error', { message: 'Not in this room' });
      return;
    }
    
    // Validate message
    const cleanMessage = String(message)
      .slice(0, 2000)
      .trim();
    
    if (cleanMessage.length === 0) return;
    
    // Update room activity
    roomData.lastActivity = Date.now();
    
    // Broadcast message
    const messageData = {
      message: cleanMessage,
      sender: userData.name,
      senderId: userData.id,
      senderNickname: userData.name,
      nickname: userData.name,
      type: type,
      timestamp: Date.now(),
      roomId: targetRoomId,
      room: targetRoomId
    };
    
    // Send to all in room except sender
    socket.to(targetRoomId).emit("receive_message", messageData);

    
    // Also send to sender for consistency (optional)
    
    
    
    logSecurityEvent('MESSAGE_SENT', {
      roomId: targetRoomId,
      userId: userData.id,
      messageLength: cleanMessage.length,
      type: type
    });
  });
  

  /* ===== WEBRTC SIGNALING ===== */
  socket.on("signal", (data) => {
    if (isRateLimited(socket.id, "signal")) return;
  
    const { room, to, sdp, candidate } = data;
    const userData = state.users.get(socket.id);
    if (!userData) return;
  
    if (room) {
      const roomData = state.rooms.get(room);
      if (!roomData || !roomData.users.has(socket.id)) return;
      roomData.lastActivity = Date.now();
    }
  
    // P2P
    if (to) {
      io.to(to).emit("signal", {
        from: socket.id,
        fromUser: userData.name,
        sdp,
        candidate
      });
      return;
    }
  
    // GROUP MESH
    if (room) {
      socket.to(room).emit("signal", {
        from: socket.id,
        fromUser: userData.name,
        sdp,
        candidate
      });
    }
  });
  
  
  
  
  /* ===== SKIP/LEAVE ===== */
  socket.on("skip", (data) => {
    if (isRateLimited(socket.id, "skip")) {
      socket.emit('error', { 
        message: 'Too many skips. Please wait a moment.' 
      });
      return;
    }
    
    const userData = state.users.get(socket.id);
    if (!userData) return;
    
    const mode = data?.mode || userData.mode || 'text';
    const tags = data?.tags || userData.tags || [];
    
    // Leave all rooms
    userData.rooms.forEach(roomId => {
      const roomData = state.rooms.get(roomId);
      if (roomData) {
        // Notify other users
        socket.to(roomId).emit("partner-left", {
          partnerId: userData.id,
          partnerName: userData.name,
          roomId: roomId
        });
        socket.to(roomId).emit("user-left", {
          userId: userData.id,
          nickname: userData.name,
          userName: userData.name,
          roomId: roomId
        });
        
        // Remove from room
        removeUserFromRoom(socket.id, roomId, "skipped");
        socket.leave(roomId);
      }
    });
    
    // Clear user rooms
    userData.rooms.clear();
    
    // Remove from waiting queues
    for (const modeKey in state.waiting) {
      state.waiting[modeKey].delete(socket.id);
    }
    
    // Rejoin matching queue with same mode and tags
    if (mode && userData) {
      userData.mode = mode;
      userData.tags = tags;
      
      if (mode.startsWith('group_')) {
        handleGroupJoin(socket, mode, userData);
      } else {
        handleOneOnOneJoin(socket, mode, userData);
      }
    } else {
      // Send waiting status if no mode
      socket.emit("waiting");
    }
    
    logSecurityEvent('USER_SKIPPED', {
      userId: userData.id,
      name: userData.name,
      mode: mode
    });
    
    // Update admin panel
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
  });
  
  /* ===== REPORT USER ===== */
  socket.on("report", (data) => {
    const { room, reason, partnerId, partnerName } = data;
    const userData = state.users.get(socket.id);
    
    if (!userData) return;
    
    const report = {
      id: `report_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      reporterId: userData.id,
      reporterName: userData.name,
      reportedId: partnerId,
      reportedName: partnerName,
      reason: (reason || 'No reason provided').slice(0, 500),
      roomId: room,
      reporterIP: userData.ip,
      reporterToken: userData.token,
      timestamp: Date.now(),
      status: 'pending'
    };
    
    state.reports.unshift(report);
    
    // Notify admins
    io.to('admins').emit('new-report', report);
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
    
    // Confirm to reporter
    socket.emit("report-received", { 
      success: true, 
      reportId: report.id 
    });
    
    // Auto-skip after reporting (optional)
    socket.emit("skip");
    
    logSecurityEvent('USER_REPORTED', report);
    
    // Log to file
    logToFile("reports.log", report);
  });
  
  /* ===== GROUP CHAT EVENTS ===== */
  socket.on("create-group", (data) => {
    const { mode = 'group_text', nickname = 'Anonymous' } = data;
    const userData = state.users.get(socket.id);
    
    if (!userData) {
      socket.emit('error', { message: 'User session not found' });
      return;
    }
    
    userData.name = nickname;
    userData.mode = mode;
    
    handleGroupJoin(socket, mode, userData);
  });
  
  socket.on("join-group", (data) => {
    const { roomId, mode = 'group_text', nickname = 'Anonymous' } = data;
    const userData = state.users.get(socket.id);
    
    if (!userData) {
      socket.emit('error', { message: 'User session not found' });
      return;
    }
    
    userData.name = nickname;
    userData.mode = mode;
    
    const room = state.rooms.get(roomId);
    if (room && room.status === 'active' && room.users.size < ROOM_MAX_SIZE[room.mode]) {
      if (addUserToRoom(socket.id, roomId, userData)) {
        userData.rooms.add(roomId);
        socket.join(roomId);
        
        socket.emit("joined-room", { roomId, mode: room.mode });
        
        socket.to(roomId).emit("user-joined", {
          userId: userData.id,
          nickname: userData.name,
          participantCount: room.users.size
        });
      } else {
        socket.emit('error', { message: 'Room is full' });
      }
    } else {
      socket.emit('error', { message: 'Room not found or unavailable' });
    }
  });
  
  /* ===== TYPING INDICATOR ===== */
  socket.on("typing", (data) => {
    const { room, isTyping } = data;
    const roomId = room;
    const userData = state.users.get(socket.id);
    
    if (!roomId || !userData) return;
    
    const roomData = state.rooms.get(roomId);
    if (!roomData || !roomData.users.has(socket.id)) return;
    
    socket.to(roomId).emit("user-typing", {
      userId: socket.id,
      userName: userData.name,
      isTyping: Boolean(isTyping)
    });
  });
  
  /* ===== ADMIN EVENTS ===== */
  socket.on("admin-auth", (data) => {
    const { username, password, adminKey } = data;
    
    if (username === ADMIN_CREDENTIALS.username && 
        password === ADMIN_CREDENTIALS.password &&
        adminKey === ADMIN_CREDENTIALS.adminKey) {
      
      state.admins.add(socket.id);
      socket.join('admins');
      
      socket.emit("admin-auth-success", {
        message: "Admin authentication successful",
        permissions: ["view", "ban", "unban", "view_logs", "view_reports"]
      });
      
      // Send current state
      socket.emit("admin-state", getPublicStateForAdmin());
      
      logAdminAction(socket.id, "ADMIN_LOGIN", { ip: getUserIP(socket) });
      
    } else {
      socket.emit("admin-auth-failed", {
        error: "Invalid admin credentials"
      });
      
      logSecurityEvent('FAILED_ADMIN_LOGIN', {
        socketId: socket.id,
        ip: getUserIP(socket)
      });
    }
  });
  
  socket.on("admin-command", (data) => {
    if (!state.admins.has(socket.id)) {
      socket.emit("error", { message: "Not authorized" });
      return;
    }
    
    const { command, ...params } = data;
    
    switch (command) {
      case "get-stats":
        socket.emit("admin-stats", getPublicStateForAdmin());
        break;
        
      case "ban-user":
        if (params.userId) {
          state.blockedUsers.add(params.userId);
          logAdminAction(socket.id, "BAN_USER", params);
          socket.emit("command-success", { command, ...params });
        }
        break;
        
      case "unban-user":
        if (params.userId) {
          state.blockedUsers.delete(params.userId);
          logAdminAction(socket.id, "UNBAN_USER", params);
          socket.emit("command-success", { command, ...params });
        }
        break;
        
      case "get-logs":
        socket.emit("admin-logs", {
          security: state.securityLogs.slice(0, 100),
          totalLogs: state.securityLogs.length
        });
        break;
        
      case "end-room":
        if (params.roomId) {
          const room = state.rooms.get(params.roomId);
          if (room) {
            endRoom(params.roomId, "admin_terminated");
            logAdminAction(socket.id, "END_ROOM", params);
            socket.emit("command-success", { command, ...params });
          }
        }
        break;
        
      default:
        socket.emit("error", { message: "Unknown command" });
    }
    
    // Update all admins
    io.to('admins').emit('admin-state', getPublicStateForAdmin());
  });
  
  /* ===== DISCONNECT HANDLER ===== */
  socket.on("disconnect", () => {
    const userData = state.users.get(socket.id);
    
    if (userData) {
      // Leave all rooms
      userData.rooms.forEach(roomId => {
        const roomData = state.rooms.get(roomId);
        if (roomData) {
          // Notify other users
          socket.to(roomId).emit("partner-disconnected", {
            partnerId: userData.id,
            partnerName: userData.name,
            roomId: roomId
          });
          
          // Remove from room
          removeUserFromRoom(socket.id, roomId, "disconnected");
        }
      });
      
      // Remove from waiting queues
      for (const mode in state.waiting) {
        state.waiting[mode].delete(socket.id);
      }
      
      // Remove from admins
      if (state.admins.has(socket.id)) {
        state.admins.delete(socket.id);
        socket.leave('admins');
        logAdminAction(socket.id, "ADMIN_LOGOUT");
      }
      
      // Remove rate limit tracking
      state.socketRateLimits.delete(socket.id);
      
      // Remove user
      state.users.delete(socket.id);
      
      logSecurityEvent('USER_DISCONNECTED', {
        userId: userData.id,
        socketId: socket.id,
        ip: userData.ip,
        duration: Date.now() - userData.connectedAt,
        rooms: Array.from(userData.rooms)
      });
    }
    
    // Update online count and admin panel
    io.emit("online_count", { count: state.users.size });


    io.to('admins').emit('admin-state', getPublicStateForAdmin());
    
    // Process queue if space is available
    if (state.users.size < MAX_USERS) {
      processQueue();
  }
  });
});

/* ================= PERIODIC CLEANUP ================= */
setInterval(() => {
  const now = Date.now();
  const oneHourAgo = now - (60 * 60 * 1000);
  const fiveMinutesAgo = now - (5 * 60 * 1000);
  const thirtyMinutesAgo = now - (30 * 60 * 1000);
  
  // Clean up old rooms
  for (const [roomId, room] of state.rooms) {
    if (room.status === 'ended' && room.endedAt < oneHourAgo) {
      state.rooms.delete(roomId);
    }
    
    // Clean up inactive rooms (no activity for 30 minutes)
    if (room.status === 'active' && room.lastActivity < thirtyMinutesAgo) {
      endRoom(roomId, "inactivity");
    }
  }
  
  // Clean up users waiting too long (5+ minutes)
  for (const mode in state.waiting) {
    for (const [socketId, userData] of state.waiting[mode].entries()) {
      if (userData.waitingSince && userData.waitingSince < fiveMinutesAgo) {
        state.waiting[mode].delete(socketId);
      
        const socket = io.sockets.sockets.get(socketId);
        if (socket) {
          socket.emit('waiting-timeout');
        }
      }
      
    }
  }
  
  // Clean up old rate limit data (older than 2 minutes)
  for (const [socketId, limits] of state.socketRateLimits.entries()) {
    for (const type in limits) {
      if (now - limits[type].firstRequest > 120000) {
        delete limits[type];
      }
    }
    if (Object.keys(limits).length === 0) {
      state.socketRateLimits.delete(socketId);
    }
  }
  
  // Clean up old reports and logs
  if (state.reports.length > 1000) {
    state.reports = state.reports.slice(0, 1000);
  }
  
  if (state.securityLogs.length > 2000) {
    state.securityLogs = state.securityLogs.slice(0, 2000);
  }
  
  // Update admin panel
  io.to('admins').emit('admin-state', getPublicStateForAdmin());
  
  // Log memory usage periodically
  const memoryUsage = process.memoryUsage();
  if (memoryUsage.heapUsed > 500 * 1024 * 1024) { // 500MB threshold
    console.warn(`⚠️  High memory usage: ${Math.round(memoryUsage.heapUsed / 1024 / 1024)}MB`);
  }
  
}, 5 * 60 * 1000); // Run every 5 minutes

/* ================= START SERVER ================= */
async function startServer() {
  await setupLogging();
  
  server.listen(PORT, HOST, () => {
    console.log(`
    🚀 ManaMingle Server Started!
    ==============================
    👉 Environment: ${NODE_ENV}
    👉 Domain: ${DOMAIN}
    👉 Main URL: http://${HOST}:${PORT}
    👉 Admin Panel: http://${HOST}:${PORT}/admin
    👉 Health Check: http://${HOST}:${PORT}/health
    
    📊 Room Limits:
    • 1-on-1 Text/Video/Audio: 2 users
    • Group Text Chat: 6 users
    • Group Video Chat: 4 users
    
    ⚠️  ${NODE_ENV === 'production' ? 'PRODUCTION MODE' : 'DEVELOPMENT MODE'}
    ⚠️  ${ADMIN_CREDENTIALS.password === 'ChangeMe123!' ? 'CHANGE DEFAULT ADMIN CREDENTIALS!' : 'Admin credentials set'}
    `);
  });
}

startServer().catch(console.error);

/* ================= ERROR HANDLING ================= */
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err);
  logSecurityEvent('SERVER_ERROR', { 
    error: err.message, 
    stack: err.stack 
  });
  logToFile("errors.log", { 
    type: 'uncaughtException', 
    error: err.message, 
    stack: err.stack,
    timestamp: Date.now() 
  });
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('UNHANDLED REJECTION at:', promise, 'reason:', reason);
  logSecurityEvent('UNHANDLED_REJECTION', { 
    reason: String(reason) 
  });
  logToFile("errors.log", { 
    type: 'unhandledRejection', 
    reason: String(reason),
    timestamp: Date.now() 
  });
});

// Graceful shutdown
process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

function gracefulShutdown() {
  console.log('🛑 Received shutdown signal. Closing server...');
  
  // Notify all users
  io.emit('server-shutdown', { 
    message: 'Server is restarting. Please reconnect in a moment.',
    timestamp: Date.now() 
  });
  
  // Close all rooms
  for (const [roomId, room] of state.rooms) {
    if (room.status === 'active') {
      endRoom(roomId, 'server_maintenance');
    }
  }
  
  // Save state (optional)
  logToFile("shutdown.log", {
    timestamp: Date.now(),
    rooms: state.rooms.size,
    users: state.users.size,
    reports: state.reports.length
  });
  
  setTimeout(() => {
    server.close(() => {
      console.log('✅ Server closed gracefully');
      process.exit(0);
    });
  }, 5000); // Give 5 seconds for cleanup
}
