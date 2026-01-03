# Mana Mingle - Enhanced Anonymous Chat Platform

A secure, accessible, and feature-rich anonymous chat platform for Telugu speakers worldwide, now with comprehensive improvements.

## 🚀 New Features & Improvements (Version 2.0)

### ✅ External CSS Architecture
- **Separated Concerns**: Moved all CSS to external `public/styles.css` file
- **Better Performance**: Reduced HTML file size and improved caching
- **Maintainability**: Easier to update styles without touching HTML
- **CSP Compliance**: Removed inline styles for better security

### ✅ Enhanced Server Endpoints
- **API Validation**: `/api/validate-tags` with comprehensive input validation
- **Smart Matching**: `/api/find-matches` with advanced algorithm
- **Report System**: `/api/report-user` with detailed logging
- **Health Check**: `/api/stats` for monitoring server health
- **Rate Limiting**: Prevents abuse with configurable limits
- **Error Handling**: Comprehensive error logging and user feedback

### ✅ Real User Matching System
- **Multi-Factor Algorithm**: Considers tag similarity, wait time, location, and randomness
- **Interest-Based Matching**: Prioritizes users with common tags
- **Fallback Matching**: Ensures users get matched even without common interests
- **Match Scoring**: Transparent scoring system for match quality
- **Queue Management**: Fair waiting system with position tracking

### ✅ Comprehensive Input Validation
- **Client-Side Validation**: Real-time feedback using `InputValidator` class
- **Server-Side Validation**: Double validation for security
- **Sanitization**: XSS protection and content filtering
- **Rate Limiting**: Prevents spam and abuse
- **Pattern Matching**: Supports Telugu characters and international input
- **Error Feedback**: Clear, actionable error messages

### ✅ Accessibility Improvements
- **ARIA Labels**: Comprehensive screen reader support
- **Keyboard Navigation**: Full keyboard accessibility
- **Skip Links**: Quick navigation for screen readers
- **Live Regions**: Dynamic content announcements
- **Focus Management**: Proper focus handling in modals
- **High Contrast**: Support for high contrast mode
- **Reduced Motion**: Respects user motion preferences
- **Semantic HTML**: Proper heading structure and landmarks

## 🛡️ Security Enhancements

### Content Security Policy (CSP)
- Removed `unsafe-inline` directives
- Strict script and style sources
- Protection against XSS attacks

### Input Sanitization
- HTML entity encoding
- Script tag removal
- SQL injection prevention
- Profanity filtering

### Rate Limiting
- API endpoint protection
- Socket event rate limiting
- User session tracking
- Abuse prevention

## 📁 File Structure

```
mana-mingle/
├── public/
│   ├── styles.css              # External CSS file
│   ├── js/
│   │   └── validation.js       # Input validation utilities
│   ├── index.html              # Enhanced main page
│   └── [other HTML files]
├── server.js                   # Original server
├── server-improved.js          # Enhanced server with new features
├── package.json               # Updated dependencies
└── README.md                  # This file
```

## 🚀 Getting Started

### Prerequisites
- Node.js 18+ 
- npm or yarn

### Installation
```bash
# Clone the repository
git clone <repository-url>
cd mana-mingle

# Install dependencies
npm install

# Start the enhanced server
npm start

# Or start the original server
npm run original

# Development mode with auto-reload
npm run dev
```

### Environment Variables
Create a `.env` file for production:
```env
NODE_ENV=production
PORT=3000
ADMIN_USER=your_admin_username
ADMIN_PASS=your_secure_password
ADMIN_KEY=your_admin_api_key
DOMAIN=yourdomain.com
```

## 🔧 API Endpoints

### POST /api/validate-tags
Validates user tags with comprehensive checks.

**Request:**
```json
{
  "tags": ["telugu", "hyderabad", "movies"]
}
```

**Response:**
```json
{
  "isValid": true,
  "errors": [],
  "tags": ["telugu", "hyderabad", "movies"]
}
```

### POST /api/find-matches
Advanced matching algorithm with multiple factors.

**Request:**
```json
{
  "tags": ["telugu", "movies"],
  "mode": "text"
}
```

**Response:**
```json
{
  "matches": [
    {
      "userId": "user1",
      "matchScore": 85,
      "commonTags": ["telugu", "movies"],
      "userRating": 4.5
    }
  ],
  "totalFound": 1,
  "algorithm": "enhanced_v2"
}
```

### POST /api/report-user
Enhanced user reporting system.

**Request:**
```json
{
  "reportedUserId": "user123",
  "reason": "inappropriate_content",
  "description": "User was sharing inappropriate content"
}
```

## 🎯 Accessibility Features

### Screen Reader Support
- Comprehensive ARIA labels
- Live region announcements
- Semantic HTML structure
- Proper heading hierarchy

### Keyboard Navigation
- Tab order optimization
- Skip links for quick navigation
- Keyboard shortcuts (Ctrl+K for tag input)
- Focus management in modals

### Visual Accessibility
- High contrast mode support
- Reduced motion preferences
- Clear focus indicators
- Sufficient color contrast ratios

## 🔒 Security Features

### Input Validation
- Client and server-side validation
- XSS prevention
- SQL injection protection
- Rate limiting

### Content Security
- Strict CSP headers
- HTTPS enforcement
- Secure cookie settings
- CORS configuration

## 🧪 Testing

The application includes comprehensive validation and error handling. Test the following scenarios:

1. **Tag Validation**: Try adding invalid characters, long tags, or too many tags
2. **Rate Limiting**: Rapidly click buttons to test rate limiting
3. **Accessibility**: Navigate using only keyboard and screen reader
4. **Error Handling**: Test with network disconnections and invalid inputs

## 📈 Performance Improvements

- **External CSS**: Better caching and reduced HTML size
- **Compression**: Gzip compression for all responses
- **Rate Limiting**: Prevents server overload
- **Memory Management**: Automatic cleanup of old sessions
- **Efficient Matching**: Optimized algorithm for faster matching

## 🚀 Production Deployment

### Prerequisites
- Node.js >= 18
- SSL Certificate (HTTPS required)
- Domain: `manamingle.site`

### Quick Start

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Configure Environment Variables**
   ```bash
   # Copy the example file
   cp .env.example .env
   
   # Edit .env and set your ADMIN_KEY
   # Generate a secure random password (minimum 32 characters)
   ```

3. **Set Environment Variables**
   - `ADMIN_KEY` - Required: Strong password for admin access
   - `PORT` - Optional: Server port (default: 3000)
   - `HOST` - Optional: Host to bind (default: 0.0.0.0)
   - `NODE_ENV` - Optional: Set to "production" (default: production)
   - `ALLOWED_ORIGINS` - Optional: Comma-separated CORS origins

4. **Start the Enhanced Server**
   ```bash
   npm start
   # Or for production
   npm run start:prod
   ```

### Production Configuration

The application is configured for production with:
- ✅ CORS restricted to `https://manamingle.site` and `https://www.manamingle.site`
- ✅ Secure cookies (HttpOnly, Secure, SameSite=Strict)
- ✅ Helmet security headers
- ✅ Content Security Policy
- ✅ HSTS enabled
- ✅ Production-only Socket.IO connections

### Keep Render Service Alive (Free)

If deploying to Render's free tier, the service spins down after 15 minutes. **Keep it alive 24/7 for FREE:**

**Quick Setup (2 minutes):**
1. Go to [uptimerobot.com](https://uptimerobot.com) → Sign up (free)
2. Add monitor: `https://manamingle.site/_health`
3. Set interval: 5 minutes
4. Done! Service stays alive ✅

### Admin Access

1. Navigate to `https://manamingle.site/admin.html`
2. Enter your `ADMIN_KEY` from the `.env` file
3. Click "Auth" to authenticate

### Health Check

The server provides a health check endpoint:
```
GET https://manamingle.site/_health
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly (especially accessibility)
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🆘 Support

For support, please contact the development team or create an issue in the repository.

---

**Version 2.0.0** - Enhanced with accessibility, security, and user experience improvements.

