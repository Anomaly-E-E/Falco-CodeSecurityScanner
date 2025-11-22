

const { verifyToken } = require('../utils/jwt');

async function authMiddleware(req, res, next) {
  try {
    //Get Authorization header from request
    const authHeader = req.headers.authorization;
    
    console.log('🔒 Auth middleware triggered');
    console.log('Authorization header:', authHeader ? 'Present' : 'Missing');
    
    //Check if Authorization header exists
    if (!authHeader) {
      return res.status(401).json({ 
        error: 'No token provided. Please login.' 
      });
    }
    
    //Extract token from "Bearer <token>" format
    const token = authHeader.split(' ')[1];
    
    console.log('Token extracted:', token ? token.substring(0, 20) + '...' : 'MISSING');
    
    // Make sure token exists after split
    if (!token) {
      return res.status(401).json({ 
        error: 'Invalid token format. Expected: Bearer <token>' 
      });
    }
    
    //Verify token is valid and not expired
    const decoded = verifyToken(token);
    
    console.log('✅ Token valid for user:', decoded.email);
    
    //Add user data to request object (available in next functions)
    req.user = {
      userId: decoded.userId,
      email: decoded.email
    };
    
    //ontinue to the next middleware/route handler
    next();
    
  } catch (error) {
    // Handle errors
    console.error('Auth middleware error:', error);
    return res.status(401).json({ 
      error: 'Invalid or expired token' 
    });
  }
}

module.exports = authMiddleware;