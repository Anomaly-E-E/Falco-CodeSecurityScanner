const { supabase } = require('../config/supabase');
const { hashPassword } = require('../utils/password');
const { isValidEmail, isValidPassword, sanitizeEmail } = require('../utils/validation');
const { generateToken, generateVerificationToken } = require('../utils/jwt');
const { sendVerificationEmail } = require('../services/emailService');

/**
 * 
 * 1. User sends: { email, password }
 * 2.  validate: email format, password strength
 * 3.  check: email already exists?
 * 4.  hash: password (security!)
 * 5.  create: verification token (random string)
 * 6.  insert: user into database
 * 7.  send: verification email
 * 8.  return: success message (NOT the password!)
 */

async function register(req, res) {
  try {
    // STEP 1: Get data from request body
    const { email, password } = req.body;
    
    console.log('📝 Registration attempt for:', email);
    
    // STEP 2: Validate inputs exist
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email and password are required' 
      });
    }
    
    // STEP 3: Sanitize email (remove spaces, lowercase)
    const cleanEmail = sanitizeEmail(email);
    
    // STEP 4: Validate email format
    if (!isValidEmail(cleanEmail)) {
      return res.status(400).json({ 
        error: 'Invalid email format' 
      });
    }
    
    // STEP 5: Validate password strength
    const passwordCheck = isValidPassword(password);
    if (!passwordCheck.valid) {
      return res.status(400).json({ 
        error: passwordCheck.message 
      });
    }
    
    // STEP 6: Check if email already exists
    const { data: existingUser } = await supabase
      .from('users')
      .select('id')
      .eq('email', cleanEmail)
      .single();
    
    if (existingUser) {
      return res.status(409).json({ 
        error: 'Email already registered' 
      });
    }
    
    // STEP 7: Hash the password (security!)
    const passwordHash = await hashPassword(password);
    
    // STEP 8: Generate verification token (random string)
    const verificationToken = generateVerificationToken();
    
    // STEP 9: Insert user into database
    const { data: newUser, error: insertError } = await supabase
      .from('users')
      .insert({
        email: cleanEmail,
        password_hash: passwordHash,
        verification_token: verificationToken,
        is_verified: false,
        credits: 10 // Free credits on signup!
      })
      .select('id, email, credits, created_at')
      .single();
    
    if (insertError) {
      console.error('Database error:', insertError);
      return res.status(500).json({ 
        error: 'Failed to create account' 
      });
    }
    
    // STEP 10: Send verification email
    await sendVerificationEmail(cleanEmail, verificationToken);
    
    // STEP 11: Return success (NO PASSWORD in response!)
    console.log('✅ User registered:', newUser.email);
    
    res.status(201).json({
      message: 'Registration successful! Please check your email to verify your account.',
      user: {
        id: newUser.id,
        email: newUser.email,
        credits: newUser.credits,
        isVerified: false
      }
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      error: 'An error occurred during registration' 
    });
  }
}

/**
 * EMAIL VERIFICATION FUNCTION
 * 
 * 1. Get token from request body
 * 2. Validate token exists
 * 3. Find user with this token in database
 * 4. Check if user exists
 * 5. Check if already verified
 * 6. Update user: set is_verified = true
 * 7. Clear the verification token
 * 8. Send success response
 */

async function verifyEmail(req, res) {
  try {
  
    //Get token from request
    const { token } = req.body;
    console.log('📧 Email verification attempt');
    console.log(token ? token.substring(0, 10) + '*****' : 'MISSING');
    
    //Validate token
    if (!token) {
      return res.status(400).json({ 
        error: 'Verification token is required' 
      });
    }
    
    
    // Find user
    const { data: user, error: findError } = await supabase
     .from('users')
     .select('id, email, is_verified')
     .eq('verification_token', token)
     .single();
    
    
    // Check user exists
    if (findError || !user) {
      console.log('❌ User not found with this token');
      return res.status(400).json({ 
        error: 'Invalid or expired verification token' 
      });
    }
    
    
    //Check if already verified
    if (user.is_verified) {
      console.log('⚠️ User already verified:', user.email);
      return res.status(400).json({ 
        error: 'Email already verified. You can login now.' 
      });
    }
    
    
    //Update user
    const { error: updateError } = await supabase
     .from('users')
     .update({
       is_verified: true,
        verification_token: null
     })
     .eq('id', user.id);

// Check if update failed
   if (updateError) {
    console.error('❌ Database update failed:', updateError);
    return res.status(500).json({ 
      error: 'Failed to verify email. Please try again.' 
    });
  }
  
  console.log('✅ Email verified for:', user.email);
    
    
    //success response
    res.status(200).json({
      message: 'Email verified successfully! You can now login.',
      email: user.email
    });
    
    
  } catch (error) {
    // Step 8: Handle errors
    console.error('Email verification error:', error);
    res.status(500).json({ 
      error: 'An error occurred during verification' 
    });
  }
}

module.exports = {
  register
};