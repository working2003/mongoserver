require('dotenv').config();
const jwt = require('jsonwebtoken');
const User = require('../models/user'); // Your User model
const { UserDetail } = require('otpless-node-js-auth-sdk');

// Helper to generate a JWT
const generateJWTToken = (userId) => {
  const JWT_EXPIRATION_Value = process.env.JWT_EXPIRATION || '180d'
  return jwt.sign({ userId }, process.env.JWT_SECRET, {
    expiresIn: JWT_EXPIRATION_Value, // e.g., '1d' for 1 day
  });
};

// Helper to generate unique value
const generateUniqueValue = () => {
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
};

// Store OTP details temporarily (in production, use Redis or similar)
const otpStore = new Map();

// Step 1: Send OTP
const sendOTP = async (req, res) => {
  try {
    const { mobile } = req.body;  
    console.log('Sending OTP for:', mobile);

    const clientId = process.env.OTPLESS_CLIENT_ID;
    const clientSecret = process.env.OTPLESS_CLIENT_SECRET;
    const channel = 'SMS';
    const orderId = generateUniqueValue();
    const expiry = process.env.OTPLESS_EXPIRY;
    const otpLength = process.env.OTPLESS_OTP_LENGTH;

    if (!clientId || !clientSecret) {
      console.error('Missing required environment variables');
      return res.status(500).json({ 
        message: 'Server configuration error',
        success: false 
      });
    }

    if (!mobile || !/^\d{10}$/.test(mobile)) {
      console.error('Invalid mobile number:', mobile);
      return res.status(400).json({ 
        message: 'Invalid mobile number. Please provide a 10-digit number.',
        success: false 
      });
    }

    const phoneNumber = "+91" + mobile;
    console.log('Sending SMS OTP to:', phoneNumber);

    const response = await UserDetail.sendOTP(
      phoneNumber,   // phone number
      null,         // email (not needed for SMS)
      channel,      // SMS channel
      null,         // hash (optional)
      orderId,      // orderId
      expiry,       // expiry
      otpLength,    // otpLength
      clientId,     // clientId
      clientSecret  // clientSecret
    );
    console.log('OTP Response:', response);

    // Store the OTP details for verification
    otpStore.set(mobile, {
      orderId,
      timestamp: Date.now()
    });

    // Clean up old entries after 5 minutes
    setTimeout(() => {
      otpStore.delete(mobile);
    }, 5 * 60 * 1000);

    return res.status(200).json({ 
      message: 'OTP sent successfully',
      success: true
    });
  } catch (error) {
    console.error('OTP Error:', error);
    return res.status(500).json({ 
      message: 'Failed to send OTP. Please try again.',
      success: false
    });
  }
};

// Step 2: Verify OTP and Login
const verifyOTPAndLogin = async (req, res) => {
  try {
    const { mobile, otp } = req.body;  
    console.log('Verifying OTP:', { mobile, otp });
    
    const clientId = process.env.OTPLESS_CLIENT_ID;
    const clientSecret = process.env.OTPLESS_CLIENT_SECRET;

    if (!mobile || !otp) {
      console.error('Missing required fields:', { mobile, otp });
      return res.status(400).json({ 
        message: 'Mobile number and OTP are required',
        success: false 
      });
    }

    const phoneNumber = "+91" + mobile;
    console.log('Verifying OTP for phone:', phoneNumber);

    // Get stored OTP details
    const storedData = otpStore.get(mobile);
    if (!storedData) {
      console.error('No OTP request found for this number');
      return res.status(400).json({ 
        message: 'Please request a new OTP',
        success: false 
      });
    }

    try {
      console.log('Using stored orderId:', storedData.orderId);
      const response = await UserDetail.verifyOTP(
        "",           // email
        phoneNumber,  // phone
        storedData.orderId,  // use stored orderId
        otp,         // otp
        clientId,    // clientId
        clientSecret // clientSecret
      );
      console.log('OTP verification response:', JSON.stringify(response, null, 2));

      if (!response || !response.isOTPVerified) {
        console.error('OTP verification failed:', response);
        return res.status(400).json({ 
          message: 'Invalid OTP',
          success: false 
        });
      }

      // Find or create user in the database
      let user = await User.findOne({ mobileNumber: mobile });  
      if (!user) {
        user = new User({ mobileNumber: mobile });  
        await user.save();
      }

      // Generate JWT
      const token = generateJWTToken(user._id);

      // Clear the stored OTP data
      otpStore.delete(mobile);

      return res.status(200).json({
        token,
        userStatus: user.status || 'In Progress',
        message: 'Login successful',
        success: true
      });
    } catch (verifyError) {
      console.error('OTP verification error:', verifyError);
      return res.status(400).json({ 
        message: 'Failed to verify OTP',
        success: false 
      });
    }
  } catch (error) {
    console.error('OTP verification error:', error);
    res.status(500).json({ 
      error: error.message,
      message: 'Failed to verify OTP',
      success: false 
    });
  }
};

// Step 3: Middleware to Authenticate Requests
const authenticateRequest = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied, token missing!' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid token' });
    }
    req.user = decoded; // Attach user to request object
    next();
  });
};

module.exports = {
  sendOTP,
  verifyOTPAndLogin,
  authenticateRequest,
};
