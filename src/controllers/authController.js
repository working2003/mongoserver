require('dotenv').config();
const {generateUniqueValue} = require('../util/generateUniqueName');
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

// Store OTP details temporarily (in production, use Redis or similar)
const otpStore = new Map();

// Step 1: Send OTP
const sendOTP = async (req, res) => {
  try {
    // Log environment state
    console.log('Environment Check:', {
      NODE_ENV: process.env.NODE_ENV,
      VERCEL_ENV: process.env.VERCEL_ENV,
      hasEnvVars: {
        OTPLESS_CLIENT_ID: !!process.env.OTPLESS_CLIENT_ID,
        OTPLESS_CLIENT_SECRET: !!process.env.OTPLESS_CLIENT_SECRET
      }
    });

    const { mobileNumber } = req.body;
    
    if (!mobileNumber || !/^\d{10}$/.test(mobileNumber)) {
      return res.status(400).json({ 
        success: false,
        message: 'Invalid mobile number. Please provide a 10-digit number.',
        debug: { mobileNumber }
      });
    }

    // Check environment variables
    if (!process.env.OTPLESS_CLIENT_ID || !process.env.OTPLESS_CLIENT_SECRET) {
      const error = new Error('Missing OTPless credentials');
      error.details = {
        missingVars: {
          OTPLESS_CLIENT_ID: !process.env.OTPLESS_CLIENT_ID,
          OTPLESS_CLIENT_SECRET: !process.env.OTPLESS_CLIENT_SECRET
        },
        environment: process.env.NODE_ENV,
        vercelEnv: process.env.VERCEL_ENV
      };
      throw error;
    }

    const clientId = process.env.OTPLESS_CLIENT_ID;
    const clientSecret = process.env.OTPLESS_CLIENT_SECRET;
    const phoneNumber = "+91" + mobileNumber;
    const orderId = generateUniqueValue();

    // Log OTP request details
    console.log('OTP Request:', {
      phoneNumber,
      orderId,
      timestamp: new Date().toISOString()
    });

    try {
      const response = await UserDetail.sendOTP({
        phoneNumber,
        orderId,
        channel: 'sms',
        clientId,
        clientSecret,
        otpLength: 4,
        expiryMinutes: 5
      });

      console.log('OTPless API Response:', {
        success: response?.success,
        hasMessage: !!response?.message,
        timestamp: new Date().toISOString()
      });

      if (!response || !response.success) {
        throw new Error(response?.message || 'OTPless API failed to send OTP');
      }

      // Store OTP details
      otpStore.set(mobileNumber, {
        orderId,
        timestamp: Date.now(),
        attempts: 0
      });

      // Cleanup after expiry
      setTimeout(() => otpStore.delete(mobileNumber), 5 * 60 * 1000);

      return res.status(200).json({
        success: true,
        message: 'OTP sent successfully',
        orderId,
        debug: {
          timestamp: new Date().toISOString(),
          phoneNumber: phoneNumber.substring(0, 6) + '****' + phoneNumber.slice(-2)
        }
      });
    } catch (otpError) {
      console.error('OTPless API Error:', otpError);
      throw new Error(`Failed to send OTP: ${otpError.message}`);
    }
  } catch (error) {
    console.error('OTP Send Error:', {
      message: error.message,
      stack: error.stack,
      details: error.details || {},
      timestamp: new Date().toISOString()
    });

    return res.status(500).json({
      success: false,
      message: process.env.NODE_ENV === 'development' 
        ? `Server error: ${error.message}`
        : 'Failed to send OTP. Please try again later.',
      debug: process.env.NODE_ENV === 'development' ? {
        error: error.message,
        details: error.details,
        timestamp: new Date().toISOString()
      } : undefined
    });
  }
};

// Step 2: Verify OTP
const verifyOTPAndLogin = async (req, res) => {
  try {
    const { mobileNumber, otp, firstName } = req.body;

    if (!mobileNumber || !otp) {
      return res.status(400).json({
        success: false,
        message: 'Mobile number and OTP are required'
      });
    }

    const otpData = otpStore.get(mobileNumber);
    
    if (!otpData) {
      return res.status(400).json({
        success: false,
        message: 'OTP expired or not found. Please request a new OTP.'
      });
    }

    if (otpData.attempts >= 3) {
      otpStore.delete(mobileNumber);
      return res.status(400).json({
        success: false,
        message: 'Too many failed attempts. Please request a new OTP.'
      });
    }

    const clientId = process.env.OTPLESS_CLIENT_ID;
    const clientSecret = process.env.OTPLESS_CLIENT_SECRET;

    const verifyResponse = await UserDetail.verifyOTP({
      phoneNumber: "+91" + mobileNumber,
      otp,
      orderId: otpData.orderId,
      clientId,
      clientSecret
    });

    if (!verifyResponse || !verifyResponse.success) {
      otpData.attempts += 1;
      throw new Error(verifyResponse?.message || 'Invalid OTP');
    }

    // OTP verified successfully, remove from store
    otpStore.delete(mobileNumber);

    // Create or update user
    let user = await User.findOne({ mobileNumber });
    
    if (!user) {
      user = new User({
        mobileNumber,
        firstName,
        status: "Active",
        lastLogIn: new Date()
      });
    } else {
      user.firstName = firstName || user.firstName;
      user.status = "Active";
      user.lastLogIn = new Date();
    }
    
    await user.save();

    // Generate JWT token
    const token = generateJWTToken(user._id);

    return res.status(200).json({
      success: true,
      message: 'OTP verified successfully',
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        mobileNumber: user.mobileNumber,
        status: user.status
      }
    });
  } catch (error) {
    console.error('OTP Verification Error:', error);
    return res.status(500).json({
      success: false,
      error: error.message || 'Failed to verify OTP'
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
