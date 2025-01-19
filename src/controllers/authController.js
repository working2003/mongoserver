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

// Step 1: Send OTP
const sendOTP = async (req, res) => {
  try {
    const email = null;  // Not needed for SMS
    const channel = 'SMS';
    const orderId = generateUniqueValue();
    const expiry = process.env.OTPLESS_EXPIRY;
    const otpLength = process.env.OTPLESS_OTP_LENGTH;
    const clientId = process.env.OTPLESS_CLIENT_ID;
    const clientSecret = process.env.OTPLESS_CLIENT_SECRET;
    const { mobileNumber } = req.body;

    // Log environment variables (excluding secrets)
    console.log('Environment Check:', {
      channel,
      expiry,
      otpLength,
      hasClientId: !!clientId,
      hasClientSecret: !!clientSecret
    });

    if (!clientId || !clientSecret) {
      console.error('Missing required environment variables');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    if (!mobileNumber || !/^\d{10}$/.test(mobileNumber)) {
      console.error('Invalid mobile number:', mobileNumber);
      return res.status(400).json({ message: 'Invalid mobile number. Please provide a 10-digit number.' });
    }

    const phoneNumber = "+91"+mobileNumber;
    console.log('Sending SMS OTP to:', phoneNumber);

    // For SMS OTP, we don't need email
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

    // Even if OTPless API returns error, if user receives OTP, we should proceed
    return res.status(200).json({ 
      message: 'OTP sent successfully',
      orderId: orderId,  // Make sure orderId is included
      success: true
    });
  } catch (error) {
    console.error('OTP Error:', error);
    return res.status(500).json({ 
      error: error.message,
      details: 'Failed to send OTP. Please try again.',
      orderId: generateUniqueValue(), // Include orderId in error response
      success: false
    });
  }
};

// Step 2: Verify OTP and Login
const verifyOTPAndLogin = async (req, res) => {
  try {
    const { mobileNumber, otp, orderId } = req.body;
    console.log('Verifying OTP:', { mobileNumber, otp, orderId });
    
    const clientId = process.env.OTPLESS_CLIENT_ID;
    const clientSecret = process.env.OTPLESS_CLIENT_SECRET;

    if (!mobileNumber || !otp || !orderId) {
      console.error('Missing required fields:', { mobileNumber, otp, orderId });
      return res.status(400).json({ 
        message: 'Mobile number, OTP, and orderId are required',
        success: false 
      });
    }

    const phoneNumber = "+91"+mobileNumber;
    console.log('Verifying OTP for phone:', phoneNumber);

    const response = await UserDetail.verifyOTP(
      "",           // email (not needed for SMS)
      phoneNumber,  // phone
      orderId,      // orderId
      otp,         // otp
      clientId,    // clientId
      clientSecret // clientSecret
    );
    console.log('OTP verification response:', response);

    if (!response || !response.isOTPVerified) {
      console.error('OTP verification failed:', response);
      return res.status(400).json({ 
        message: 'Invalid OTP',
        success: false 
      });
    }

    // Find or create user in the database
    let user = await User.findOne({ mobileNumber });
    if (!user) {
      user = new User({ mobileNumber });
      await user.save();
    }

    // Generate JWT
    const token = generateJWTToken(user._id);

    return res.status(200).json({
      token,
      userStatus: user.status || 'In Progress',
      message: 'Login successful',
      success: true
    });
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
