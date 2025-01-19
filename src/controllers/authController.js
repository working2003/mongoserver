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
    const email = null;  // Not needed for SMS
    const channel = 'SMS';
    const orderId = generateUniqueValue();
    const expiry = process.env.OTPLESS_EXPIRY;
    const otpLength = process.env.OTPLESS_OTP_LENGTH;
    const clientId = process.env.OTPLESS_CLIENT_ID;
    const clientSecret = process.env.OTPLESS_CLIENT_SECRET;
    const { mobileNumber } = req.body;

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
    otpStore.set(mobileNumber, {
      orderId,
      timestamp: Date.now()
    });

    // Clean up old entries after 5 minutes
    setTimeout(() => {
      otpStore.delete(mobileNumber);
    }, 5 * 60 * 1000);

    return res.status(200).json({ 
      message: 'OTP sent successfully',
      success: true
    });
  } catch (error) {
    console.error('OTP Error:', error);
    return res.status(500).json({ 
      error: error.message,
      details: 'Failed to send OTP. Please try again.',
      success: false
    });
  }
};

// Step 2: Verify OTP and Login
const verifyOTPAndLogin = async (req, res) => {
  try {
    const { mobileNumber, otp } = req.body;
    console.log('Verifying OTP:', { mobileNumber, otp });
    
    const clientId = process.env.OTPLESS_CLIENT_ID;
    const clientSecret = process.env.OTPLESS_CLIENT_SECRET;

    if (!mobileNumber || !otp) {
      console.error('Missing required fields:', { mobileNumber, otp });
      return res.status(400).json({ 
        message: 'Mobile number and OTP are required',
        success: false 
      });
    }

    const phoneNumber = "+91"+mobileNumber;
    console.log('Verifying OTP for phone:', phoneNumber);

    // Get stored OTP details
    const storedData = otpStore.get(mobileNumber);
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
      let user = await User.findOne({ mobileNumber });
      if (!user) {
        user = new User({ mobileNumber });
        await user.save();
      }

      // Generate JWT
      const token = generateJWTToken(user._id);

      // Clear the stored OTP data
      otpStore.delete(mobileNumber);

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

// OTPLESS Authentication
const handleOtplessAuth = async (req, res) => {
  try {
    // Check required environment variables
    if (!process.env.JWT_SECRET) {
      console.error('Missing JWT_SECRET environment variable');
      return res.status(500).json({ 
        success: false, 
        message: 'Server configuration error' 
      });
    }

    const { waId, waNumber } = req.body;

    if (!waId || !waNumber) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing required WhatsApp authentication data' 
      });
    }

    // Clean phone number - remove any non-digit characters
    const cleanPhoneNumber = waNumber.replace(/\D/g, '');
    
    // Ensure it's a valid phone number
    if (!/^\d{10}$/.test(cleanPhoneNumber)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid phone number format'
      });
    }

    // Find or create user
    let user = await User.findOne({ whatsappId: waId });
    
    if (!user) {
      // Create new user
      user = new User({
        whatsappId: waId,
        mobileNumber: cleanPhoneNumber, // Use the cleaned phone number
        registeredAt: new Date()
      });
      await user.save();
    }

    // Generate JWT token
    const token = generateJWTToken(user._id);

    // Return success response
    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        mobileNumber: user.mobileNumber,
        whatsappId: user.whatsappId,
        firstName: user.firstName,
        lastName: user.lastName
      }
    });

  } catch (error) {
    console.error('OTPLESS auth error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Authentication failed' 
    });
  }
};

module.exports = {
  sendOTP,
  verifyOTPAndLogin,
  authenticateRequest,
  handleOtplessAuth
};
