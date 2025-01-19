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

    // For SMS OTP, we don't need email or orderId
    const response = await UserDetail.sendOTP(
      phoneNumber,   // phone number
      null,         // email (not needed for SMS)
      channel,      // SMS channel
      null,         // hash (optional)
      null,         // orderId (optional)
      expiry,       // expiry
      otpLength,    // otpLength
      clientId,     // clientId
      clientSecret  // clientSecret
    );
    console.log('OTP Response:', response);

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

    // Try with orderId first
    const orderId = generateUniqueValue();
    console.log('Attempting verification with new orderId:', orderId);

    try {
      const response = await UserDetail.verifyOTP(
        "",           // email (not needed for SMS)
        phoneNumber,  // phone
        orderId,      // trying with a new orderId
        otp,         // otp
        clientId,    // clientId
        clientSecret // clientSecret
      );
      console.log('Full OTP verification response:', JSON.stringify(response, null, 2));

      if (response && response.isOTPVerified) {
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
      } else {
        // Try without orderId as fallback
        console.log('First attempt failed, trying without orderId');
        const fallbackResponse = await UserDetail.verifyOTP(
          "",           // email
          phoneNumber,  // phone
          null,        // no orderId
          otp,         // otp
          clientId,    // clientId
          clientSecret // clientSecret
        );
        console.log('Fallback verification response:', JSON.stringify(fallbackResponse, null, 2));

        if (!fallbackResponse || !fallbackResponse.isOTPVerified) {
          console.error('Both verification attempts failed:', { 
            firstAttempt: response,
            fallbackAttempt: fallbackResponse 
          });
          return res.status(400).json({ 
            message: 'Invalid OTP',
            success: false 
          });
        }

        // If fallback succeeds, proceed with user creation/login
        let user = await User.findOne({ mobileNumber });
        if (!user) {
          user = new User({ mobileNumber });
          await user.save();
        }

        const token = generateJWTToken(user._id);
        return res.status(200).json({
          token,
          userStatus: user.status || 'In Progress',
          message: 'Login successful',
          success: true
        });
      }
    } catch (verifyError) {
      console.error('OTP verification error:', verifyError);
      throw verifyError;
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
