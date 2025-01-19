import env from '../../config/env';
import React, { useState, useRef, useEffect } from 'react';
import { View, Text, StyleSheet, TextInput, TouchableOpacity, Alert, Platform } from 'react-native';
import { useNavigation, useRoute } from '@react-navigation/native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import BackButton from '../../components/BackButton';

const OTPVerification = () => {
  const [otp, setOtp] = useState(['', '', '', '']);
  const inputRefs = useRef([]);
  const navigation = useNavigation();
  const route = useRoute();
  const { mobileNumber = '', language = 'English' } = route.params || {};
  const [timer, setTimer] = useState(30);

  // Log navigation params
  useEffect(() => {
    console.log('OTPVerification mounted with params:', { mobileNumber, language });
  }, [mobileNumber, language]);

  const translations = {
    English: {
      header: 'OTP Verification',
      subHeader: `Please check your ${mobileNumber} to see the verification code`,
      otpLabel: 'OTP Code',
      verifyButtonText: 'Verify',
      resendText: 'Resending code in',
    },
    Marathi: {
      header: 'OTP पडताळणी',
      subHeader: `कृपया तुमच्या ${mobileNumber} वर OTP कोड पहा`,
      otpLabel: 'OTP कोड',
      verifyButtonText: 'पडताळा',
      resendText: 'कोड पुन्हा पाठविला जात आहे',
    },
    Hindi: {
      header: 'OTP सत्यापन',
      subHeader: `कृपया अपने ${mobileNumber} पर सत्यापन कोड देखें`,
      otpLabel: 'OTP कोड',
      verifyButtonText: 'सत्यापित करें',
      resendText: 'कोड फिर से भेजा जा रहा है',
    },
  };

  const { header, subHeader, otpLabel, verifyButtonText, resendText } = translations[language || 'English'];

  useEffect(() => {
    // Start timer
    if (timer > 0) {
      const interval = setInterval(() => {
        setTimer((prevTimer) => prevTimer - 1);
      }, 1000);

      return () => clearInterval(interval);
    }
  }, [timer]);

  const handleOtpChange = (text: string, index: number) => {
    const newOtp = [...otp];
    newOtp[index] = text;
    setOtp(newOtp);

    // Auto-focus next input
    if (text && index < 3) {
      inputRefs.current[index + 1].focus();
    }
  };

  const handleKeyPress = (e: any, index: number) => {
    if (e.nativeEvent.key === 'Backspace' && !otp[index] && index > 0) {
      inputRefs.current[index - 1].focus();
    }
  };

  const verifyOTP = async () => {
    try {
      const otpValue = otp.join('');
      console.log('Verifying OTP with data:', { mobileNumber, otp: otpValue });

      const response = await fetch(`${env.API_URL}login/verify`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json'
        },
        body: JSON.stringify({
          mobile: mobileNumber,
          otp: otpValue
        }),
      });

      console.log('Verification response status:', response.status);
      const data = await response.json();
      console.log('Verification response:', data);

      if (response.ok && data.success) {
        // Store the token
        const token = "Bearer " + data.token;
        console.log('Token received:', token);
        await AsyncStorage.setItem('token', token);

        // Navigate based on user status
        if (data.userStatus === 'In Progress') {
          navigation.navigate('JoinInNow');
        } else {
          navigation.navigate('Home');
        }
      } else {
        throw new Error(data.message || 'Invalid OTP');
      }
    } catch (error) {
      console.error('OTP verification failed:', error);
      Alert.alert(
        'Error',
        error.message || 'Failed to verify OTP. Please try again.',
        [{ text: 'OK' }]
      );
      
      // Clear OTP fields on error
      setOtp(['', '', '', '']);
      inputRefs.current[0]?.focus();
    }
  };

  const resendOTP = async () => {
    try {
      const response = await fetch(`${env.API_URL}login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          mobileNumber
        }),
      });

      const data = await response.json();
      
      if (response.ok && data.success) {
        setTimer(30);
        Alert.alert('Success', 'OTP sent successfully!');
      } else {
        Alert.alert('Error', data.message || 'Failed to send OTP');
      }
    } catch (error) {
      console.error('Send OTP error:', error);
      Alert.alert('Error', 'Failed to send OTP. Please try again.');
    }
  };

  return (
    <View style={styles.container}>
      <BackButton />
      <Text style={styles.header}>{header}</Text>
      <Text style={styles.subHeader}>{subHeader}</Text>
      
      <View style={styles.otpContainer}>
        <Text style={styles.otpLabel}>{otpLabel}</Text>
        <View style={styles.inputContainer}>
          {otp.map((digit, index) => (
            <TextInput
              key={index}
              ref={ref => inputRefs.current[index] = ref}
              style={styles.input}
              value={digit}
              onChangeText={text => handleOtpChange(text.replace(/[^0-9]/g, ''), index)}
              keyboardType="numeric"
              maxLength={1}
              onKeyPress={e => handleKeyPress(e, index)}
            />
          ))}
        </View>
      </View>

      <TouchableOpacity
        style={styles.verifyButton}
        onPress={verifyOTP}
        disabled={otp.some(digit => !digit)}
      >
        <Text style={styles.verifyButtonText}>{verifyButtonText}</Text>
      </TouchableOpacity>

      {timer > 0 ? (
        <Text style={styles.timerText}>{`${resendText} ${timer}s`}</Text>
      ) : (
        <TouchableOpacity onPress={resendOTP}>
          <Text style={styles.resendButton}>Resend OTP</Text>
        </TouchableOpacity>
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    paddingHorizontal: 20,
    backgroundColor: 'white',
  },
  header: {
    fontSize: 24,
    fontWeight: 'bold',
    marginTop: 50,
    marginBottom: 10,
  },
  subHeader: {
    fontSize: 16,
    color: '#666',
    marginBottom: 30,
  },
  otpContainer: {
    marginBottom: 30,
  },
  otpLabel: {
    fontSize: 16,
    marginBottom: 10,
  },
  inputContainer: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    marginBottom: 30,
  },
  input: {
    width: 50,
    height: 50,
    borderWidth: 1,
    borderRadius: 10,
    textAlign: 'center',
    fontSize: 24,
    marginHorizontal: 5,
  },
  verifyButton: {
    backgroundColor: '#007AFF',
    paddingVertical: 15,
    borderRadius: 10,
    alignItems: 'center',
    marginBottom: 20,
  },
  verifyButtonText: {
    color: 'white',
    fontSize: 18,
    fontWeight: 'bold',
  },
  timerText: {
    textAlign: 'center',
    color: '#666',
  },
  resendButton: {
    color: '#007AFF',
    textAlign: 'center',
    fontSize: 16,
  },
});

export default OTPVerification;
