const mongoose = require('mongoose')
const AutoIncrement = require('mongoose-sequence')(mongoose);

//define schema
const transactionSchema = new mongoose.Schema({
  transactionId: {
    type: Number,
    unique: true,
    auto: true, 
  },
  userId: {
    type: Number,
    required: true,
  },
  transactionDescription: {
    type: String,
    required: false,
  },
  transactionAmount: {
    type: Number,
    required: true,
  },
  transactionType: {
    type: String,
    enum: ['debited', 'credited'],
    required: true,
  },
  transactionDate: {
    type: Date,
    required: true,
    default: Date.now,
  }
});

transactionSchema.plugin(AutoIncrement, { inc_field: 'transactionId' });
//model create by using schema
const Transaction = mongoose.model('transaction',transactionSchema);

module.exports = Transaction;