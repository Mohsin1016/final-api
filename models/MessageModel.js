const mongoose = require("mongoose");

const MessageSchema = new mongoose.Schema(
  {
    sender: { type: mongoose.Schema.Types.ObjectId, ref: "user" },
    recipient: { type: mongoose.Schema.Types.ObjectId, ref: "user" },
    text: String,
    file: String,
  },
  { timestamps: true } // Use timestamps instead of timeseries
);

const MessageModel = mongoose.model("message", MessageSchema); // Corrected typo "meesage" to "message"
module.exports = MessageModel;
