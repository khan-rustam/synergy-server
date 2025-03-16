// ============================================================================
// DEPENDENCIES AND CONFIGURATIONS
// ============================================================================
const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const fetch = require("node-fetch");
const nodemailer = require("nodemailer");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
const crypto = require("crypto");

// Load environment variables
dotenv.config();
console.log("🔧 Environment variables loaded successfully");

// ============================================================================
// DATABASE MODELS
// ============================================================================

// User Model
const userSchema = new mongoose.Schema(
  {
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    confirmPassword: { type: String, required: true },
    isAdmin: { type: Boolean, default: false },
    resetPasswordToken: { type: String, default: null },
    resetPasswordExpire: { type: Date, default: null },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

// Blog Model
const blogSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    content: { type: String, required: true },
    imageUrl: { type: String, required: true },
    tags: { type: [String], default: [] },
    status: { type: String, enum: ['draft', 'published'], default: 'draft' },
    author: { type: String, default: 'Admin' }
  },
  { timestamps: true }
);

const Blog = mongoose.model("Blog", blogSchema);


// Slide Model
const slideSchema = new mongoose.Schema(
  {
    imageUrl: { type: String, required: true }
  },
  { timestamps: true }
);

const Slide = mongoose.model("Slide", slideSchema);

// Testimonial Model
const testimonialSchema = new mongoose.Schema(
  {
    clientName: { type: String, required: true },
    companyName: { type: String, required: true },
    rating: { type: Number, required: true, min: 1, max: 5 },
    description: { type: String, required: true },
    imageUrl: { type: String, required: true }
  },
  { timestamps: true }
);

const Testimonial = mongoose.model("Testimonial", testimonialSchema);

// Contact Model
const contactSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true },
    message: { type: String, required: true },
    isRead: { type: Boolean, default: false },
  },
  { timestamps: true }
);

const Contact = mongoose.model("Contact", contactSchema);

// Client Logo Model
const clientLogoSchema = new mongoose.Schema(
  {
    imageUrl: { type: String, required: true }
  },
  { timestamps: true }
);

const ClientLogo = mongoose.model("ClientLogo", clientLogoSchema);

// ============================================================================
// MIDDLEWARE
// ============================================================================

// Auth Middleware
const protect = async (req, res, next) => {
  let token;
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    try {
      token = req.headers.authorization.split(" ")[1];
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = await User.findById(decoded.id).select("-password");
      next();
    } catch (error) {
      res
        .status(401)
        .json({ success: false, error: "Not authorized, token failed" });
    }
  }
  if (!token) {
    res.status(401).json({ success: false, error: "Not authorized, no token" });
  }
};

const admin = (req, res, next) => {
  if (req.user && req.user.isAdmin) {
    console.log("🔑 Admin authentication successful");
    next();
  } else {
    res
      .status(401)
      .json({ success: false, error: "Not authorized as an admin" });
  }
};

// Error Handler Middleware
const errorHandler = (err, req, res, next) => {
  const statusCode = res.statusCode === 200 ? 500 : res.statusCode;
  res.status(statusCode).json({
    success: false,
    message: err.message,
    stack: process.env.NODE_ENV === "production" ? null : err.stack,
  });
};

// Validation Middleware
const validateRegistration = [
  body("email").isEmail().withMessage("Email is required and must be valid."),
  body("password")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters long."),
  body("confirmPassword").exists().withMessage("Confirm Password is required."),
];

const validateResetPassword = [
  body("newPassword")
    .isLength({ min: 6 })
    .withMessage("Password must be at least 6 characters long."),
  body("confirmPassword").exists().withMessage("Confirm Password is required."),
];

// ============================================================================
// CONTROLLERS
// ============================================================================

// Helper Functions
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: "30d" });
};

const createTransporter = () => {
  return nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_APP_PASSWORD,
    },
  });
};

// User Controllers
const userController = {
  register: async (req, res) => {
    try {
      console.log("👤 Processing new user registration...");
      const { email, password, confirmPassword } = req.body;
      if (password !== confirmPassword) {
        console.log("❌ Registration failed: Passwords do not match");
        return res
          .status(400)
          .json({ success: false, error: "Passwords do not match" });
      }
      const userExists = await User.findOne({ email });
      if (userExists) {
        console.log("❌ Registration failed: User already exists");
        return res
          .status(400)
          .json({ success: false, error: "User already exists" });
      }
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      const user = await User.create({
        email,
        password: hashedPassword,
        confirmPassword: hashedPassword,
      });

      console.log("✅ User registered successfully:", user.email);
      res.status(201).json({
        success: true,
        data: {
          email: user.email,
          isAdmin: user.isAdmin,
          token: generateToken(user._id),
        },
      });
    } catch (error) {
      console.error("❌ Registration error:", error.message);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  login: async (req, res) => {
    try {
      console.log("🔐 Processing user login...");
      const { email, password } = req.body;
      const user = await User.findOne({ email });
      if (user && (await bcrypt.compare(password, user.password))) {
        console.log("✅ User logged in successfully:", email);
        res.json({
          success: true,
          data: {
            email: user.email,
            isAdmin: user.isAdmin,
            token: generateToken(user._id),
          },
        });
      } else {
        console.log("❌ Login failed: Invalid credentials");
        res
          .status(401)
          .json({ success: false, error: "Invalid email or password" });
      }
    } catch (error) {
      console.error("❌ Login error:", error.message);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  forgotPassword: async (req, res) => {
    try {
      console.log("🔑 Processing forgot password request...");
      const { email } = req.body;

      const user = await User.findOne({ email });
      if (!user) {
        console.log("❌ Forgot password failed: User not found");
        return res
          .status(404)
          .json({ success: false, error: "User not found" });
      }

      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      user.resetPasswordToken = otp;
      user.resetPasswordExpire = Date.now() + 10 * 60 * 1000;
      await user.save();

      const transporter = createTransporter();
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Password Reset OTP",
        html: `
                    <h1>Password Reset Request</h1>
                    <p>Your OTP for password reset is: <strong>${otp}</strong></p>
                    <p>This OTP is valid for 10 minutes.</p>
                    <p>If you did not request this, please ignore this email.</p>
                `,
      };

      await transporter.sendMail(mailOptions);
      console.log("✅ Password reset OTP sent successfully to:", email);

      res.json({ success: true, message: "OTP sent to your email" });
    } catch (error) {
      console.error("❌ Forgot password error:", error.message);
      res.status(500).json({ success: false, error: error.message });
    }
  },

  verifyOTP: async (req, res) => {
    try {
      const { email, otp } = req.body;

      // Find user with the given email and valid OTP
      const user = await User.findOne({
        email,
        resetPasswordToken: otp,
        resetPasswordExpire: { $gt: Date.now() },
      });

      if (!user) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid or expired OTP" });
      }

      res.json({ success: true, message: "OTP verified successfully" });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  resetPassword: async (req, res) => {
    try {
      const { email, otp, newPassword, confirmPassword } = req.body;

      // Validate passwords
      if (newPassword !== confirmPassword) {
        return res
          .status(400)
          .json({ success: false, error: "Passwords do not match" });
      }

      // Find user with the given email and valid OTP
      const user = await User.findOne({
        email,
        resetPasswordToken: otp,
        resetPasswordExpire: { $gt: Date.now() },
      });

      if (!user) {
        return res
          .status(400)
          .json({ success: false, error: "Invalid or expired OTP" });
      }

      // Update password
      const salt = await bcrypt.genSalt(10);
      user.password = await bcrypt.hash(newPassword, salt);
      user.confirmPassword = user.password;
      user.resetPasswordToken = null;
      user.resetPasswordExpire = null;
      await user.save();

      res.json({ success: true, message: "Password reset successful" });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },
};

// Blog Controllers
const blogController = {
  create: async (req, res) => {
    try {
      const blog = await Blog.create(req.body);
      res.status(201).json({ success: true, data: blog });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  getAll: async (req, res) => {
    try {
      const blogs = await Blog.find().sort({ createdAt: -1 });
      res.json({ success: true, data: blogs });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },
  
  getById: async (req, res) => {
    try {
      const blog = await Blog.findById(req.params.id);
      
      if (!blog) {
        return res.status(404).json({ 
          success: false, 
          error: "Blog not found" 
        });
      }
      
      res.json({ success: true, data: blog });
    } catch (error) {
      // Handle invalid ID format
      if (error.kind === 'ObjectId') {
        return res.status(400).json({ 
          success: false, 
          error: "Invalid blog ID format" 
        });
      }
      
      res.status(500).json({ success: false, error: error.message });
    }
  },
};


// Slide Controllers
const slideController = {
  create: async (req, res) => {
    try {
      const slide = await Slide.create(req.body);
      res.status(201).json({ success: true, data: slide });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  getAll: async (req, res) => {
    try {
      const slides = await Slide.find().sort({ createdAt: -1 });
      res.json({ success: true, data: slides });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },
};

// Testimonial Controllers
const testimonialController = {
  create: async (req, res) => {
    try {
      const testimonial = await Testimonial.create(req.body);
      res.status(201).json({ success: true, data: testimonial });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  getAll: async (req, res) => {
    try {
      const testimonials = await Testimonial.find().sort({ createdAt: -1 });
      res.json({ success: true, data: testimonials });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },
};

// Client Logo Controllers
const clientLogoController = {
  create: async (req, res) => {
    try {
      const clientLogo = await ClientLogo.create(req.body);
      res.status(201).json({ success: true, data: clientLogo });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  getAll: async (req, res) => {
    try {
      const clientLogos = await ClientLogo.find().sort({ createdAt: -1 });
      res.json({ success: true, data: clientLogos });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },
};

// Contact Controllers
const contactController = {
  create: async (req, res) => {
    try {
      const contact = await Contact.create(req.body);
      res.status(201).json({ success: true, data: contact });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  getAll: async (req, res) => {
    try {
      const contacts = await Contact.find().sort({ createdAt: -1 });
      res.json({ success: true, data: contacts });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  markAsRead: async (req, res) => {
    try {
      const contact = await Contact.findByIdAndUpdate(
        req.params.id,
        { isRead: true },
        { new: true }
      );
      
      if (!contact) {
        return res.status(404).json({ success: false, error: "Contact not found" });
      }
      
      res.json({ success: true, data: contact, message: "Contact marked as read" });
    } catch (error) {
      res.status(500).json({ success: false, error: error.message });
    }
  },

  submit: async (req, res) => {
    let dbSuccess = false;
    let emailSuccess = false;
    let userEmailSuccess = false;
    let adminEmailSuccess = false;

    try {
      // 1. Save contact form to database
      const { name, email, phone, message } = req.body;
      const contact = await Contact.create({
        name,
        email,
        message: `Phone: ${phone}\n\n${message}`,
      });

      dbSuccess = true;

      // 2. Send confirmation email to user
      const transporter = createTransporter();

      // User confirmation email
      const userMailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Thank you for contacting Synergy",
        html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
                        <h2 style="color: #e53e3e; margin-bottom: 20px;">Thank You for Contacting Synergy</h2>
                        <p>Dear ${name},</p>
                        <p>We have received your message and appreciate you taking the time to reach out to us.</p>
                        <p>Our team will review your inquiry and get back to you as soon as possible, usually within 24-48 business hours.</p>
                        <p>Here's a summary of your message:</p>
                        <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #e53e3e; margin: 20px 0;">
                            <p><strong>Phone:</strong> ${phone}</p>
                            <p><strong>Message:</strong> ${message}</p>
                        </div>
                        <p>If you have any additional questions or information to provide, please feel free to reply to this email.</p>
                        <p>Best regards,</p>
                        <p>The Synergy Team</p>
                    </div>
                `,
      };

      await transporter.sendMail(userMailOptions);
      userEmailSuccess = true;

      // Admin notification email
      const adminMailOptions = {
        from: process.env.EMAIL_USER,
        to: process.env.ADMIN_EMAIL || process.env.EMAIL_USER,
        subject: "New Contact Form Submission",
        html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 5px;">
                        <h2 style="color: #e53e3e; margin-bottom: 20px;">New Contact Form Submission</h2>
                        <p>A new contact form has been submitted on the Synergy website.</p>
                        <h3>Contact Details:</h3>
                        <ul style="list-style-type: none; padding-left: 0;">
                            <li><strong>Name:</strong> ${name}</li>
                            <li><strong>Email:</strong> ${email}</li>
                            <li><strong>Phone:</strong> ${phone}</li>
                        </ul>
                        <h3>Message:</h3>
                        <div style="background-color: #f9f9f9; padding: 15px; border-left: 4px solid #e53e3e; margin: 20px 0;">
                            <p>${message}</p>
                        </div>
                        <p>Please respond to this inquiry at your earliest convenience.</p>
                    </div>
                `,
      };

      await transporter.sendMail(adminMailOptions);
      adminEmailSuccess = true;

      emailSuccess = userEmailSuccess && adminEmailSuccess;

      res.status(201).json({
        success: true,
        dbSuccess,
        emailSuccess,
        userEmailSuccess,
        adminEmailSuccess,
        message: emailSuccess
          ? "Your message has been sent successfully!"
          : "Your message was saved but we could not send confirmation emails.",
      });
    } catch (error) {
      console.error("Contact form submission error:", error);
      res.status(500).json({
        success: false,
        dbSuccess,
        emailSuccess,
        userEmailSuccess,
        adminEmailSuccess,
        message: "There was an error processing your request.",
        error: error.message,
      });
    }
  },
};

// ============================================================================
// EXPRESS APP INITIALIZATION
// ============================================================================

const app = express();

// Security Middleware
app.use(helmet());
app.use(
  cors({
    origin: true, // Allow requests from any origin
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
app.use(mongoSanitize());
app.use(xss());

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use("/api", limiter);

// Body parser and compression
app.use(express.json({ limit: "10kb" }));
app.use(compression());

// ============================================================================
// ROUTES
// ============================================================================

// User Routes
app.post("/api/user/register", validateRegistration, userController.register);
app.post("/api/user/login", userController.login);
app.post("/api/user/forgot-password", userController.forgotPassword);
app.post("/api/user/verify-otp", userController.verifyOTP);
app.post(
  "/api/user/reset-password",
  validateResetPassword,
  userController.resetPassword
);

// Blog Routes
app.post("/api/blog/new", protect, admin, blogController.create);
app.get("/api/blog", blogController.getAll);
app.get("/api/blog/get-all", blogController.getAll);
app.get("/api/blog/get-by-id/:id", blogController.getById);
app.delete("/api/blog/delete/:id", protect, admin, async (req, res) => {
  try {
    const blog = await Blog.findByIdAndDelete(req.params.id);
    if (!blog) {
      return res.status(404).json({ success: false, error: "Blog not found" });
    }
    res.json({ success: true, message: "Blog deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});


// Slide Routes
app.post("/api/slide/new", protect, admin, slideController.create);
app.post("/api/slide", protect, admin, slideController.create);
app.get("/api/slide", slideController.getAll);
app.get("/api/slide/get-all", slideController.getAll);
app.delete("/api/slide/delete/:id", protect, admin, async (req, res) => {
  try {
    const slide = await Slide.findByIdAndDelete(req.params.id);
    if (!slide) {
      return res.status(404).json({ success: false, error: "Slide not found" });
    }
    res.json({ success: true, message: "Slide deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Testimonial Routes
app.post("/api/testimonial/new", protect, admin, testimonialController.create);
app.post("/api/testimonial", protect, admin, testimonialController.create);
app.get("/api/testimonial", testimonialController.getAll);
app.get("/api/testimonial/get-all", testimonialController.getAll);
app.delete("/api/testimonial/delete/:id", protect, admin, async (req, res) => {
  try {
    const testimonial = await Testimonial.findByIdAndDelete(req.params.id);
    if (!testimonial) {
      return res.status(404).json({ success: false, error: "Testimonial not found" });
    }
    res.json({ success: true, message: "Testimonial deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Client Logo Routes
app.post("/api/client-logo/new", protect, admin, clientLogoController.create);
app.post("/api/client-logo", protect, admin, clientLogoController.create);
app.get("/api/client-logo", clientLogoController.getAll);
app.get("/api/client-logo/get-all", clientLogoController.getAll);
app.delete("/api/client-logo/delete/:id", protect, admin, async (req, res) => {
  try {
    const clientLogo = await ClientLogo.findByIdAndDelete(req.params.id);
    if (!clientLogo) {
      return res.status(404).json({ success: false, error: "Client logo not found" });
    }
    res.json({ success: true, message: "Client logo deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Contact Routes
app.post("/api/contact", contactController.create);
app.post("/api/contact/submit", contactController.submit);
app.get("/api/contact", protect, admin, contactController.getAll);
app.get("/api/contact/get-all", protect, admin, contactController.getAll);
app.put("/api/contact/:id/mark-read", protect, admin, contactController.markAsRead);
app.delete("/api/contact/:id", protect, admin, async (req, res) => {
  try {
    const contact = await Contact.findByIdAndDelete(req.params.id);
    if (!contact) {
      return res.status(404).json({ success: false, error: "Contact not found" });
    }
    res.json({ success: true, message: "Contact deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// Cloudinary Route
app.delete(
  "/api/cloudinary/destroy/:publicId",
  protect,
  admin,
  async (req, res) => {
    const { publicId } = req.params;
    const timestamp = Math.round(new Date().getTime() / 1000);

    try {
      console.log(`🖼️ Attempting to delete Cloudinary image with public_id: ${publicId}`);
      
      if (
        !process.env.CLOUDINARY_CLOUD_NAME ||
        !process.env.CLOUDINARY_API_KEY ||
        !process.env.CLOUDINARY_API_SECRET
      ) {
        console.error("❌ Missing Cloudinary configuration");
        throw new Error("Missing Cloudinary configuration");
      }

      const signature = crypto
        .createHash("sha1")
        .update(
          `public_id=${publicId}&timestamp=${timestamp}${process.env.CLOUDINARY_API_SECRET}`
        )
        .digest("hex");

      console.log(`🔐 Generated signature for Cloudinary deletion: ${signature.substring(0, 10)}...`);
      
      const cloudinaryUrl = `https://api.cloudinary.com/v1_1/${process.env.CLOUDINARY_CLOUD_NAME}/image/destroy`;
      console.log(`🌐 Sending request to Cloudinary URL: ${cloudinaryUrl}`);
      
      const requestBody = {
        public_id: publicId,
        signature: signature,
        api_key: process.env.CLOUDINARY_API_KEY,
        timestamp: timestamp,
      };
      
      console.log(`📦 Request payload: ${JSON.stringify(requestBody)}`);

      const response = await fetch(cloudinaryUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(requestBody),
      });

      console.log(`📡 Cloudinary response status: ${response.status}`);
      
      const data = await response.json();
      console.log(`📄 Cloudinary response data: ${JSON.stringify(data)}`);
      
      if (data.result !== "ok") {
        console.error(`❌ Cloudinary deletion failed: ${JSON.stringify(data)}`);
        throw new Error(
          data.error?.message || "Failed to delete image from Cloudinary"
        );
      }

      console.log(`✅ Successfully deleted image from Cloudinary: ${publicId}`);
      res
        .status(200)
        .json({ success: true, message: "Image deleted successfully" });
    } catch (error) {
      console.error(`❌ Error deleting image from Cloudinary: ${error.message}`);
      console.error(error.stack);
      res.status(500).json({
        success: false,
        message: "Error deleting image",
        error: error.message,
      });
    }
  }
);

// Global Error Handler
app.use(errorHandler);

// ============================================================================
// DATABASE CONNECTION
// ============================================================================
const connectDB = async () => {
  try {
    console.log("🔄 Attempting to connect to MongoDB...");
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log("✅ MongoDB connected successfully ");
  } catch (error) {
    console.error("❌ MongoDB connection error:", error);
    console.log("🔄 Retrying connection in 5 seconds...");
    setTimeout(connectDB, 5000);
  }
};

// Initial connection
connectDB();

// Handle MongoDB connection errors
mongoose.connection.on("error", (err) => {
  console.error("❌ MongoDB error:", err);
});

mongoose.connection.on("disconnected", () => {
  console.log("🔌 MongoDB disconnected! Attempting to reconnect...");
  connectDB();
});

// ============================================================================
// ERROR HANDLING
// ============================================================================
process.on("unhandledRejection", (err) => {
  console.log("❌ UNHANDLED REJECTION! Shutting down...");
  console.log("Error:", err.name, err.message);
  process.exit(1);
});

process.on("uncaughtException", (err) => {
  console.log("❌ UNCAUGHT EXCEPTION! Shutting down...");
  console.log("Error:", err.name, err.message);
  process.exit(1);
});

// ============================================================================
// SERVER START
// ============================================================================
const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`
    🚀 Server is running!
    📡 Port: ${PORT}
    🌍 Environment: ${process.env.NODE_ENV}
    ⏰ Started at: ${new Date().toLocaleString()}
    `);
});

// Add logging middleware for all requests
app.use((req, res, next) => {
  console.log(
    `📥 ${req.method} request to ${req.url} at ${new Date().toLocaleString()}`
  );
  next();
});

// Add logging for successful responses
app.use((req, res, next) => {
  const originalSend = res.send;
  res.send = function (data) {
    console.log(
      `📤 Response sent for ${req.method} ${req.url} - Status: ${res.statusCode}`
    );
    originalSend.apply(res, arguments);
  };
  next();
});
