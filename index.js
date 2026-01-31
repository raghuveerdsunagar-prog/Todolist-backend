const express = require("express");

const app = express();
const bcrypt = require("bcrypt");
// const multer = require('multer');
const cors = require("cors");
const path = require("path");
const { error } = require("console");
const SECRET_KEY = "keytomysql";
const jwt = require("jsonwebtoken");
const prisma = require("./config/Prisma");
// const validate=require("valiadte");
const {
  registerSchema,
  loginSchema,
  otpSchema,
  Taskschema,
} = require("./zod_validations/zod.js"); // adjust the path as needed


app.use(cors());
app.use(express.json());


const { z } = require("zod");
//middleware
const validate = (schema) => (req, res, next) => {
  try {
    req.body = schema.parse(req.body); // overwrite with parsed data
    next();
  } catch (err) {
    return res.status(400).json({ error: err.errors });
  }
};

const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",

  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Temporary OTP store (email → { otp, data })
const otpStore = {};

app.post("/user/uregi",validate(registerSchema), async (req, res) => {
  //  const checkQuery = 'SELECT * FROM regi WHERE email = ?';
  const { name, email, country, state, city, password } = req.body;
  console.log("Received body:", req.body);

  try {
    const existinguser = await prisma.regi.findUnique({ where: { email } });
    if (existinguser) {
      return res.status(400).json({ message: "user already exists" });
    }

    //   hash password with salt

    //generate otp
    const otp = Math.floor(Math.random() * 100000 + Math.random() * 900000);
    console.log(otp);

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: "your OTP code",
      text: `Your OTP is ${otp}. it is valid for 2 minutes.`,
    };

    //sendotp
    await transporter.sendMail(mailOptions);

    // store OTP + user data temporarily
    otpStore[email] = {
      otp,
      data: { name, email, country, state, city, password },
      expiresAt: Date.now() + 2 * 60 * 1000, // 2 minutes expiry
    };

    res.status(200).json({ message: "OTP sent sucessfully" });
  } catch (err) {
    console.log(err);

    res.status(500).json({ message: "error sending otp", error: err });
  }
});

app.post("/verifyotp", validate(otpSchema),async (req, res) => {
  const { email, otp } = req.body;

  try {
    const record = otpStore[email];
    if (!record)
      return res.status(400).json({ message: "no OTP found for this" });

    if (Date.now() > record.expiresAt) {
      delete otpStore[email];
      return res.status(410).json({ message: "otp expired" });
    }

    if (record.otp !== parseInt(otp)) {
      return res.status(401).json({ message: "Inavlid OTP" });
    }

    const { name, country, state, city, password } = record.data;
    console.log(record.data);
    const hashedpassword = await bcrypt.hash(password, 10);

    await prisma.regi.create({
      data: {
        name,
        email,
        Country: country || null, // match schema
        State: state || null,
        city,
        password: hashedpassword,
      },
    });

    delete otpStore[email]; // clear OTP after success

    res.status(200).json({ message: "Registration successful" });
  } catch (err) {
    console.error("OTP verification error:", err);
    res
      .status(500)
      .json({ message: "Error verifying OTP", error: err.message });
  }
});

//verifytoken
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized: No token provided" });
  }

  const token = authHeader.split(" ")[1];
  jwt.verify(token, SECRET_KEY, (err, decode) => {
    if (err) {
      return res.status(403).json({ error: "Invalid Token" });
    }
    req.user = decode; // contains userid and role
    next();
  });
};

// Role Authorization Middleware
const authorizeRoles = (roles) => async (req, res, next) => {
  if (!req.user || !roles.includes(req.user.userrole)) {
    return res.status(403).json({ error: "Access Denied" });
  }
  next();
};

let generatetoken = (userid, userrole) => {
  return jwt.sign({ userid, userrole }, SECRET_KEY, { expiresIn: "1h" });
};
app.post("/login", validate(loginSchema),async (req, res) => {
  const { email, password } = req.body;
  console.log(email, password);

  try {
    const user = await prisma.regi.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ message: "User not found" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: "Invalid password" });

    const token = generatetoken(user.userid, user.role);

    res.status(200).json({
      message: "Login successful",
      token,
      role: user.role,
    });
  } catch (err) {
    res.status(500).json({ message: "Database error", error: err.message });
  }
});

//   const query='SELECT * FROM regi WHERE email =?';

//generate JWT

// app.get("/udiplay", async (req, res) => {
// //   const displayquery = "select * from regi";

//   db.query(displayquery, (err, result) => {
//     if (err) {
//       return res
//         .status(500)
//         .json({ message: "error in fetching data", error: err });
//     } else {
//       return res.status(200).json(result);
//     }
//   });
// });

// const todos = await prisma.todolist.findMany({
//   where: { email: "req.user.userid" },
// });
// res.status(todos);




app.delete("/deleteuser/:id", async (req, res) => {
  const { id } = req.params;
  //   const deletquery = "DELETE FROM regi WHERE userid= ?";

  try {
    await prisma.regi.delete({
      where: { userid: parseInt(id) },
    });
    res.status(200).json({ message: "userv deleted successfully" });
  } catch (err) {
    res.status(500).json({ message: "error deleting user" });
  }
});

app.get(
  "/api/todo",
  verifyToken,
  authorizeRoles(["user"]),
  async (req, res) => {
    try {
      const userid = req.user.userid;

      // Read pagination params from query string
      const page = parseInt(req.query.page) || 1; // default page = 1
      const limit = parseInt(req.query.limit) || 5; // default limit = 5

      const skip = (page - 1) * limit;

      const todos = await prisma.todolist.findMany({
        where: { userid: userid },
        where: { userid },
        skip,
        take: limit,
        orderBy: { taskid: "asc" }, // optional: order by taskid
      });
      // Get total count for pagination metadata
      const total = await prisma.todolist.count({
        where: { userid },
      });

      res.status(200).json({
        data: todos,
        pagination: {
          total,
          page,
          limit,
          totalPages: Math.ceil(total / limit),
        },
      });
    } catch (err) {
      return res
        .status(500)
        .json({ message: "error in fetching data", error: err });
    }
  }
);

//deletdtask
app.delete(
  "/api/todo/:taskid",
  verifyToken,
  authorizeRoles(["user"]),
  async (req, res) => {
    try {
      const { taskid } = req.params;
      const userid = req.user.userid;

      if (!taskid || isNaN(taskid)) {
        return res.status(400).json({ message: "Invalid taskid" });
      }

      const result = await prisma.todolist.deleteMany({
        where: {
          taskid: parseInt(taskid),
          userid: userid,
        },
      });

      if (result.count === 0) {
        return res
          .status(404)
          .json({ message: "Task not found or not authorized" });
      }

      res.status(200).json({ message: "Task deleted successfully" });
    } catch (err) {
      res
        .status(500)
        .json({ message: "Error deleting task", error: err.message });
    }
  }
);

//createtask
app.post(
  "/addtask",
  verifyToken,
  authorizeRoles(["user"]),validate(Taskschema),
  async (req, res) => {
    const { taskname, description, status, date } = req.body;
    const userid = req.user.userid;

    try {
      const newTask = await prisma.todolist.create({
        data: {
          taskname,
          description,
          status,
          date: new Date(date),
          userid,
        },
      });

      res.json({
        message: "Todo added successfully",
        id: newTask.taskid, // or newTask.id depending on your schema
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  }
);

//fetchtask
app.get(
  "/api/todo/:taskid",
  verifyToken,
  authorizeRoles(["user"]),
  async (req, res) => {
    try {
      const { taskid } = req.params;
      const userid = req.user.useri; // from JWT payload\

      const task = await prisma.todolist.findFirst({
        where: { taskid: parseInt(taskid) },
        userid: userid,
      });
      if (!task) {
        return res.status(404).json({ message: "Task not found" });
      }

      res.json(task);
    } catch (err) {
      res.status(500).json({ err: err.message });
    }
  }
);

app.put(
  "/api/todo/:taskid",
  verifyToken,
  authorizeRoles(["user"]),
  async (req, res) => {
    try {
      const { taskid } = req.params;
      const { taskname, description, status, date } = req.body;
      const userid = req.user.userid;

      const formattedDate = date ? new Date(date) : null;

      // First check ownership
      const existingTask = await prisma.todolist.findFirst({
        where: {
          taskid: parseInt(taskid),
          userid: userid,
        },
      });

      if (!existingTask) {
        return res
          .status(404)
          .json({ message: "Task not found or not authorized" });
      }

      // Update by primary key
      const updatedTask = await prisma.todolist.update({
        where: { taskid: parseInt(taskid) },
        data: {
          taskname,
          description,
          status,
          date: formattedDate,
        },
      });

      res.json({ message: "Todo updated successfully", task: updatedTask });
    } catch (err) {
      console.error("Prisma Error:", err);
      res.status(500).json({ error: err.message });
    }
  }
);
app.listen(8000, (err) => {
  if (err) {
    console.log("error in starting up the server", err);
  } else {
    console.log("server ruuning on port 8000");
  }
});
