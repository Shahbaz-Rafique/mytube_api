// Import necessary modules and models
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const { transporter } = require('../Utils/nodemailer');
const crypto = require('crypto');
const { auth, adminAuth } = require('../middleware/authMiddleware');

// Endpoint to for admin verification
router.get('/isadmin', adminAuth, async (req, res) => {
    let user = await User.findOne({ _id: req.user.id })
    if (user.email !== 'admin@gmail.com') {
        return res.status(400).json({
            success: false,
            message: "Not authorized as an admin"
        })
    }
    res.json({
        success: true,
        message: "Admin verified successfully"
    })
})

// End point for Admin Panel Login
router.post('/adminpanellogin', async (req, res) => {
    try {
        let user = await User.findOne({ email: process.env.ADMIN_EMAIL });
        if (!user) {
            const adminPassword = process.env.ADMIN_PASSWORD;
            const hashedPassword = await hashPassword(adminPassword);
            const newUser = new User({
                name: 'admin',
                email: 'admin@gmail.com',
                profile_image: 'https://www.gravatar.com/avatar/',
                password: hashedPassword,
            });

            user = await newUser.save();

            if (!user) {
                return res.status(500).json({
                    success: false,
                    message: 'Error creating admin user',
                });
            }
        }

        const emailMatch = req.body.email === user.email;

        if (!emailMatch) {
            console.log('email does not match');
            return res.status(400).json({
                success: false,
                message: 'Incorrect email',
            });
        }

        const passwordMatch = await bcrypt.compare(req.body.password, user.password);

        if (!passwordMatch) {
            console.log('password does not match');
            return res.status(400).json({
                success: false,
                message: 'Incorrect password',
            });
        }

        const data = {
            user: {
                id: user.id,
            },
        };

        const token = jwt.sign(data, req.body.password, { expiresIn: '1h' });
        res.json({
            success: true,
            token,
            message: 'Admin logged in successfully',
        });
    } catch (error) {
        console.error('Error during admin panel login:', error.message);
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
});


// Registration route
router.post('/register', async (req, res) => {
    console.log(req.body);
    try {
        let check = await User.findOne({ email: req.body.email });

        if (check) {
            return res.status(400).json({
                success: false,
                message: "User already exists",
            });
        }

        const hashedPassword = await crypto.createHash('sha256').update(req.body.password).digest('hex');

        const user = new User({
            name: req.body.name,
            email: req.body.email,
            profile_image: req.body.profile_image,
            password: hashedPassword,
        });

        await user.save();

        const data = {
            user: {
                id: user.id,
            },
        };

        const token = jwt.sign(data, process.env.JWT_SECRET);

        const mailOptions = {
            from: 'MyTube <shahbazrafique429@gmail.com>',
            to: req.body.email,
            subject: "You have been added as a user to MyTube",
            html: `We are excited to welcome you to MyTube, the ultimate platform for sharing and discovering amazing videos! This email is to inform you that your account has been created successfully by our administrator.
            <br/>
            Your MyTube Account Details:
            <br/>
            Email: ${req.body.email}<br/>
            Password: ${req.body.password} `,
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error);
            } else {
                res.status(201).json({
                    success: true,
                    token,
                    message: "User registered successfully",
                });
            }
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
});

//checkSignin

router.post('/signin', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Check if the user exists
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password',
            });
        }

        // Compare the password
        // const passwordMatch = await bcrypt.compare(password, user.password);
        const passwordMatch = await crypto.createHash('sha256').update(password).digest('hex');
        console.log(email, user.password, passwordMatch );
        if (user.password!=passwordMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password',
            });
        }


        // Create token
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

        // Send response with token
        res.status(200).json({
            success: true,
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                profile_image: user.profile_image,
            },
            message: 'User signed in successfully',
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            success: false,
            message: 'Internal Server Error',
        });
    }
});


// List users route
router.get('/list', async (req, res) => {
    try {
        const users = await User.find();
        res.status(200).json({
            success: true,
            users,
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
});

// Update user route
router.put('/update/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const updatedUser = await User.findByIdAndUpdate(userId, req.body, { new: true });

        if (!updatedUser) {
            return res.status(404).json({
                success: false,
                message: "User not found",
            });
        }

        console.log(updatedUser);

        res.status(200).json({
            success: true,
            user: updatedUser,
            message: "User updated successfully",
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
});

// Delete user route
router.delete('/delete/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const deletedUser = await User.findByIdAndDelete(userId);

        if (!deletedUser) {
            return res.status(404).json({
                success: false,
                message: "User not found",
            });
        }

        res.status(200).json({
            success: true,
            message: "User deleted successfully",
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
});


// update use pasword

router.put('/updatePassword/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;
        const { currentPassword, newPassword, confirmPassword } = req.body;

        // Validate that newPassword and confirmPassword match

        console.log(currentPassword, newPassword, confirmPassword)

        // if (newPassword !== confirmPassword) {
        //     return res.status(400).json({
        //         success: false,
        //         message: "New password and confirm password do not eo19",
        //     });
        // }

        // Retrieve the user from the database
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found",
            });
        }

        // Compare the currentPassword with the user's current hashed password
        const passwordMatch = await bcrypt.compare(currentPassword, user.password);
        if (!passwordMatch) {
            return res.status(400).json({
                success: false,
                message: "Current password is incorrect",
            });
        }

        // Hash the newPassword
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update the user's password in the database
        const updatedUser = await User.findByIdAndUpdate(userId, { password: hashedPassword }, { new: true });

        res.status(200).json({
            success: true,
            user: updatedUser,
            message: "Password updated successfully",
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message,
        });
    }
});


// get user by Id




router.get('/getUser/:userId', async (req, res) => {
    try {
        const userId = req.params.userId;

        // Find the user by ID
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found',
            });
        }

        // If the user is found, return the user data
        res.status(200).json({
            success: true,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                profile_image: user.profile_image,
            },
            message: 'User found successfully',
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({
            success: false,
            message: 'Internal Server Error',
        });
    }
});

module.exports = router;
