const express = require('express');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');
const path = require('path');
require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json({ limit: '10mb' })); // Base64 images handle panraku limit increase panniyirukku

app.get('/admin-login.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../Front end/admin-login.html'));
});
app.get('/admin-register.html', (req, res) => {
    res.sendFile(path.join(__dirname, '../Front end/admin-register.html'));
});
app.use(express.static(path.join(__dirname, '../Front end')));
app.use(express.static('Front end')); // fallback support

// Session Middleware Configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'poster_paradise_secure_secret_key_2026',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // true if using HTTPS in production
        httpOnly: true,
        sameSite: 'lax', // Added to ensure cookie persists properly after login redirection
        maxAge: 24 * 60 * 60 * 1000 // 1 Day session validity
    }
}));

// Supabase Client Connection using Secret Key for Backend Admin operations
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// --- ACTIVE VISITORS IN-MEMORY STORE ---
const activeVisitorsMap = new Map();

// Cleanup inactive visitors every 10 seconds (if no heartbeat for 10 seconds)
setInterval(() => {
    const now = Date.now();
    for (const [sessionId, timestamp] of activeVisitorsMap.entries()) {
        if (now - timestamp > 10000) {
            activeVisitorsMap.delete(sessionId);
        }
    }
}, 10000);

// --- AUTHENTICATION MIDDLEWARE ---
const requireAdminAuth = (req, res, next) => {
    if (req.session && req.session.isAdminLoggedIn) {
        return next();
    }
    return res.status(401).json({ error: 'Unauthorized access. Please login.' });
};

const requireUserAuth = (req, res, next) => {
    if (req.session && req.session.isUserLoggedIn) {
        return next();
    }
    return res.status(401).json({ error: 'Please login or create an account to use the cart.' });
};

// --- ADMIN AUTH ROUTES ---
app.post('/api/admin/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password are required' });
    }

    try {
        // Check if admin already exists
        const { data: existingAdmin } = await supabase
            .from('admins')
            .select('*')
            .eq('username', username)
            .single();

        if (existingAdmin) {
            return res.status(400).json({ error: 'Username already exists' });
        }

        // Hash password securely
        const saltRounds = 10;
        const password_hash = await bcrypt.hash(password, saltRounds);

        // Insert new admin into database
        const { error } = await supabase
            .from('admins')
            .insert([{ username, password_hash }]);

        if (error) {
            console.error("Supabase admin registration error:", error);
            return res.status(500).json({ error: error.message });
        }

        res.json({ message: 'Admin registered successfully!' });
    } catch (err) {
        console.error("Registration error:", err);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const { data: admin, error } = await supabase
            .from('admins')
            .select('*')
            .eq('username', username)
            .single();

        if (error || !admin) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        const isPasswordValid = await bcrypt.compare(password, admin.password_hash);
        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Invalid username or password' });
        }

        req.session.isAdminLoggedIn = true;
        req.session.adminUser = admin.username;
        res.json({ message: 'Login successful!' });
    } catch (err) {
        console.error("Login error:", err);
        res.status(500).json({ error: 'Server error during login' });
    }
});

app.get('/api/admin/check-session', (req, res) => {
    if (req.session && req.session.isAdminLoggedIn) {
        return res.json({ authenticated: true, user: req.session.adminUser });
    }
    res.json({ authenticated: false });
});

app.post('/api/admin/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).json({ error: 'Could not log out.' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Logged out successfully!' });
    });
});


// --- ADMIN STATS & ACTIVE VISITORS API ROUTE ---
app.get('/api/admin/stats', requireAdminAuth, async (req, res) => {
    try {
        const { count: userCount, error: userError } = await supabase
            .from('users')
            .select('*', { count: 'exact', head: true });

        if (userError) {
            console.error("Stats fetch error:", userError);
            return res.status(500).json({ error: 'Failed to fetch admin stats' });
        }

        res.json({
            totalUsers: userCount || 0,
            activeVisitors: activeVisitorsMap.size
        });
    } catch (err) {
        console.error("Server stats error:", err);
        res.status(500).json({ error: err.message });
    }
});


// --- LIVE VISITOR HEARTBEAT ROUTE ---
app.post('/api/user/heartbeat', (req, res) => {
    const sessionId = req.sessionID || (req.body && req.body.clientId);
    if (sessionId) {
        activeVisitorsMap.set(sessionId, Date.now());
    }
    res.json({ status: 'ok', activeVisitors: activeVisitorsMap.size });
});


// --- CUSTOMER ACCOUNT & PROFILE ROUTES ---
app.post('/api/user/register', async (req, res) => {
    const { name, phone, password, address } = req.body;
    if (!name || !phone || !password) {
        return res.status(400).json({ error: 'Name, phone number and password are required' });
    }

    try {
        const { data: existingUser } = await supabase
            .from('users')
            .select('*')
            .eq('phone', phone)
            .single();

        if (existingUser) {
            return res.status(400).json({ error: 'An account with this phone number already exists.' });
        }

        const saltRounds = 10;
        const password_hash = await bcrypt.hash(password, saltRounds);

        const { data, error } = await supabase
            .from('users')
            .insert([{ name, phone, password_hash, address }])
            .select()
            .single();

        if (error) {
            console.error("Supabase user registration error:", error);
            return res.status(500).json({ error: error.message });
        }

        req.session.isUserLoggedIn = true;
        req.session.userId = data.id;
        req.session.userName = data.name;
        req.session.userPhone = data.phone;

        res.json({ message: 'Account created successfully!', user: { id: data.id, name: data.name, phone: data.phone, address: data.address } });
    } catch (err) {
        console.error("User registration error:", err);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

app.post('/api/user/login', async (req, res) => {
    const { phone, password } = req.body;
    if (!phone || !password) {
        return res.status(400).json({ error: 'Phone number and password are required' });
    }

    try {
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('phone', phone)
            .single();

        if (error || !user) {
            return res.status(400).json({ error: 'Invalid phone number or password' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password_hash);
        if (!isPasswordValid) {
            return res.status(400).json({ error: 'Invalid phone number or password' });
        }

        req.session.isUserLoggedIn = true;
        req.session.userId = user.id;
        req.session.userName = user.name;
        req.session.userPhone = user.phone;

        res.json({ message: 'Login successful!', user: { id: user.id, name: user.name, phone: user.phone, address: user.address } });
    } catch (err) {
        console.error("User login error:", err);
        res.status(500).json({ error: 'Server error during login' });
    }
});

app.get('/api/user/check-session', async (req, res) => {
    if (req.session && req.session.isUserLoggedIn) {
        try {
            const { data: user } = await supabase
                .from('users')
                .select('id, name, phone, address')
                .eq('id', req.session.userId)
                .single();
            return res.json({ authenticated: true, user: user || { name: req.session.userName, phone: req.session.userPhone } });
        } catch (err) {
            return res.json({ authenticated: true, user: { name: req.session.userName, phone: req.session.userPhone } });
        }
    }
    res.json({ authenticated: false });
});

app.post('/api/user/logout', (req, res) => {
    if (req.session) {
        req.session.isUserLoggedIn = false;
        req.session.userId = null;
        req.session.userName = null;
        req.session.userPhone = null;
    }
    res.json({ message: 'Logged out successfully!' });
});


// --- CUSTOMER CART ROUTES ---
app.get('/api/cart', requireUserAuth, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('cart_items')
            .select('*')
            .eq('user_id', req.session.userId);

        if (error) {
            return res.status(500).json({ error: error.message });
        }
        res.json(Array.isArray(data) ? data : []);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/cart', requireUserAuth, async (req, res) => {
    const { title, price, size, quantity, image_url } = req.body;
    if (!title || !price || !size || !quantity) {
        return res.status(400).json({ error: 'Invalid cart item details' });
    }

    try {
        const { data, error } = await supabase
            .from('cart_items')
            .insert([{ user_id: req.session.userId, title, price, size, quantity, image_url }])
            .select();

        if (error) {
            return res.status(500).json({ error: error.message });
        }
        res.json({ message: 'Item added to cart successfully!', item: data[0] });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/cart/:id', requireUserAuth, async (req, res) => {
    const { id } = req.params;
    try {
        const { error } = await supabase
            .from('cart_items')
            .delete()
            .eq('id', id)
            .eq('user_id', req.session.userId);

        if (error) {
            return res.status(500).json({ error: error.message });
        }
        res.json({ message: 'Cart item removed successfully!' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/cart', requireUserAuth, async (req, res) => {
    try {
        const { error } = await supabase
            .from('cart_items')
            .delete()
            .eq('user_id', req.session.userId);

        if (error) {
            return res.status(500).json({ error: error.message });
        }
        res.json({ message: 'Cart cleared successfully!' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// --- 1. SETTINGS ROUTES ---
app.get('/api/settings', async (req, res) => {
    try {
        const { data, error } = await supabase.from('settings').select('*').limit(1).single();
        if (error) {
            return res.json({});
        }
        res.json(data || {});
    } catch (err) {
        res.json({});
    }
});

app.post('/api/settings', requireAdminAuth, async (req, res) => {
    const { 
        liveLocation, 
        banner1, 
        banner2, 
        bannerDesktop1, 
        bannerDesktop2, 
        bannerMobile1, 
        bannerMobile2, 
        isLive, 
        advanceEnabled, 
        deliveryCharge,
        upiQr, 
        whatsappTemplate 
    } = req.body;
    
    const { data: existing } = await supabase.from('settings').select('id').limit(1).single();
    
    let result;
    if (existing && existing.id) {
        result = await supabase
            .from('settings')
            .update({ 
                liveLocation, 
                banner1, 
                banner2, 
                bannerDesktop1, 
                bannerDesktop2, 
                bannerMobile1, 
                bannerMobile2, 
                isLive, 
                advanceEnabled, 
                deliveryCharge,
                upiQr, 
                whatsappTemplate 
            })
            .eq('id', existing.id);
    } else {
        result = await supabase
            .from('settings')
            .insert([{ 
                liveLocation, 
                banner1, 
                banner2, 
                bannerDesktop1, 
                bannerDesktop2, 
                bannerMobile1, 
                bannerMobile2, 
                isLive, 
                advanceEnabled, 
                deliveryCharge,
                upiQr, 
                whatsappTemplate 
            }]);
    }
    
    if (result.error) {
        console.error("Supabase settings error:", result.error);
        return res.status(500).json({ error: result.error.message });
    }
    res.json({ message: "Settings saved successfully!" });
});


// --- 2. CATEGORIES ROUTES ---
app.get('/api/categories', async (req, res) => {
    try {
        const { data, error } = await supabase.from('categories').select('*');
        if (error) {
            console.error("Supabase categories error:", error);
            return res.status(500).json({ error: error.message });
        }
        res.json(Array.isArray(data) ? data : []);
    } catch (err) {
        console.error("Server error:", err);
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/categories', requireAdminAuth, async (req, res) => {
    const { id, title, driveUrl, posters } = req.body;
    const { data, error } = await supabase.from('categories').upsert([{ id, title, driveUrl, posters }]);
    if (error) {
        console.error("Supabase category save error:", error);
        return res.status(500).json({ error: error.message });
    }
    res.json({ message: "Category saved successfully!", data });
});

app.delete('/api/categories/:id', requireAdminAuth, async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('categories').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: "Category deleted successfully!" });
});


// --- 3. TESTIMONIALS ROUTES ---
app.get('/api/testimonials', async (req, res) => {
    try {
        const { data, error } = await supabase.from('testimonials').select('*');
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        res.json(Array.isArray(data) ? data : []);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/testimonials', requireAdminAuth, async (req, res) => {
    const { name, city, image, text } = req.body;
    const { data, error } = await supabase.from('testimonials').insert([{ name, city, image, text }]);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: "Testimonial added successfully!", data });
});

app.delete('/api/testimonials/:id', requireAdminAuth, async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('testimonials').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: "Testimonial deleted successfully!" });
});


// --- 4. FEEDBACKS ROUTES ---
app.get('/api/feedbacks', requireAdminAuth, async (req, res) => {
    try {
        const { data, error } = await supabase.from('feedbacks').select('*');
        if (error) {
            return res.status(500).json({ error: error.message });
        }
        res.json(Array.isArray(data) ? data : []);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/feedbacks', async (req, res) => {
    const { name, city, text } = req.body;
    const { data, error } = await supabase.from('feedbacks').insert([{ name, city, text }]);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: "Feedback submitted successfully!", data });
});

app.delete('/api/feedbacks/:id', requireAdminAuth, async (req, res) => {
    const { id } = req.params;
    const { error } = await supabase.from('feedbacks').delete().eq('id', id);
    if (error) return res.status(500).json({ error: error.message });
    res.json({ message: "Feedback deleted successfully!" });
});

app.get('/', (req, res) => {
  res.send('Poster Paradise Backend is running successfully!');
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
    console.log(`Poster Paradise Backend running on port ${PORT}`);
    
    // Test Database Connection on Startup
    try {
        const { error } = await supabase.from('settings').select('*').limit(1);
        if (error) {
            console.error("❌ Database Connection Failed:", error.message);
        } else {
            console.log("✅ Supabase Database Connected Successfully!");
        }
    } catch (err) {
        console.error("❌ Database Connection Error:", err.message);
    }
});