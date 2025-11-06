const { MongoClient } = require('mongodb');

// متغيرات البيئة السرية
const URI = process.env.MONGODB_URI;
const API_SECRET = process.env.API_SECRET;
const AES_KEY = process.env.AES_KEY; 

let dbClient = null;

async function connectToDatabase() {
    if (dbClient) return dbClient;
    
    // إنشاء اتصال جديد
    dbClient = await MongoClient.connect(URI);
    return dbClient;
}

module.exports = async (req, res) => {
    // 1. التحقق من الرمز المشترك (Shared Secret)
    const sentSecret = req.headers['x-api-secret'];
    if (sentSecret !== API_SECRET) {
        return res.status(401).json({ status: "error", message: "Unauthorized." });
    }

    // 2. استخراج المعرف الفريد (Server ID)
    const serverId = req.query.server_id;
    if (!serverId) {
        // إذا لم يرسل البلجن المعرف، نرسل المفتاح لتجنب التعطيل
        return res.status(200).json({ status: "success", key: AES_KEY, warning: "Tracking skipped: Missing server_id." });
    }

    let client;
    try {
        client = await connectToDatabase();
        // 🚨 تأكد من اسم قاعدة البيانات هنا 🚨
        const db = client.db("key_control_db"); 
        const blacklist = db.collection("blacklist");
        const tracking = db.collection("tracking");

        // 3. التحقق من الحظر الفوري (Is Blocked?)
        const isBlocked = await blacklist.findOne({ serverId: serverId });
        if (isBlocked) {
            // إرسال كود 403 (Forbidden) ليتم تعطيل البلجن
            return res.status(403).json({ status: "blocked", message: "Access revoked by admin." });
        }

        // 4. التحديث والتتبع في مجموعة 'tracking'
        await tracking.updateOne(
            { serverId: serverId },
            { $set: { lastSeen: new Date() } },
            { upsert: true } // ينشئ سجلًا جديدًا إذا لم يجده
        );
        
        // 5. إرسال المفتاح
        return res.status(200).json({ 
            status: "success", 
            key: AES_KEY 
        });

    } catch (error) {
        console.error("Database or Server Error:", error);
        // في حالة فشل الاتصال بـ DB، نرسل المفتاح كإجراء أمان لمنع تعطل السيرفر
        return res.status(200).json({ status: "success", key: AES_KEY, warning: "DB connection failed, key granted." });
    }
};
