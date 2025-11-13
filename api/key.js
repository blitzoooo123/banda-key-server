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

    // 2. استخراج كلا المعرفين
    const serverId = req.query.server_id; 
    const processorId = req.query.processor_id; 

    // إذا لم يتم إرسال أي من المعرفين، نرسل المفتاح بتحذير
    if (!serverId || !processorId) {
        return res.status(200).json({ 
            status: "success", 
            key: AES_KEY, 
            warning: "Tracking skipped: Missing server_id or processor_id." 
        });
    }

    let client;
    try {
        client = await connectToDatabase();
        const db = client.db("key_control_db"); 
        const blacklist = db.collection("blacklist");
        const tracking = db.collection("tracking");

        // 3. التحقق من الحظر المزدوج (Server ID OR Processor ID) 🚨 التعديل الرئيسي هنا 🚨
        const isBlocked = await blacklist.findOne({
            $or: [
                { processorId: processorId }, // حظر الجهاز (HWID/MAC)
                { serverId: serverId }        // حظر السيرفر بالاسم
            ]
        }); 
        
        if (isBlocked) {
            // إرسال كود 403 (Forbidden) ليتم تعطيل البلجن
            return res.status(403).json({ status: "blocked", message: "Access revoked by admin." });
        }

        // 4. التحديث والتتبع في مجموعة 'tracking'
        await tracking.updateOne(
            // نستخدم processorId كمعرّف أساسي للتتبع
            { processorId: processorId }, 
            { 
                $set: { 
                    lastSeen: new Date(),
                    serverId: serverId // نخزن اسم السيرفر
                } 
            },
            { upsert: true }
        );
        
        // 5. إرسال المفتاح
        return res.status(200).json({ 
            status: "success", 
            key: AES_KEY 
        });

    } catch (error) {
        console.error("Database or Server Error:", error);
        return res.status(200).json({ status: "success", key: AES_KEY, warning: "DB connection failed, key granted." });
    }
};
