const { MongoClient } = require('mongodb');

// متغيرات البيئة السرية
const URI = process.env.MONGODB_URI;
const API_SECRET = process.env.API_SECRET;
const AES_KEY = process.env.AES_KEY; 

let dbClient = null;

async function connectToDatabase() {
    if (dbClient) return dbClient;
    
    dbClient = await MongoClient.connect(URI);
    return dbClient;
}

module.exports = async (req, res) => {
    // 1. التحقق من الرمز المشترك (Shared Secret)
    const sentSecret = req.headers['x-api-secret'];
    if (sentSecret !== API_SECRET) {
        return res.status(401).json({ status: "error", message: "Unauthorized." });
    }

    // 2. استخراج المعرفين
    const serverId = req.query.server_id; 
    const processorId = req.query.processor_id; 

    if (!serverId || !processorId) {
        return res.status(200).json({ status: "success", key: AES_KEY, warning: "Tracking skipped: Missing ID." });
    }

    let client;
    try {
        client = await connectToDatabase();
        const db = client.db("key_control_db"); 
        const blacklist = db.collection("blacklist");
        const tracking = db.collection("tracking");
        
        // المتغيرات الثابتة لعملية الاشتراك
        const GRACE_PERIOD_DAYS = 3;
        const MS_PER_DAY = 1000 * 60 * 60 * 24;
        const INITIAL_SECURITY_DAYS = 7; // 💡 7 أيام مهلة أولية إذا لم يتم تعيين تاريخ

        // 3. التحقق من الحظر
        const isBlocked = await blacklist.findOne({ $or: [{ processorId: processorId }, { serverId: serverId }] }); 
        if (isBlocked) {
            return res.status(403).json({ status: "blocked", message: "Access revoked by admin." });
        }

        // 4. التحديث والتتبع والحصول على بيانات الاشتراك
        const trackingDocResult = await tracking.findOneAndUpdate(
            { processorId: processorId }, 
            { $set: { lastSeen: new Date(), serverId: serverId } },
            { upsert: true, returnDocument: 'after' }
           
        );
        
        const trackingDoc = trackingDocResult.value;
        let expiryDate = trackingDoc.expiryDate; // 🚨 تم تغيير التعريف إلى let

        // 💡 التعديل الجديد: تعيين تاريخ انتهاء أولي إذا لم يكن موجوداً
        if (!expiryDate) {
            const initialExpiryDate = new Date(Date.now() + (INITIAL_SECURITY_DAYS * MS_PER_DAY));
            
            await tracking.updateOne(
                { processorId: processorId },
                { $set: { expiryDate: initialExpiryDate } }
            );
            
            expiryDate = initialExpiryDate;
        }
        
        let status = 200; 
        let remainingDays = 999;
        
        // 💡 الآن يمكننا الاعتماد على وجود expiryDate دائماً
        const now = new Date();
        const timeDifference = expiryDate.getTime() - now.getTime();
        remainingDays = Math.ceil(timeDifference / MS_PER_DAY);
        
        if (remainingDays <= 0) {
            // انتهى الاشتراك، نحسب فترة السماح
            const graceExpiryDate = new Date(expiryDate.getTime() + (GRACE_PERIOD_DAYS * MS_PER_DAY));
            const timeUntilGraceEnds = graceExpiryDate.getTime() - now.getTime();
            remainingDays = Math.ceil(timeUntilGraceEnds / MS_PER_DAY);
            
            if (remainingDays > 0) {
                // 🚨 داخل فترة السماح
                status = 200; 
            } else {
                // 🚨 انتهت فترة السماح! تدمير ذاتي
                status = 405; 
                remainingDays = 0;
            }
        }
        
        // 5. إرسال المفتاح
        if (status === 405) {
            return res.status(405).json({ 
                status: "self_destruct", 
                message: "Subscription expired and grace period over.",
                remaining_days: 0 
            });
        }
        
        return res.status(200).json({ 
            status: "success", 
            key: AES_KEY,
            remaining_days: remainingDays // إرسال الأيام المتبقية
        });

    } catch (error) {
        console.error("Database or Server Error:", error);
        return res.status(200).json({ status: "success", key: AES_KEY, warning: "DB check failed, key granted." });
    }
};
