const { MongoClient } = require('mongodb');

const URI = process.env.MONGODB_URI;
const API_SECRET = process.env.API_SECRET; 

let dbClient = null;

async function connectToDatabase() {
    if (dbClient) return dbClient;
    dbClient = await MongoClient.connect(URI);
    return dbClient;
}

module.exports = async (req, res) => {
    // 1. التحقق من الرمز المشترك
    const sentSecret = req.headers['x-api-secret'];
    if (sentSecret !== API_SECRET) {
        return res.status(401).json({ status: "error", message: "Unauthorized." });
    }
    
    // 2. استخراج المعرف الفريد (من البلجن)
    const serverId = req.query.server_id;
    if (!serverId) {
        return res.status(400).json({ status: "error", message: "Missing server_id parameter." });
    }

    let client;
    try {
        client = await connectToDatabase();
        const db = client.db("key_control_db");
        const commandQueue = db.collection("command_queue"); 

        // 3. البحث عن أمر مُنتظَر لهذا السيرفر والحذف الفوري (للتأكد من تنفيذه مرة واحدة)
        // findOneAndDelete يضمن إرجاع الأمر وحذفه في خطوة واحدة
        const queuedCommand = await commandQueue.findOneAndDelete(
            { serverId: serverId },
            { sort: { timestamp: 1 } } 
        );

        if (queuedCommand.value) {
            // 4. تم العثور على أمر: إرسال أمر ماينكرافت الخام
            return res.status(200).json({
                status: "command_ready",
                minecraftCommand: queuedCommand.value.commandText
            });
        } else {
            // 5. لا يوجد أمر: إرسال حالة "لا يوجد أمر"
            return res.status(200).json({ status: "no_command" });
        }

    } catch (error) {
        console.error("Database Error on PULL:", error);
        return res.status(500).json({ status: "error", message: "Internal server error." });
    }
};
