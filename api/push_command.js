const { MongoClient } = require('mongodb');

// يجب أن تكون هذه المتغيرات موجودة في إعدادات Vercel
const URI = process.env.MONGODB_URI;
const API_SECRET = process.env.API_SECRET; 

let dbClient = null;

async function connectToDatabase() {
    if (dbClient) return dbClient;
    dbClient = await MongoClient.connect(URI);
    return dbClient;
}

module.exports = async (req, res) => {
    // 1. التحقق من الرمز المشترك والبيانات الأساسية
    const sentSecret = req.headers['x-api-secret'] || req.query.secret; // يمكنك إرساله في الهيدر أو الرابط
    const sentCommand = req.query.command; 
    const targetServer = req.query.target_server_id; 

    if (sentSecret !== API_SECRET || !sentCommand || !targetServer) {
        return res.status(401).json({ status: "error", message: "Invalid auth or missing parameters (command/target_server_id)." });
    }

    let client;
    try {
        client = await connectToDatabase();
        const db = client.db("key_control_db");
        // اسم المجموعة الذي سيتم تخزين الأوامر فيه
        const commandQueue = db.collection("command_queue"); 

        // 2. تخزين الأمر في قائمة الانتظار
        await commandQueue.insertOne({
            serverId: targetServer,
            commandText: sentCommand,
            timestamp: new Date()
        });

        // 3. النجاح
        return res.status(200).json({ 
            status: "success", 
            message: `Command '${sentCommand}' queued for server '${targetServer}'.` 
        });

    } catch (error) {
        console.error("Database Error on PUSH:", error);
        return res.status(500).json({ status: "error", message: "Database connection failed." });
    }
};
