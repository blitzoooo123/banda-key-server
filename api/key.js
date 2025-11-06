// هذا الكود هو وظيفة بسيطة تعمل على Vercel
module.exports = (req, res) => {
    // 1. المفتاح السري (سيتم تحميله من متغيرات البيئة لاحقاً)
    const SECRET_KEY = process.env.AES_KEY; 
    
    // 2. الرمز المشترك للتحقق (Shared Secret)
    const SHARED_SECRET_CODE = process.env.API_SECRET;

    // 3. التحقق من الرمز المرسل من بلجن ماينكرافت
    const sentSecret = req.headers['x-api-secret'];

    if (!SECRET_KEY || !SHARED_SECRET_CODE) {
         // إذا لم يتم تعريف المتغيرات، فهذه مشكلة في الإعداد
        return res.status(500).json({ status: "error", message: "Server configuration error." });
    }

    if (sentSecret !== SHARED_SECRET_CODE) {
        // فشل التحقق (البلجن غير شرعي)
        return res.status(401).json({ status: "error", message: "Unauthorized." });
    }
    
    // 4. الإرسال الناجح للمفتاح
    res.status(200).json({ 
        status: "success", 
        key: SECRET_KEY // المفتاح المشفر بصيغة Base64
    });
};