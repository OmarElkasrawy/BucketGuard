import axios from 'axios';

const API_URL = "http://127.0.0.1:5000"; // flask backend url

export const getBuckets = async () => {
    try {
        console.log("🔍 DEBUG: Requesting bucket list from Flask...");
        const response = await axios.get(`${API_URL}/buckets`);
        console.log("✅ DEBUG: API Response ->", response.data);
        return response.data;
    } catch (error) {
        console.error("Error fetching bucket list: ", error);
        return null;
    }
};

export const detectIssues = async (bucketName) => {
    try {
        console.log(`🔍 DEBUG: Sending request to /detect?bucket=${bucketName}`); // ✅ Print request
        const response = await axios.get(`${API_URL}/detect`, { params: { bucket: bucketName } });
        console.log("✅ DEBUG: API Response ->", response.data);
        return response.data;
    } catch (error) {
        console.error("❌ Error detecting issues:", error);
        return null;
    }
};


export const remediateIssue = async (bucketName, issue) => {
    try {
        console.log(`🔧 DEBUG: Sending request to remediate '${issue}' in bucket '${bucketName}'`);
        const response = await axios.post(`${API_URL}/remediate`, {
            bucket: bucketName,
            issue: issue
        });
        console.log("✅ DEBUG: API Response ->", response.data);
        return response.data;
    } catch (error) {
        console.error("❌ Error remediating issue:", error);
        return null;
    }
};
