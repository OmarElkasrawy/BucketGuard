```
██████  ██    ██  ██████ ██   ██ ███████ ████████      ██████  ██    ██  █████  ██████  ██████  
██   ██ ██    ██ ██      ██  ██  ██         ██        ██       ██    ██ ██   ██ ██   ██ ██   ██ 
██████  ██    ██ ██      █████   █████      ██        ██   ███ ██    ██ ███████ ██████  ██   ██ 
██   ██ ██    ██ ██      ██  ██  ██         ██        ██    ██ ██    ██ ██   ██ ██   ██ ██   ██ 
██████   ██████   ██████ ██   ██ ███████    ██         ██████   ██████  ██   ██ ██   ██ ██████  
                                                                                                
                                                                                                
```


![BucketGuard Logo](frontend/src/assets/logoBG.png)

A comprehensive security monitoring and remediation tool for AWS S3 buckets, ensuring compliance with security best practices and CIS benchmarks.

## 🛡️ Features

- **Security Monitoring**
  - Detect public access vulnerabilities
  - Check versioning status
  - Monitor public access block configurations

- **Automated Remediation**
  - Fix identified security issues
  - Implement security best practices
  - Maintain CIS compliance

- **User Interface**
  - Interactive dashboard
  - Real-time security status
  - Visual health indicators
  - Detailed issue reporting

- **Compliance Tracking**
  - CIS benchmark references
  - Security score calculation
  - Compliance status monitoring
  - Detailed reporting

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- Node.js 14+
- AWS Account with S3 access
- AWS Account Credentials to be Entered
### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/OmarElkasrawy/BucketGuard.git
   cd BucketGuard
   ```

2. **Backend Setup**
   ```bash
   # Install Python dependencies
   pip install -r requirements.txt
   
   # Initialize the database
   python Bucket\ Guard/DB/initialize_db.py
   ```

3. **Frontend Setup**
   ```bash
   cd frontend
   npm install
   ```

### Running the Application

1. **Start the Backend**
   ```bash
   # From the root directory
   python Bucket\ Guard/backend/app.py
   ```

2. **Start the Frontend**
   ```bash
   # From the frontend directory
   npm run serve
   ```

3. **Access the Application**
   - Open your browser and navigate to `http://localhost:8080`

## 🛠️ Technology Stack

### Frontend
- Vue.js 3
- Axios for API communication
- Modern JavaScript (ES6+)
- CSS3 for styling

### Backend
- Python Flask
- AWS SDK (boto3)
- SQLite3 for database
- RESTful API architecture

## 🔧 Remediation Actions

The tool can automatically fix the following issues:

- Remove public access
- Enable versioning
- Configure encryption
- Enable public access block

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 📞 Support

For support, please open an issue in the GitHub repository.

