<template>
  <div class="app-container">
    <div class="cis-badge-container">
      <img src="./assets/cis.png" class="cis-badge" alt="CIS Badge" />
    </div>
    
    <div class="main-container">
      <header class="app-header">
        <div class="header-content">
          <img src="./assets/logoBG.png" alt="BucketGuard Logo" class="logo" />
          <h1>BucketGuard</h1>
        </div>
      </header>

      <main class="app-content">
        <!-- AWS Configuration Form -->
        <div v-if="!awsConfigured" class="config-section">
          <div class="config-card">
            <h2>Configure AWS Credentials</h2>
            <div class="form-group">
              <label for="accessKey">AWS Access Key</label>
              <input 
                id="accessKey"
                v-model="accessKey" 
                type="text"
                placeholder="Enter your AWS Access Key"
                class="form-input"
              />
            </div>
            <div class="form-group">
              <label for="secretKey">AWS Secret Key</label>
              <input 
                id="secretKey"
                v-model="secretKey" 
                type="password"
                placeholder="Enter your AWS Secret Key"
                class="form-input"
              />
            </div>
            <button @click="addMachine" class="primary-button">
              <span class="button-icon">🔐</span>
              Connect AWS
            </button>
          </div>
        </div>

        <!-- Main Dashboard -->
        <div v-if="awsConfigured" class="dashboard">
          <!-- Bucket Selection -->
          <div class="bucket-selector">
            <div class="select-wrapper">
              <select v-model="selectedBucket" @change="onBucketChange" class="form-select">
                <option disabled value="">Select a Bucket</option>
                <option v-for="bucket in buckets" :key="bucket">{{ bucket }}</option>
              </select>
            </div>
            <button @click="scanBucket" class="primary-button">
              <span class="button-icon">🔍</span>
              Scan Bucket
            </button>
          </div>

          <!-- Dashboard Grid -->
          <div class="dashboard-grid">
            <!-- Success Results -->
            <div v-if="currentBucketStatus && currentBucketStatus.issues && currentBucketStatus.issues.length === 0" class="results-section success">
              <div class="results-header">
                <h2>Security Scan Results</h2>
                <span class="bucket-name">{{ selectedBucket }}</span>
              </div>
              <div class="results-content">
                <table class="results-table">
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Compliance Check</th>
                      <th>CIS Reference</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td><span class="status-icon success">✓</span></td>
                      <td>Public access is disabled</td>
                      <td>CIS AWS Foundations Benchmark S3.8</td>
                    </tr>
                    <tr>
                      <td><span class="status-icon success">✓</span></td>
                      <td>Versioning is enabled</td>
                      <td>CIS AWS Foundations Benchmark S3.14</td>
                    </tr>
                    <tr>
                      <td><span class="status-icon success">✓</span></td>
                      <td>Block Public Access is enabled</td>
                      <td>CIS AWS Foundations Benchmark S3.1</td>
                    </tr>
                  </tbody>
                </table>
                <div class="compliance-badge">
                  <span class="badge-icon">✓</span>
                  <span>CIS Compliant</span>
                </div>
              </div>
            </div>

            <!-- Issues Results -->
            <div v-if="currentBucketStatus && currentBucketStatus.issues && currentBucketStatus.issues.length > 0" class="results-section issues">
              <div class="results-header">
                <h2>Security Issues Detected</h2>
                <span class="bucket-name">{{ selectedBucket }}</span>
              </div>
              <div class="results-content">
                <table class="issues-table">
                  <thead>
                    <tr>
                      <th>Issue</th>
                      <th>CIS Reference</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="issue in currentBucketStatus.issues" :key="issue.issue">
                      <td>
                        <span class="issue-icon">⚠️</span>
                        {{ issue.issue }}
                      </td>
                      <td>{{ issue.cis_reference }}</td>
                      <td>
                        <button @click="fixIssue(issue.issue)" class="action-button">
                          Fix Issue
                        </button>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>

            <!-- Health Dashboard -->
            <div class="health-dashboard">
              <div class="health-dashboard-header">
                <h2>Bucket Health Overview</h2>
              </div>
              <div class="gauge-container">
                <div class="gauge-wrapper">
                  <div class="gauge" :class="healthClass">
                    <div class="gauge-background"></div>
                    <div 
                      class="gauge-fill" 
                      :style="{ 
                        transform: `rotate(${healthRotation}deg)`,
                        borderColor: healthColor
                      }"
                    ></div>
                    <div class="gauge-cover">
                      <span class="gauge-value">{{ healthScore }}%</span>
                      <span class="gauge-label">Secure</span>
                    </div>
                  </div>
                </div>
                <div class="health-stats">
                  <div class="stat-card">
                    <div class="stat-label">Bucket</div>
                    <div class="stat-value">{{ selectedBucket }}</div>
                  </div>
                  <div class="stat-card">
                    <div class="stat-label">Status</div>
                    <div class="stat-value" :style="{ color: healthColor }">
                      {{ healthStatus }}
                    </div>
                  </div>
                  <div class="stat-card">
                    <div class="stat-label">Issues</div>
                    <div class="stat-value">{{ currentBucketStatus?.issues?.length || 0 }}</div>
                  </div>
                  <div class="stat-card">
                    <div class="stat-label">Last Scan</div>
                    <div class="stat-value">{{ formatDate(currentBucketStatus?.scannedAt) }}</div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Empty State -->
          <div v-if="selectedBucket && (!currentBucketStatus || !currentBucketStatus.issues)" class="empty-state">
            <div class="empty-state-content">
              <span class="empty-state-icon">🔍</span>
              <p>Select a bucket and click 'Scan' to check for security issues.</p>
            </div>
          </div>
        </div>
      </main>
    </div>
  </div>
</template>


<script>
import { getBuckets, detectIssues, remediateIssue } from './api';

export default {
  data() {
    return {
      awsConfigured: false,
      accessKey: '',
      secretKey: '',
      buckets: [],
      selectedBucket: "",
      bucketStatuses: {}, // Object to store scan results for each bucket
      scanned: false,
      // Maximum expected issues (used for health calculation)
      maxIssues: 3 
    };
  },
  computed: {
    currentBucketStatus() {
      return this.bucketStatuses[this.selectedBucket] || null;
    },
    healthScore() {
      if (!this.currentBucketStatus || !this.currentBucketStatus.issues) return 0;
      
      const issueCount = this.currentBucketStatus.issues.length;
      const score = 100 - (issueCount / this.maxIssues * 100);
      return Math.max(0, Math.round(score));
    },
    healthRotation() {
      return (100 - this.healthScore) / 100 * 180;
    },
    healthClass() {
      if (this.healthScore >= 90) return 'healthy';
      if (this.healthScore >= 70) return 'warning';
      return 'critical';
    },
    healthStatus() {
      if (!this.currentBucketStatus) return 'Not Scanned';
      if (this.healthScore === 100) return 'Fully Compliant';
      if (this.healthScore >= 90) return 'Mostly Secure';
      if (this.healthScore >= 70) return 'Needs Attention';
      return 'Critical Issues';
    },
    healthColor() {
      if (!this.currentBucketStatus) return '#64748b';  // Default gray color
      if (this.healthScore >= 90) {
        return '#28a745';
      } else if (this.healthScore >= 70) {
        return this.blendColors('#28a745', '#ffc107', (90 - this.healthScore) / 20);
      } else if (this.healthScore >= 40) {
        return this.blendColors('#ffc107', '#dc3545', (70 - this.healthScore) / 30);
      } else {
        return '#dc3545';
      }
    }
  },
  async mounted() {
    const response = await getBuckets();
    if (response) {
      this.buckets = response.buckets;
    }
  },
  methods: {
    onBucketChange() {
      // When bucket changes, currentBucketStatus computed property will update automatically
    },
    async scanBucket() {
      if (!this.selectedBucket) return;
      
      const response = await detectIssues(this.selectedBucket);
      if (response) {
        // Store the scan results for this bucket
        this.bucketStatuses = {
          ...this.bucketStatuses,
          [this.selectedBucket]: {
            issues: response.issues,
            scannedAt: new Date()
          }
        };
        this.scanned = true;
      }
    },
    async fixIssue(issue) {
      const response = await remediateIssue(this.selectedBucket, issue);
      if (response) {
        alert(`Issue: ${issue} has been fixed!`);
        this.scanBucket(); // Re-scan to update status
      }
    },
    formatDate(date) {
      if (!date) return 'N/A';
      
      // Format date as 'MM/DD/YYYY, HH:MM AM/PM'
      const d = new Date(date);
      return d.toLocaleString('en-US', {
        month: '2-digit',
        day: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    },
    blendColors(color1, color2, ratio) {
      // Convert hex colors to RGB
      const parseColor = (hexStr) => {
        const hex = hexStr.replace('#', '');
        return {
          r: parseInt(hex.substring(0, 2), 16),
          g: parseInt(hex.substring(2, 4), 16),
          b: parseInt(hex.substring(4, 6), 16)
        };
      };
      
      // Convert blended RGB back to hex
      const rgbToHex = (r, g, b) => {
        return "#" + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1);
      };
      
      // Get RGB values
      const c1 = parseColor(color1);
      const c2 = parseColor(color2);
      
      // Blend colors
      const r = Math.round(c1.r * (1 - ratio) + c2.r * ratio);
      const g = Math.round(c1.g * (1 - ratio) + c2.g * ratio);
      const b = Math.round(c1.b * (1 - ratio) + c2.b * ratio);
      
      return rgbToHex(r, g, b);
    },

    async addMachine() {
      try {
        const response = await fetch('http://localhost:5000/add-machine', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            access_key: this.accessKey,
            secret_key: this.secretKey
          })
        });

        const result = await response.json();
        
        if (response.ok) {
          // Test the credentials by trying to list buckets
          const bucketsResponse = await getBuckets();
          if (bucketsResponse && bucketsResponse.buckets) {
            this.buckets = bucketsResponse.buckets;
            this.awsConfigured = true;
            alert("✅ AWS credentials configured successfully!");
          } else {
            throw new Error("Unable to list buckets. Please check your credentials.");
          }
        } else {
          throw new Error(result.error || "Invalid AWS credentials");
        }
      } catch (error) {
        alert(`❌ Error: ${error.message}`);
        this.accessKey = '';
        this.secretKey = '';
        this.awsConfigured = false;
      }
    }
  }
};
</script>

<style>
:root {
  --primary-color: #2563eb;
  --primary-hover: #1d4ed8;
  --success-color: #22c55e;
  --warning-color: #f59e0b;
  --danger-color: #ef4444;
  --background-color: #f8fafc;
  --card-background: #ffffff;
  --text-primary: #1e293b;
  --text-secondary: #64748b;
  --border-color: #e2e8f0;
  --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
  --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1);
  --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1);
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  background-color: var(--background-color);
  color: var(--text-primary);
  line-height: 1.5;
}

.app-container {
  min-height: 100vh;
  position: relative;
}

.main-container {
  max-width: 1550px;
  margin: 0 auto;
  padding: 2rem 4rem;
}

.app-header {
  margin-bottom: 3rem;
  padding: 1rem 0;
  border-bottom: 1px solid var(--border-color);
}

.header-content {
  display: flex;
  align-items: center;
  gap: 1.5rem;
}

.logo {
  height: 100px;
  width: auto;
  filter: drop-shadow(0 2px 4px rgba(0, 0, 0, 0.1));
}

h1 {
  font-size: 3rem;
  font-weight: 700;
  color: var(--text-primary);
  letter-spacing: -0.025em;
}

/* Form Styles */
.config-section {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 60vh;
}

.config-card {
  background: var(--card-background);
  padding: 2.5rem;
  border-radius: 1rem;
  box-shadow: var(--shadow-lg);
  width: 100%;
  max-width: 400px;
  transition: transform 0.2s ease, box-shadow 0.2s ease;
  display: flex;
  flex-direction: column;
  align-items: center;
}

.config-card h2 {
  margin-bottom: 2rem;
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--text-primary);
  text-align: center;
}

.form-group {
  margin-bottom: 1.5rem;
  width: 100%;
}

.form-group label {
  display: block;
  margin-bottom: 0.5rem;
  color: var(--text-secondary);
  font-weight: 500;
}

.form-input {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid var(--border-color);
  border-radius: 0.5rem;
  font-size: 1rem;
  transition: all 0.2s ease;
}

.form-input:hover {
  border-color: var(--primary-color);
}

.form-input:focus {
  outline: none;
  border-color: var(--primary-color);
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
}

.form-select {
  width: 100%;
  padding: 0.875rem 1rem;
  border: 2px solid var(--border-color);
  border-radius: 0.75rem;
  font-size: 1rem;
  background-color: var(--card-background);
  cursor: pointer;
  transition: all 0.2s ease;
  color: var(--text-primary);
  font-weight: 500;
  appearance: none;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 24 24' stroke='%236b7280'%3E%3Cpath stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M19 9l-7 7-7-7'%3E%3C/path%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: right 1rem center;
  background-size: 1.5em;
  padding-right: 2.5rem;
}

.form-select:hover {
  border-color: var(--primary-color);
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
}

.form-select:focus {
  outline: none;
  border-color: var(--primary-color);
  box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.2);
}

/* Button Styles */
.primary-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  padding: 0.875rem 1.75rem;
  background: linear-gradient(45deg, var(--primary-color), var(--primary-hover));
  color: white;
  border: none;
  border-radius: 0.75rem;
  font-size: 1rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
  box-shadow: 0 2px 4px rgba(37, 99, 235, 0.2);
  margin-top: 1rem;
  min-width: 180px;
}

.primary-button:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 6px rgba(37, 99, 235, 0.3);
  background: linear-gradient(45deg, var(--primary-hover), var(--primary-color));
}

.primary-button:active {
  transform: translateY(0);
  box-shadow: 0 2px 4px rgba(37, 99, 235, 0.2);
}

.action-button {
  padding: 0.625rem 1.25rem;
  background-color: var(--primary-color);
  color: white;
  border: none;
  border-radius: 0.5rem;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.2s ease;
  min-width: 100px;
}

.action-button:hover {
  background-color: var(--primary-hover);
  transform: translateY(-1px);
  box-shadow: 0 4px 6px -1px rgb(0 0 0 / 0.1);
}

/* Results Section Enhancement */
.results-section {
  background: var(--card-background);
  border-radius: 1rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1);
  overflow: hidden;
  transition: all 0.2s ease;
  border: 1px solid rgba(226, 232, 240, 0.8);
  position: relative;
  height: 100%;
  display: flex;
  flex-direction: column;
}

.results-section:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.12), 0 2px 4px -2px rgba(0, 0, 0, 0.08);
  border-color: rgba(37, 99, 235, 0.2);
}

.results-header {
  padding: 1.75rem;
  border-bottom: 1px solid rgba(226, 232, 240, 0.8);
  display: flex;
  justify-content: space-between;
  align-items: center;
  background: linear-gradient(to right, var(--card-background), rgba(248, 250, 252, 0.5));
  position: relative;
}

.results-header::after {
  content: '';
  position: absolute;
  bottom: -1px;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(to right, 
    rgba(37, 99, 235, 0.1),
    rgba(37, 99, 235, 0.05) 50%,
    transparent
  );
}

.results-header.success {
  background: linear-gradient(to right, #dcfce7, #bbf7d0);
  color: #166534;
}

.results-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  margin: 0;
}

.bucket-name {
  font-size: 0.875rem;
  color: var(--text-secondary);
  background-color: var(--background-color);
  padding: 0.25rem 0.75rem;
  border-radius: 1rem;
  transition: all 0.2s ease;
}

.bucket-name:hover {
  background-color: var(--border-color);
}

.results-content {
  padding: 2.5rem;
  position: relative;
  flex: 1;
  display: flex;
  flex-direction: column;
}

/* Table Styles Enhancement */
.results-table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  margin-bottom: 2rem;
}

.results-table th {
  text-align: left;
  padding: 1.25rem;
  font-weight: 600;
  color: var(--text-secondary);
  background: var(--background-color);
  border-bottom: 2px solid var(--border-color);
  font-size: 0.875rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.results-table td {
  padding: 1.25rem;
  border-bottom: 1px solid var(--border-color);
  transition: all 0.2s ease;
  vertical-align: middle;
}

.results-table tr:last-child td {
  border-bottom: none;
}

.results-table tr:hover td {
  background-color: #f8fafc;
}

/* Status Icon Enhancement */
.status-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: 50%;
  margin-right: 1rem;
  font-size: 1.125rem;
  transition: all 0.2s ease;
  line-height: 1;
}

.status-icon.success {
  background: linear-gradient(45deg, #22c55e, #16a34a);
  color: white;
  box-shadow: 0 2px 4px rgba(34, 197, 94, 0.2);
}

.status-icon.warning {
  background: linear-gradient(45deg, #f59e0b, #d97706);
  color: white;
  box-shadow: 0 2px 4px rgba(245, 158, 11, 0.2);
}

/* Compliance Badge Enhancement */
.compliance-badge {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.75rem;
  background: linear-gradient(45deg, #22c55e, #16a34a);
  color: white;
  padding: 1rem 2rem;
  border-radius: 1rem;
  font-weight: 600;
  font-size: 1.125rem;
  margin: 1rem auto;
  max-width: max-content;
  box-shadow: 0 4px 6px rgba(34, 197, 94, 0.2);
  transition: all 0.2s ease;
  position: relative;
  overflow: hidden;
}

.compliance-badge::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: linear-gradient(45deg, rgba(255,255,255,0.1), rgba(255,255,255,0));
  transform: translateX(-100%);
  transition: transform 0.5s ease;
}

.compliance-badge:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 8px rgba(34, 197, 94, 0.3);
}

.compliance-badge:hover::before {
  transform: translateX(100%);
}

.badge-icon {
  font-size: 1.5rem;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  background: rgba(255, 255, 255, 0.2);
  border-radius: 50%;
  padding: 0;
  line-height: 1;
}

/* Add divider between table and badge */
.results-content::after {
  content: '';
  display: block;
  width: 80%;
  height: 1px;
  background: linear-gradient(to right, transparent, var(--border-color), transparent);
  margin: 2rem auto;
}

/* Health Dashboard */
.health-dashboard {
  background: var(--card-background);
  border-radius: 1rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1);
  transition: all 0.2s ease;
  border: 1px solid rgba(226, 232, 240, 0.8);
  height: 100%;
  display: flex;
  flex-direction: column;
  padding-bottom: 2rem;
  position: relative;
  overflow: hidden;
}

.health-dashboard:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.12), 0 2px 4px -2px rgba(0, 0, 0, 0.08);
  border-color: rgba(37, 99, 235, 0.2);
}

.health-dashboard-header {
  padding: 1.75rem;
  border-bottom: 1px solid rgba(226, 232, 240, 0.8);
  background: linear-gradient(to right, var(--card-background), rgba(248, 250, 252, 0.5));
  position: relative;
}

.health-dashboard-header::after {
  content: '';
  position: absolute;
  bottom: -1px;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(to right, 
    rgba(37, 99, 235, 0.1),
    rgba(37, 99, 235, 0.05) 50%,
    transparent
  );
}

.health-dashboard-header h2 {
  font-size: 1.5rem;
  font-weight: 600;
  margin: 0;
  color: var(--text-primary);
}

.gauge-container {
  padding: 2.5rem 3rem 3rem;
  display: flex;
  flex-direction: column;
  gap: 3rem;
  flex: 1;
}

.gauge-wrapper {
  display: flex;
  justify-content: center;
  padding-bottom: 1rem;
}

.health-stats {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1.5rem;
  padding: 0 2rem;
}

.stat-card {
  background: var(--card-background);
  padding: 1.25rem;
  border-radius: 0.75rem;
  transition: all 0.2s ease;
  border: 1px solid rgba(226, 232, 240, 0.8);
  position: relative;
  overflow: hidden;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.04);
}

.stat-card::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 2px;
  background: linear-gradient(to right, 
    rgba(37, 99, 235, 0.2),
    rgba(37, 99, 235, 0.1) 50%,
    transparent
  );
  opacity: 0;
  transition: opacity 0.2s ease;
}

.stat-card:hover {
  transform: translateY(-2px);
  border-color: rgba(37, 99, 235, 0.2);
  box-shadow: 0 2px 4px -1px rgba(0, 0, 0, 0.08), 0 1px 2px -1px rgba(0, 0, 0, 0.06);
}

.stat-card:hover::before {
  opacity: 1;
}

.stat-label {
  font-size: 0.875rem;
  color: var(--text-secondary);
  margin-bottom: 0.5rem;
  font-weight: 500;
}

.stat-value {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--text-primary);
}

/* Bucket Selector */
.bucket-selector {
  display: flex;
  gap: 3rem;
  align-items: center;
  margin-bottom: 2rem;
  padding: 1.5rem 2rem;
  background: var(--card-background);
  border-radius: 1rem;
  box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1);
  transition: all 0.2s ease;
  border: 1px solid rgba(226, 232, 240, 0.8);
  justify-content: space-between;
}

.bucket-selector:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.12), 0 2px 4px -2px rgba(0, 0, 0, 0.08);
  border-color: rgba(37, 99, 235, 0.2);
}

.bucket-selector .primary-button {
  margin-top: 0;
  align-self: center;
}

.select-wrapper {
  flex: 1;
  max-width: 500px;
  display: flex;
  align-items: center;
}

.form-select {
  margin: 0;
  height: 48px; /* Match button height */
}

/* Empty State */
.empty-state {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 300px;
  background: var(--card-background);
  border-radius: 1rem;
  box-shadow: var(--shadow-md);
  transition: transform 0.2s ease, box-shadow 0.2s ease;
}

.empty-state:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-lg);
}

.empty-state-content {
  text-align: center;
  color: var(--text-secondary);
}

.empty-state-icon {
  font-size: 3rem;
  margin-bottom: 1rem;
  display: block;
}

/* CIS Badge */
.cis-badge-container {
  position: fixed;
  bottom: 2rem;
  right: 2rem;
  z-index: 0;
}

.cis-badge {
  width: 200px;
  opacity: 0.6;
  pointer-events: none;
}

/* Responsive Design */
@media (max-width: 1440px) {
  .main-container {
    padding: 2rem;
  }
}

@media (max-width: 1024px) {
  .dashboard-grid {
    grid-template-columns: 1fr;
    gap: 3rem;
    margin: 2rem auto;
  }
  
  .main-container {
    padding: 1.5rem;
  }
}

/* Gauge Styles */
.gauge {
  width: 200px;
  height: 200px;
  position: relative;
  margin: 2rem auto;
}

.gauge-background {
  width: 200px;
  height: 200px;
  border-radius: 50%;
  border: 20px solid #f1f5f9;
  position: absolute;
  box-sizing: border-box;
}

.gauge-fill {
  width: 200px;
  height: 200px;
  border-radius: 50%;
  border: 20px solid;
  position: absolute;
  transform-origin: 50% 50%;
  box-sizing: border-box;
  transition: all 0.5s ease-in-out;
}

.gauge-cover {
  width: 200px;
  height: 200px;
  position: absolute;
  border-radius: 50%;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  box-sizing: border-box;
  text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
}

.gauge-value {
  font-size: 2.5rem;
  font-weight: 700;
  color: var(--text-primary);
  margin-bottom: 0.5rem;
}

.gauge-label {
  font-size: 1rem;
  color: var(--text-secondary);
  font-weight: 500;
}

.gauge.healthy .gauge-fill {
  border-color: var(--success-color);
  box-shadow: 0 0 15px rgba(34, 197, 94, 0.3);
}

.gauge.warning .gauge-fill {
  border-color: var(--warning-color);
  box-shadow: 0 0 15px rgba(245, 158, 11, 0.3);
}

.gauge.critical .gauge-fill {
  border-color: var(--danger-color);
  box-shadow: 0 0 15px rgba(239, 68, 68, 0.3);
}

/* Table Styles Enhancement */
.issues-table {
  width: 100%;
  border-collapse: separate;
  border-spacing: 0;
  margin-bottom: 2rem;
}

.issues-table th {
  text-align: left;
  padding: 1.25rem 1.5rem;
  font-weight: 600;
  color: var(--text-secondary);
  background: var(--background-color);
  border-bottom: 2px solid var(--border-color);
  font-size: 0.875rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}

.issues-table th:first-child {
  width: 45%;
}

.issues-table th:nth-child(2) {
  width: 35%;
}

.issues-table th:last-child {
  width: 20%;
  text-align: center;
}

.issues-table td {
  padding: 1.25rem 1.5rem;
  border-bottom: 1px solid var(--border-color);
  transition: all 0.2s ease;
  vertical-align: middle;
  line-height: 1.5;
}

.issues-table tr:last-child td {
  border-bottom: none;
}

.issues-table tr:hover td {
  background-color: #f8fafc;
}

.issues-table td:last-child {
  text-align: center;
}

.issue-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 28px;
  height: 28px;
  border-radius: 50%;
  background: rgba(245, 158, 11, 0.1);
  margin-right: 0.75rem;
  font-size: 1rem;
  line-height: 1;
  padding: 0;
}

.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 3.5rem;
  margin: 3rem auto;
  width: 100%;
}
</style>