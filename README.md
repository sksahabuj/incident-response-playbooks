# Incident Response Playbooks - Cloud Security Automation

[![AWS](https://img.shields.io/badge/AWS-Lambda-orange)](https://aws.amazon.com/lambda/)
[![Python](https://img.shields.io/badge/Python-3.x-blue)](https://www.python.org)
[![Status](https://img.shields.io/badge/Status-Planned-yellow)]()

## 🎯 Project Overview

Automated incident response playbooks for cloud security incidents. Python-based orchestration for containment, investigation, and recovery in AWS environments.

**Purpose:** Translate 9 years of SOC incident response experience into automated cloud-native IR workflows.

## 🚨 Playbook Categories

### 🔐 Compromised Credentials
**Status:** 📅 Planned (Week 5-6)  

**Scenarios:**
- Compromised IAM access keys
- Root account compromise
- Stolen session tokens
- Cross-account role abuse

**Automated Actions:**
- Disable compromised access keys
- Rotate credentials
- Revoke active sessions
- Block suspicious IP addresses
- Alert security team
- Generate forensic timeline

### ☁️ Resource Compromise
**Status:** 📅 Planned (Week 7-8)

**Scenarios:**
- EC2 instance crypto mining
- Lambda function backdoor
- S3 bucket data exfiltration
- Unauthorized resource creation

**Automated Actions:**
- Isolate compromised resources
- Capture forensic snapshots
- Block network egress
- Collect CloudTrail evidence
- Generate incident report

### 🔓 Unauthorized Access
**Status:** 📅 Planned (Week 9-10)

**Scenarios:**
- Console login from suspicious IP
- Privilege escalation attempts
- Unauthorized API calls
- MFA bypass attempts

**Automated Actions:**
- Block source IP addresses
- Disable affected user accounts
- Enable enhanced logging
- Trigger SOC escalation
- Document timeline

### 🛡️ Security Control Bypass
**Status:** 📅 Planned (Week 11-12)

**Scenarios:**
- CloudTrail disabled
- GuardDuty suspended
- Security Hub disabled
- Config recorder stopped

**Automated Actions:**
- Re-enable security controls
- Alert on configuration changes
- Restore baseline security posture
- Investigate who made changes
- Prevent recurrence

## 🔧 Playbook Architecture
```
┌─────────────────────────────────────────────────────────┐
│                   Security Event                         │
│            (GuardDuty / Security Hub)                    │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────┐
│                  EventBridge Rule                        │
│           (Pattern Match on Finding)                     │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────┐
│              Lambda Function (Orchestrator)              │
│                                                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │  Containment │  │ Investigation│  │   Recovery   │  │
│  │   Actions    │──▶│   Actions    │──▶│   Actions    │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└──────────────────┬──────────────────────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────────────────────┐
│              Notification & Logging                      │
│         (SNS Alert + S3 Evidence Storage)                │
└─────────────────────────────────────────────────────────┘
```

## 📋 Sample Playbook: Compromised Access Key

### Detection
```python
# Triggered by GuardDuty Finding
finding_type = "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration"
```

### Phase 1: Containment (Automated)
```python
def contain_compromised_key(access_key_id, user_name):
    """
    Immediate automated response to compromised access key
    """
    # 1. Disable the compromised access key
    iam.update_access_key(
        UserName=user_name,
        AccessKeyId=access_key_id,
        Status='Inactive'
    )
    
    # 2. Attach explicit deny policy to user
    iam.put_user_policy(
        UserName=user_name,
        PolicyName='IncidentResponseDeny',
        PolicyDocument=deny_all_policy
    )
    
    # 3. Revoke all active sessions
    iam.delete_login_profile(UserName=user_name)
    
    # 4. Log containment actions
    log_incident_action("Containment Complete", user_name)
```

### Phase 2: Investigation (Automated Evidence Collection)
```python
def investigate_compromise(access_key_id, timeframe):
    """
    Collect evidence for forensic analysis
    """
    # 1. Query CloudTrail for all actions by access key
    events = cloudtrail.lookup_events(
        LookupAttributes=[{
            'AttributeKey': 'AccessKeyId',
            'AttributeValue': access_key_id
        }],
        StartTime=timeframe['start'],
        EndTime=timeframe['end']
    )
    
    # 2. Identify suspicious API calls
    suspicious_calls = filter_suspicious_actions(events)
    
    # 3. Map to MITRE ATT&CK techniques
    attack_techniques = map_to_mitre(suspicious_calls)
    
    # 4. Generate timeline
    timeline = create_incident_timeline(events)
    
    # 5. Store evidence in S3
    store_evidence(timeline, suspicious_calls)
```

### Phase 3: Recovery (Semi-Automated)
```python
def recover_from_compromise(user_name):
    """
    Restore secure state after incident
    """
    # 1. Generate new access key for user
    new_key = iam.create_access_key(UserName=user_name)
    
    # 2. Remove incident response deny policy
    iam.delete_user_policy(
        UserName=user_name,
        PolicyName='IncidentResponseDeny'
    )
    
    # 3. Re-enable MFA enforcement
    enforce_mfa(user_name)
    
    # 4. Notify user of new credentials (via SNS)
    notify_user_credential_rotation(user_name, new_key)
    
    # 5. Close incident ticket
    update_incident_status("Resolved")
```

## 🛠️ Tech Stack

- **Orchestration:** AWS Lambda (Python 3.x)
- **Event Detection:** GuardDuty, Security Hub, EventBridge
- **Automation:** Boto3, AWS Systems Manager
- **Logging:** CloudWatch Logs, S3
- **Alerting:** SNS, SES
- **Evidence Storage:** S3 with encryption
- **Forensics:** CloudTrail, VPC Flow Logs

## 📚 What I'm Learning

- Event-driven security automation
- Lambda function development for IR
- AWS APIs for security response
- Forensic evidence collection in cloud
- Incident orchestration workflows
- SOAR principles and implementation

## 🎓 Skills Demonstrated

✅ Incident response automation  
✅ Cloud-native security orchestration  
✅ Python for security engineering  
✅ AWS security service integration  
✅ Evidence collection and preservation  
✅ MITRE ATT&CK mapping  

## 📂 Repository Structure
```
incident-response-playbooks/
├── README.md
├── playbooks/
│   ├── compromised_credentials/
│   │   ├── access_key_compromise.py
│   │   ├── root_account_compromise.py
│   │   └── session_token_theft.py
│   ├── resource_compromise/
│   │   ├── ec2_cryptomining.py
│   │   ├── lambda_backdoor.py
│   │   └── s3_exfiltration.py
│   ├── unauthorized_access/
│   │   └── suspicious_console_login.py
│   └── security_control_bypass/
│       └── cloudtrail_disabled.py
├── lambda/
│   ├── orchestrator/
│   ├── containment/
│   ├── investigation/
│   └── recovery/
├── terraform/  (future)
│   └── infrastructure/
├── docs/
│   ├── playbook_guide.md
│   ├── deployment.md
│   └── testing.md
└── tests/
    └── playbook_tests.py
```

## 🚀 Deployment Architecture

Playbooks deploy as:
1. **Lambda Functions** - Automated response logic
2. **EventBridge Rules** - Event pattern matching
3. **IAM Roles** - Least privilege permissions
4. **SNS Topics** - Alert notifications
5. **S3 Buckets** - Evidence storage

## 📊 Development Roadmap

**Month 3:** Compromised credential playbooks (2 playbooks)  
**Month 4:** Resource compromise playbooks (2 playbooks)  
**Month 5:** Unauthorized access playbooks (2 playbooks)  
**Month 6:** Security control bypass playbooks (2 playbooks)

**Total Target:** 8 production-ready IR playbooks by June 2026

## 🎯 Playbook Quality Standards

Each playbook must include:
- ✅ Automated containment within 60 seconds
- ✅ Comprehensive evidence collection
- ✅ MITRE ATT&CK technique mapping
- ✅ Detailed logging and audit trail
- ✅ Notification to security team
- ✅ Testing and validation procedures
- ✅ Rollback capabilities

## 📊 Current Status

**Started:** February 22, 2026  
**Playbooks Completed:** 0/8  
**Completion:** 0%  
**Next Milestone:** First playbook by April 1, 2026

## 🔗 Related Projects

- [aws-security-lab](../aws-security-lab) - Testing environment for playbooks
- [threat-detection-rules](../threat-detection-rules) - Detection rules triggering playbooks
- [security-automation-scripts](../security-automation-scripts) - Reusable automation components

---

*Part of my transition from SOC Operations to Cloud Security Engineering*  
*Automating incident response at cloud speed*

**Author:** SK Sahabuj Zaman | [GitHub](https://github.com/sksahabuj) | [Email](mailto:sksahabuj@gmail.com)
