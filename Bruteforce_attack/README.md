# Splunk_bruteforce_investigation
A bruteforce attack occurs when a hacker tries different combinations of usernames and password to brak into a system.


[Download dataset used](./Data/splunkdata.csv)

![Overview](./images/Screenshot%20From%202026-05-04%2015-17-11.png)

The first step is to ingest data into the splunk software.
After data ingestion:

Confirm the data is there by clicking search and and reporting then type the command:

```spl
index=main sourcetype=csv
```

Output:
![confirmation](./images/findingData.png)

### SPL basics: Filter and search
Find all failed logins:
``` spl 
index=main sourcetype=csv action=login status_code=401
```
#### Output
![failedLogins](./images/failedLogins.png)

### Filter to specific fields only:
``` spl
index=main sourcetype=csv action=login status_code=401
| fields _time, host, user, src_ip
```
![specificFields image](./images/specific-fields.png)

### Find a specific user's activity:

``` spl
index=main sourcetype=csv user=alice
| table _time, host, action, app, bytes_sent
```
![specific user image](./images/specificUserctivity.png)

### Count events per user:
``` spl
index=main sourcetype=csv
| stats count by user, action
| sort -count
```
![Count events image](./images/UserEventCount.png)

### See failed logins over time:
``` spl 
index=main sourcetype=csv action=login status_code=401
| timechart count by src_ip
```
![Failed Logins image](./images/FailedLoginsOverTime.png)

### Top source IPs:
``` spl
index=main sourcetype=csv
| top limit=10 src_ip
```
![Top source IP image](./images/TopSourceIps.png)

### Total data transferred per user (bytes):
``` spl 
index=main sourcetype=csv action=file_access
| stats sum(bytes_sent) as total_bytes by user
| eval total_MB = round(total_bytes/1048576, 2)
| sort -total_MB
```
![Total data transferred image](./images/TotalDataTransferredByUser.png)

### Create a human-readable status label using eval:
``` spl 
index=main sourcetype=csv
| eval outcome = case(status_code==200, "Success", status_code==401, "Unauthorized", status_code==403, "Forbidden", true(), "Other")
| stats count by user, outcome
```
![labels image](./images/humanReadableLabels.png)

### Extract just the subnet from src_ip using rex:
```spl 
index=main sourcetype=csv
| rex field=src_ip "(?<subnet>\d+\.\d+\.\d+)\.\d+"
| stats count by subnet
```
![subnet extraction image](./images/ExtractingSubnetsFromSrc.png)

### Build a dashboard
In Splunk, run this search, then click Save As → Dashboard Panel:
``` spl 
index=main sourcetype=csv action=login
| timechart count by status_code
```

Create a second panel using:
``` spl 
index=main sourcetype=csv
| stats count by user
| sort -count
``` 
Arrange both panels into a dashboard called "Overview". Use the time picker to filter both panels simultaneously.

![Dashboard image](./images/Dashboards.png)

### Create an alert
Run the brute force detection search below, then click Save As → Alert, set it to run every 5 minutes, and trigger when count > 5:
``` spl 
index=main sourcetype=csv action=login status_code=401
| stats count by src_ip
| where count > 5
```
### Security investigation scenarios
#### Scenario A: Brute force detection: IP 185.220.101.5 tried multiple usernames before succeeding. Confirmation:
``` spl index=main sourcetype=csv src_ip=185.220.101.5
| table _time, user, action, status_code, host
| sort _time
```
![ScenarioA image](./images/ScenarioA.png)

#### Scenario B: Lateral movement: After brute-forcing into bob, the attacker accessed multiple servers. Trace the path:
``` spl
index=main sourcetype=csv src_ip=185.220.101.5 status_code=200
| table _time, user, host, app, action
| sort _time
```
![ScenarioB image](./images/scenarioB.png)

#### Scenario C: Data exfiltration: alice downloaded an abnormally large amount of data. To find the spike:
``` spl 
index=main sourcetype=csv user=alice action=file_access
| eval MB = round(bytes_sent/1048576, 2)
| table _time, host, MB
| sort _time
```
![ScenarioC image](./images/ScenarioC.png)

#### Scenario D — Full investigation summary: Combine everything into one threat hunting query:
``` spl
index=main sourcetype=csv
| stats count as total_events, sum(bytes_sent) as total_bytes, values(host) as hosts_accessed, values(action) as actions by src_ip, user
| eval risk = case(total_events > 10 AND total_bytes > 5000000, "HIGH", total_events > 5, "MEDIUM", true(), "LOW")
| where risk != "LOW"
| table src_ip, user, risk, total_events, total_bytes, hosts_accessed
| sort -total_bytes
```
![ScenarioC image](./images/scenarioD.png)
