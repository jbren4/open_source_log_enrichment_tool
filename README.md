# Open Source Log Enrichment tool

    This is an open source modular log enrichment tool that enriches JSON or CSV logs with:
        -IP Geolocation
        -Threat Intel data
        -Cloud Directory Information
    Designed by security engineers for Detection Engineering, SOAR Automations, and Incident Responders

---

## Main Features
    -Batch Processing of input JSON/CSV logs
    -Enriched logs are written to disk as JSON/CSV files
    -API Integrations with threat intel providers and cloud directories
        -IPAbuseDB
        -IPInfo
        -VirusTotal
        -IPQualityScore
        -Entra ID
        -Modular and easy to expand
    -Currently IP and accounts fields are supported 

---

## Getting Started and Configuration
    - Clone the repo: git clone https://github.com/jbren4/open_source_log_enrichment_tool
    - cd ./open_source_log_enrichment_tool/configfiles
    - **Configure script_config.csv**
        
        - Specify values in setting_value column
            ```
            /path_to_CSV_or_JSON_log_file_to_enrich Path_to_Log_File_To_Enrich
            Client_ID_Obtained_From_Entra_ID Entra_Client_ID
            Client_Secret_Obtained_From_Entra_ID Entra_Client_Secret
            Entra_Tenant_ID                     Tenant_ID
            /path_to_field_config.csv           Path_to_Field_Configuration_File
            Virus_Total_API_Key                 VT_API_Key
            IP_Info_API_Key                     IP_Info_API_Key
            IP_Abuse_DB_API_Key                 IP_Abuse_DB_API_Key
            IP_Quality_Score_API_Key            IPQS_API_Key
            /Path_To_write_enriched_log_files   Output_Path
            Output format (JSON or CSV)         Output_Option
            Input_Log_File_Format (JSON/CSV)    Input_File_Format
            ```
   
   - **Configure field_config.csv**
        
        - Specify values in the field_name column
            -Here indicate the field names that will be levereged to enrich the logs
        - Specify values in the type column 
            -Here indicate the datatype of the field
                -Only IP and Account types are currently supported
        - Specify values in Unique_Account_Identifer column
            -This is only required for fields of account type
            -This value specifies the Entra ID account attribute that uniquely idetifies the account format in the log
   - cd ..
   - **Install necessary Python modules:** 
       - pip install -r requirements.txt
   - cd ./src
   - **Configure enrich_logs.py**
        - On Line 9: Enter the path to script_config.csv
            -pd.read_csv('PATH_TO_script_config.csv')

---

## Run the Project
    python3 enrich_logs.py

---

## Roadmap
    -[x] CSV and JSON batch processing
    -[x] API integration for enriching IP fields 
    -[x] API integration for enriching account fields
    -[]  API integration for enriching domain fields (May 2025)
    -[]  Gracefully handle exceeding API limits (June 2025)
    -[]  Command line utility and configuration via install script (August 2025)
    -[]  Stream processing via API post requsts (October 2025)
    -[]  Integration with SIEM platforms (January 2026)
    -[]  Log Parsing and normalization support (TBD)
