import requests
import re

#Enrich the log with the following data from Virus Total
    #Number of engines that marked the IP as malicious
    #Number of engines that marked the IP as safe
    #True/False if the IP is safe. An IP is considered safe if all Virus Total Engines have marked the IP as safe
#Enriches the log based on the values of IP fields
def Obtain_VT_Ratings(dictionary_of_VT_Engine_Ratings,log_type_param ,log_object_param,field_name_to_enrich_param,list_of_IP_Ratings_param,VT_Safe_Engine_Score_For_IP_param,VT_Malicious_Engine_Score_For_IP_param):
    #Declare list of every Virus Total Engine
    list_of_vt_engines=['ArcSight Threat Intelligence','Criminal IP','G-Data','Lionic','alphaMountain.ai','Abusix','ADMINUSLabs','AlienVault','benkow.cc','Certego','CINS Army','CRDF','desenmascara.me','Dr.Web','Emsisoft','ESTsecurity','Google Safebrowsing','Heimdal Security','Malwared','malwares.com URL checker','Phishing Database','PREBYTES','Quttera','SCUMWARE.org','securolytics','Sophos','StopForumSpam','ThreatHive','Trustwave','Viettel Threat Intelligence','VX Vault','Xcitium Verdict Cloud','ZeroCERT','AutoShun','Bfore.Ai PreCrime','Cluster25','Cyan','Forcepoint ThreatSeeker','Gridinsoft',
    'Kaspersky','MalwareURL','Netcraft','PhishLabs','SafeToOpen','SecureBrain','URLQuery','ZeroFox','BitDefender','CyRadar','Juniper Networks','SOCRadar','AlphaSOC','Acronis','AILabs (MONITORAPP)','Antiy-AVL','Blueliv','Chong Lua Dao','CMC Threat Intelligence','Cyble','DNS8','EmergingThreats','ESET','Fortinet','GreenSnow','IPsum','MalwarePatrol','OpenPhish','Phishtank','Quick Heal','Scantitan','Seclookup','Snort IP sample list','Spam404','Sucuri SiteCheck','Threatsourcing','URLhaus','ViriBack','Webroot','Yandex Safebrowsing','0xSI_f33d','Axur','Bkav','CSIS Security Group','Ermes','GCP Abuse Intelligence','Hunt.io Intelligence','Lumu','Mimecast','PhishFort','PrecisionSec','Sansec eComscan','Underworld','VIPRE','zvelo']
    number_of_safe_engines_per_IP=0
    number_of_malicious_engines_per_IP=0
    #Iterate through each Virus Total Engine to determine if the IP was marked as malicious by the engine
    for VT_Engine_Provider in list_of_vt_engines:
        if dictionary_of_VT_Engine_Ratings.get(VT_Engine_Provider).get('result').lower() not in ['clean','unrated']:
            number_of_malicious_engines_per_IP+=1
        else:
            number_of_safe_engines_per_IP+=1
    #IP is malicious and JSON logs are being enriched
    if log_type_param.upper()=="JSON" and number_of_malicious_engines_per_IP!=0:
        log_object_param[f'{field_name_to_enrich_param}_Safe_Per_VT']=False
        log_object_param[f'Number_Of_Engines_That_Marked_{field_name_to_enrich_param}_As_Safe']=number_of_safe_engines_per_IP
        log_object_param[f'Number_Of_Engines_That_Marked_{field_name_to_enrich_param}_As_Malicious']=number_of_malicious_engines_per_IP
    #IP is safe and JSON logs are being enriched
    elif log_type_param.upper()=="JSON":
        log_object_param[f'{field_name_to_enrich_param}_Safe_Per_VT']=True
        log_object_param[f'Number_Of_Engines_That_Marked_{field_name_to_enrich_param}_As_Safe']=number_of_safe_engines_per_IP
        log_object_param[f'Number_Of_Engines_That_Marked_{field_name_to_enrich_param}_As_Malicious']=number_of_malicious_engines_per_IP
    #IP is malicious and CSV logs are being enriched
    elif log_type_param.upper()=="CSV" and number_of_malicious_engines_per_IP!=0:
        list_of_IP_Ratings_param.append(False)
        VT_Safe_Engine_Score_For_IP_param.append(number_of_safe_engines_per_IP)
        VT_Malicious_Engine_Score_For_IP_param.append(number_of_malicious_engines_per_IP)
    #IP is safe and CSV logs are being enriched
    elif log_type_param.upper()=="CSV":
        list_of_IP_Ratings_param.append(True)
        VT_Safe_Engine_Score_For_IP_param.append(number_of_safe_engines_per_IP)
        VT_Malicious_Engine_Score_For_IP_param.append(number_of_malicious_engines_per_IP)

#Enrich the log with the following data from IPInfo
    #Geolocation: City of the IP
    #Geolocation: Region/State of the IP
    #Geolocation: Country of the IP
    #Geolocation: Timezone of the IP
    #Hostname of the IP
    #ASN of the IP
    #Organizational Owner or Hosting Provider of the IP per IPInfo
#Enriches the log based on the values of IP fields
def Obtain_IP_Info_Geolocation_And_Hosting_Provider(IP_info_dictionary, log_type_param, log_object_param,field_name_to_enrich_param,       list_of_cities_param,list_of_regions_param,list_of_countries_param,list_of_ASN_param,list_of_timezones_param,list_of_hostnames_param,list_of_IP_owners_param):
    #JSON logs are being enriched
    if log_type_param.upper()=="JSON":
        if IP_info_dictionary.get('city'):
            log_object_param[f'City_Of_{field_name_to_enrich_param}']=IP_info_dictionary.get('city')
        else:
            log_object_param[f'City_Of_{field_name_to_enrich_param}']='Not Found'
        if IP_info_dictionary.get('region'):
            log_object_param[f'Region_Of_{field_name_to_enrich_param}']=IP_info_dictionary.get('region')
        else:
            log_object_param[f'Region_Of_{field_name_to_enrich_param}']='Not Found'
        if IP_info_dictionary.get('country'):
            log_object_param[f'Country_Code_Of_{field_name_to_enrich_param}']=IP_info_dictionary.get('country')
        else:
            log_object_param[f'Country_Code_Of_{field_name_to_enrich_param}']='Not Found'
        if IP_info_dictionary.get('timezone'):
            log_object_param[f'Timezone_Of_{field_name_to_enrich_param}']=IP_info_dictionary.get('timezone')
        else:
            log_object_param[f'Timezone_Of_{field_name_to_enrich_param}']='Not Found'
        if IP_info_dictionary.get('hostname'):
            log_object_param[f'Hostname_Of_{field_name_to_enrich_param}']=IP_info_dictionary.get('hostname')
        else:
            log_object_param[f'Hostname_Of_{field_name_to_enrich_param}']='Not Found'
        if IP_info_dictionary.get('org'):
            log_object_param[f'ASN_Of_{field_name_to_enrich_param}']=IP_info_dictionary.get('org').split(' ')[0].replace(' ','')
        else:
            log_object_param[f'ASN_Of_{field_name_to_enrich_param}']="Not Found"
        if IP_info_dictionary.get('org') and IP_info_dictionary.get('org')!='':
            log_object_param[f'Owner_Of_{field_name_to_enrich_param}_From_IPInfo']=re.search(r'\s.*',IP_info_dictionary.get('org')).group().removeprefix(' ')
        else:
            log_object_param[f'Owner_Of_{field_name_to_enrich_param}_From_IPInfo']="Not Found"
    #CSV logs are being enriched
    elif log_type_param.upper()=="CSV":
        if IP_info_dictionary.get('city'):
            list_of_cities_param.append(IP_info_dictionary.get('city'))
        else:
            list_of_cities_param.append("Not Found")
        if IP_info_dictionary.get('region'):
            list_of_regions_param.append(IP_info_dictionary.get('region'))
        else:
            list_of_regions_param.append("Not Found")
        if IP_info_dictionary.get('country'):
            list_of_countries_param.append(IP_info_dictionary.get('country'))
        else:
            list_of_countries_param.append("Not Found")
        if IP_info_dictionary.get('timezone'):
            list_of_timezones_param.append(IP_info_dictionary.get('timezone'))
        else:
            list_of_timezones_param.append("Not Found")
        if IP_info_dictionary.get('hostname'):
            list_of_hostnames_param.append(IP_info_dictionary.get('hostname'))
        else:
            list_of_hostnames_param.append("Not Found")
        if IP_info_dictionary.get('org'):
            list_of_ASN_param.append(IP_info_dictionary.get('org').split(' ')[0].replace(' ',''))
        else:
            list_of_ASN_param.append("Not Found")
        if IP_info_dictionary.get('org') and IP_info_dictionary.get('org')!='':
            list_of_IP_owners_param.append(re.search(r'\s.*',IP_info_dictionary.get('org')).group().removeprefix(' '))
        else:
            list_of_IP_owners_param.append("Not Found")
#Enrich the log with the following data from IPAbuseDB
    #IPVersion (IPv4 vs IPv6)
    #Public vs Private IP
    #Usage Type of the IP (ISP, Hosting Provider, ect)
    #isTor IP True/False
    #IPAbuseConfidenceScore Score:0 (Safe IP) Score:100 (High Confidence that IP is malicious)
#Enriches the log based on the values of IP fields
def Obtain_IPAbuseDB_Information(dictionary_for_info_about_IP, log_type_param,log_object_param  ,field_name_to_enrich_param, list_of_IP_Versions_param,list_of_Public_And_Private_IPs_param,list_of_Usage_Types_param,list_of_TOR_Ratings_param,list_of_IPAbuseDB_ConfidenceScores_param):
    #JSON logs being enriched
    if log_type_param.upper()=="JSON":
        if dictionary_for_info_about_IP.get('ipVersion')==4:
            log_object_param[f'IP_Version_Of_{field_name_to_enrich_param}']="IPv4"
        else:
            log_object_param[f'IP_Version_Of_{field_name_to_enrich_param}']="IPv6"
        if dictionary_for_info_about_IP.get("isPublic"):
            log_object_param[f'{field_name_to_enrich_param}_Is_Public_Or_Private']='Public'
        else:
            log_object_param[f'{field_name_to_enrich_param}_Is_Public_Or_Private']='Private'
        if dictionary_for_info_about_IP.get('usageType'):
            log_object_param[f'Usage_Information_Of_{field_name_to_enrich_param}']=dictionary_for_info_about_IP.get('usageType')
        else:
            log_object_param[f'Usage_Information_Of_{field_name_to_enrich_param}']="Not Found"
        if dictionary_for_info_about_IP.get('isTor'):
            log_object_param[f'{field_name_to_enrich_param}_Is_Tor']=True
        else:
            log_object_param[f'{field_name_to_enrich_param}_Is_Tor']=False
        if dictionary_for_info_about_IP.get('abuseConfidenceScore')!=None:
            log_object_param[f'IP_Abuse_DB_Confidence_Rating_Of_{field_name_to_enrich_param}']=dictionary_for_info_about_IP.get('abuseConfidenceScore')
        else:
            log_object_param[f'IP_Abuse_DB_Confidence_Rating_Of_{field_name_to_enrich_param}']="Not Found"
    #CSV logs being enriched
    elif log_type_param.upper()=="CSV":
        if dictionary_for_info_about_IP.get('ipVersion')==4:
            list_of_IP_Versions_param.append('IPv4')
        else:
            list_of_IP_Versions_param.append('IPv6')
        if dictionary_for_info_about_IP.get("isPublic")==True:
            list_of_Public_And_Private_IPs_param.append("Public")
        else:
            list_of_Public_And_Private_IPs_param.append("Private")
        if dictionary_for_info_about_IP.get('usageType'):
            list_of_Usage_Types_param.append(dictionary_for_info_about_IP.get('usageType'))
        else:
            list_of_Usage_Types_param.append("Not Found")
        if dictionary_for_info_about_IP.get('isTor'):
            list_of_TOR_Ratings_param.append(True)
        else:
            list_of_TOR_Ratings_param.append(False)
        if dictionary_for_info_about_IP.get('abuseConfidenceScore')!=None:
            list_of_IPAbuseDB_ConfidenceScores_param.append(dictionary_for_info_about_IP.get('abuseConfidenceScore'))
        else:
            list_of_IPAbuseDB_ConfidenceScores_param.append("Not Found")


#Enrich the log with the following data from IPQS (IPQualityScore)
    #IPisProxy (True/False)
    #IPisVPN (True/False)
    #IPisBot (True/False)
    #isTor IP (True/False)
    #Organizational Owner or Hosting Provider of the IP per IPQS
#Enriches the log based on the values of IP fields
def Obtain_VPN_And_Proxy_IPs(dictionary_of_IP_Attributes,Log_Type,log_object,field_to_enrich_with,list_of_proxy_IPs_Params,list_of_VPN_IP_Params,list_of_Bot_IP_params,list_of_IPQS_Owner_params):
    #JSON logs being enriched
    if Log_Type.upper()=="JSON":
        if dictionary_of_IP_Attributes.get('proxy'):
            log_object[f'{field_to_enrich_with}_Is_Proxy']=True
        else:
            log_object[f'{field_to_enrich_with}_Is_Proxy']=False
        if dictionary_of_IP_Attributes.get('active_vpn'):
            log_object[f'{field_to_enrich_with}_Is_VPN']=True
        else:
            log_object[f'{field_to_enrich_with}_Is_VPN']=False
        if dictionary_of_IP_Attributes.get('bot_status'):
            log_object[f'{field_to_enrich_with}_Is_Bot_IP']=True
        else:
            log_object[f'{field_to_enrich_with}_Is_Bot_IP']=False
        if dictionary_of_IP_Attributes.get('organization') and dictionary_of_IP_Attributes.get('organization')!='':
            log_object[f'Owner_Of_{field_to_enrich_with}_From_IPQS']=dictionary_of_IP_Attributes.get('organization')
        else:
            log_object[f'Owner_Of_{field_to_enrich_with}_From_IPQS']="Not Found"
    #CSV logs being enriched
    elif Log_Type.upper()=="CSV":
        if dictionary_of_IP_Attributes.get('proxy'):
            list_of_proxy_IPs_Params.append(True)
        else:
            list_of_proxy_IPs_Params.append(False)
        if dictionary_of_IP_Attributes.get('active_vpn'):
            list_of_VPN_IP_Params.append(True)
        else:
            list_of_VPN_IP_Params.append(False)
        if dictionary_of_IP_Attributes.get('bot_status'):
            list_of_Bot_IP_params.append(True)
        else:
            list_of_Bot_IP_params.append(False)
        if dictionary_of_IP_Attributes.get('organization') and dictionary_of_IP_Attributes.get('organization')!='':
            list_of_IPQS_Owner_params.append(dictionary_of_IP_Attributes.get('organization'))
        else:
            list_of_IPQS_Owner_params.append("Not Found")
#Function that enriches the log with fields indicating the IP is a bogon/private IP
def Compute_Bogon_IP_Ranges(Log_Type,dictionary_of_JSON_Log,field_name,IP_Version,Public_Or_Private,Usage_Type,list_of_IP_Ratings_param,VT_Safe_Engine_Score_For_IP_param,VT_Malicious_Engine_Score_For_IP_param,list_of_ASN_param,list_of_countries_param,list_of_timezones_param,list_of_hostnames_param,list_of_regions_param,list_of_cities_param,list_of_IP_owners_param,list_of_IP_Versions_param,list_of_Public_And_Private_IPs_param,list_of_Usage_Types_param,list_of_TOR_Ratings_param,list_of_IPAbuseDB_ConfidenceScores_param,list_of_proxy_IPs_param,list_of_VPN_IPs_param,list_of_Bot_IPs_param,list_of_IPQS_Owner_params):
        #JSON logs being enriched
        if Log_Type.upper()=="JSON":
            dictionary_of_JSON_Log[f'{field_name}_Safe_Per_VT']=True
            dictionary_of_JSON_Log[f'Number_Of_Engines_That_Marked_{field_name}_As_Safe']=94
            dictionary_of_JSON_Log[f'Number_Of_Engines_That_Marked_{field_name}_As_Malicious']=0
            dictionary_of_JSON_Log[f'ASN_Of_{field_name}']="N/A"
            dictionary_of_JSON_Log[f'Country_Code_Of_{field_name}']="N/A"
            dictionary_of_JSON_Log[f'Timezone_Of_{field_name}']="N/A"
            dictionary_of_JSON_Log[f'Hostname_Of_{field_name}']="N/A"
            dictionary_of_JSON_Log[f'Region_Of_{field_name}']="N/A"
            dictionary_of_JSON_Log[f'City_Of_{field_name}']="N/A"
            dictionary_of_JSON_Log[f'Owner_Of_{field_name}_From_IPInfo']="N/A"
            dictionary_of_JSON_Log[f'Owner_Of_{field_name}_From_IPQS']="N/A"
            dictionary_of_JSON_Log[f'IP_Version_Of_{field_name}']=IP_Version
            dictionary_of_JSON_Log[f'{field_name}_Is_Public_Or_Private']=Public_Or_Private
            dictionary_of_JSON_Log[f'Usage_Information_Of_{field_name}']=Usage_Type
            dictionary_of_JSON_Log[f'{field_name}_Is_Tor']=False
            dictionary_of_JSON_Log[f'IP_Abuse_DB_Confidence_Rating_Of_{field_name}']="N/A"
            dictionary_of_JSON_Log[f'{field_name}_Is_Proxy']=False
            dictionary_of_JSON_Log[f'{field_name}_Is_VPN']=False
            dictionary_of_JSON_Log[f'{field_name}_Is_Bot_IP']=False
        #CSV logs being enriched
        elif Log_Type.upper()=="CSV":
            list_of_IP_Ratings_param.append(True)
            VT_Safe_Engine_Score_For_IP_param.append(94)
            VT_Malicious_Engine_Score_For_IP_param.append(0)
            list_of_ASN_param.append("N/A")
            list_of_countries_param.append("N/A")
            list_of_timezones_param.append("N/A")
            list_of_hostnames_param.append("N/A")
            list_of_regions_param.append('N/A')
            list_of_cities_param.append("N/A")
            list_of_IP_owners_param.append("N/A")
            list_of_IP_Versions_param.append(IP_Version)
            list_of_Public_And_Private_IPs_param.append(Public_Or_Private)
            list_of_Usage_Types_param.append(Usage_Type)
            list_of_TOR_Ratings_param.append(False)
            list_of_IPAbuseDB_ConfidenceScores_param.append("N/A")
            list_of_proxy_IPs_param.append(False)
            list_of_VPN_IPs_param.append(False)
            list_of_Bot_IPs_param.append(False)
            list_of_IPQS_Owner_params.append("N/A")

#Function that takes in a regular Python string and returns a raw string representation of the input string
    #Used for file paths
def return_raw_string(regular_string):
    return r'{}'.format(regular_string)

#Enrich the log with the following data from Entra ID Cloud Directory
    #userPrincipalName (UPN)
    #userType (Member/Guest)
    #createdDateTime (Account Creation Timestamp)
    #lastPasswordChangeDateTime (Account last password change timestamp)
    #jobTitle (Job Title)
    #companyName (Company Name)
    #department (Department)
    #employeeId (EmployeeID)
    #officeLocation (Physical Office Location)
    #state (State/Region)
    #postalCode (Zip Code)
    #country (Country of the user)
    #mail (Primary Email)
    #mailNickname (mailNickname)
    #Account's Manager (Adds the UPN of the account's manager to the log)
#Enriches the log based on the values of account fields
def Enrich_Account_Values(log_type,attribute_that_will_enrich_the_event_with,unique_account_identifier_attribute,name_of_field,log_object,list_of_UPNs,list_of_User_Types,list_of_Account_Creation_Dates,list_of_Last_Password_Change_Time,list_of_Job_Titles,list_of_company_name,list_of_Departments,list_of_employee_IDs,list_of_office_location,list_of_regions_for_accounts,list_of_zip_codes,list_of_employee_countries,list_of_primary_emails,list_of_mail_nicknames,list_of_managers,list_of_enabled_accounts_with_fields_to_enrich_on,bearer_token_for_graph_api_requests):
    account_already_enriched=False
    #Iterate through each enabled account with the directory
    for enabled_account in list_of_enabled_accounts_with_fields_to_enrich_on:
        #Account field within CSV log matches an account within the cloud directory. Thus enrich the CSV  log based on values extracted from the cloud directory
        if enabled_account.get(unique_account_identifier_attribute)!=None and enabled_account.get(unique_account_identifier_attribute).lower().replace(' ','')==attribute_that_will_enrich_the_event_with.lower().replace(' ','') and log_type=="CSV":
            account_already_enriched=True
            if enabled_account.get('userPrincipalName'):
                list_of_UPNs.append(enabled_account.get('userPrincipalName'))
            else:
                list_of_UPNs.append("Not Found")
            if enabled_account.get('userType'):
                list_of_User_Types.append(enabled_account.get('userType'))
            else:
                list_of_User_Types.append("Not Found")
            if enabled_account.get('createdDateTime'):
                list_of_Account_Creation_Dates.append(enabled_account.get('createdDateTime'))
            else:
                list_of_Account_Creation_Dates.append("Not Found")
            if enabled_account.get('lastPasswordChangeDateTime'):
                list_of_Last_Password_Change_Time.append(enabled_account.get('lastPasswordChangeDateTime'))
            else:
                list_of_Last_Password_Change_Time.append("Not Found")
            if enabled_account.get('jobTitle'):
                list_of_Job_Titles.append(enabled_account.get('jobTitle'))
            else:
                list_of_Job_Titles.append("Not Found")
            if enabled_account.get('companyName'):
                list_of_company_name.append(enabled_account.get('companyName'))
            else:
                list_of_company_name.append("Not Found")
            if enabled_account.get('department'):
                list_of_Departments.append(enabled_account.get('department'))
            else:
                list_of_Departments.append("Not Found")
            if enabled_account.get('employeeId'):
                list_of_employee_IDs.append(enabled_account.get('employeeId'))
            else:
                list_of_employee_IDs.append("Not Found")
            if enabled_account.get('officeLocation'):
                list_of_office_location.append(enabled_account.get('officeLocation'))
            else:
                list_of_office_location.append("Not Found")
            if enabled_account.get('state'):
                list_of_regions_for_accounts.append(enabled_account.get('state'))
            else:
                list_of_regions_for_accounts.append("Not Found")
            if  enabled_account.get('postalCode'):
                list_of_zip_codes.append(enabled_account.get('postalCode'))
            else:
                list_of_zip_codes.append("Not Found")
            if enabled_account.get('country'):
                list_of_employee_countries.append(enabled_account.get('country'))
            else:
                list_of_employee_countries.append("Not Found")
            if enabled_account.get('mail'):
                list_of_primary_emails.append(enabled_account.get('mail'))
            else:
                list_of_primary_emails.append("Not Found")
            if enabled_account.get('mailNickname'):
                list_of_mail_nicknames.append(enabled_account.get('mailNickname'))
            else:
                list_of_mail_nicknames.append("Not Found")
            manager_response_object=requests.get(url=f"https://graph.microsoft.com/v1.0/users/{enabled_account.get('userPrincipalName')}/manager",headers={"authorization":f"Bearer {bearer_token_for_graph_api_requests}"})
            if manager_response_object.status_code==200:
                list_of_managers.append(manager_response_object.json().get('userPrincipalName'))
            else:
                list_of_managers.append("Not Found")
        #Account field with JSON log matches an account within the cloud directory. Thus enrich the JSON log based on values extracted from the cloud directory
        elif  enabled_account.get(unique_account_identifier_attribute)!=None and enabled_account.get(unique_account_identifier_attribute).lower().replace(' ','')==attribute_that_will_enrich_the_event_with.lower().replace(' ','') and log_type=="JSON":
            account_already_enriched=True
            if enabled_account.get('userPrincipalName'):
                log_object[f'{name_of_field}_UPN']=enabled_account.get('userPrincipalName')
            else:
                log_object[f'{name_of_field}_UPN']="Not Found"
            if enabled_account.get('userType'):
                log_object[f'{name_of_field}_User_Type']=enabled_account.get('userType')
            else:
                log_object[f'{name_of_field}_User_Type']="Not Found"
            if enabled_account.get('createdDateTime'):
                log_object[f'{name_of_field}_Account_Creation_Date']=enabled_account.get('createdDateTime')
            else:
                log_object[f'{name_of_field}_Account_Creation_Date']="Not Found"
            if enabled_account.get('lastPasswordChangeDateTime'):
                log_object[f'{name_of_field}_Last_Password_Change_TimeStamp']=enabled_account.get('lastPasswordChangeDateTime')
            else:
                log_object[f'{name_of_field}_Last_Password_Change_TimeStamp']="Not Found"
            if enabled_account.get('jobTitle'):
                log_object[f'{name_of_field}_Job_Title']=enabled_account.get('jobTitle')
            else:
                log_object[f'{name_of_field}_Job_Title']="Not Found"
            if enabled_account.get('companyName'):
                log_object[f'{name_of_field}_Company_Name']=enabled_account.get('companyName')
            else:
                log_object[f'{name_of_field}_Company_Name']="Not Found"
            if enabled_account.get('department'):
                log_object[f'{name_of_field}_Department']=enabled_account.get('department')
            else:
                log_object[f'{name_of_field}_Department']="Not Found"
            if enabled_account.get('employeeId'):
                log_object[f'{name_of_field}_employee_Id']=enabled_account.get('employeeId')
            else:
                log_object[f'{name_of_field}_employee_Id']="Not Found"
            if enabled_account.get('officeLocation'):
                log_object[f'{name_of_field}_Office_Location']=enabled_account.get('officeLocation')
            else:
                log_object[f'{name_of_field}_Office_Location']="Not Found"
            if enabled_account.get('state'):
                log_object[f'{name_of_field}_Region']=enabled_account.get('state')
            else:
                log_object[f'{name_of_field}_Region']="Not Found"
            if  enabled_account.get('postalCode'):
                log_object[f'{name_of_field}_Postal_Code']=enabled_account.get('postalCode')
            else:
                log_object[f'{name_of_field}_Postal_Code']="Not Found"
            if enabled_account.get('country'):
                log_object[f'{name_of_field}_Country']=enabled_account.get('country')
            else:
                log_object[f'{name_of_field}_Country']="Not Found"
            if enabled_account.get('mail'):
                log_object[f'{name_of_field}_Email']=enabled_account.get('mail')
            else:
                log_object[f'{name_of_field}_Email']="Not Found"
            if enabled_account.get('mailNickname'):
                log_object[f'{name_of_field}_Mail_Nickname']=enabled_account.get('mailNickname')
            else:
                log_object[f'{name_of_field}_Mail_Nickname']="Not Found"
            manager_response_object=requests.get(url=f"https://graph.microsoft.com/v1.0/users/{enabled_account.get('userPrincipalName')}/manager",headers={"authorization":f"Bearer {bearer_token_for_graph_api_requests}"})
            if manager_response_object.status_code==200:
                log_object[f'{name_of_field}_Manager']=manager_response_object.json().get('userPrincipalName')
            else:
                log_object[f'{name_of_field}_Manager']="Not Found"
    #Account field within CSV log wasn't found within an account within the cloud directory. Thus indicate account not found
    if not account_already_enriched and log_type=="CSV":
        list_of_UPNs.append("Account not found within Entra ID")
        list_of_User_Types.append("Account not found within Entra ID")
        list_of_Account_Creation_Dates.append("Account not found within Entra ID")
        list_of_Last_Password_Change_Time.append("Account not found within Entra ID")
        list_of_Job_Titles.append("Account not found within Entra ID")
        list_of_company_name.append("Account not found within Entra ID")
        list_of_Departments.append("Account not found within Entra ID")
        list_of_employee_IDs.append("Account not found within Entra ID")
        list_of_office_location.append("Account not found within Entra ID")
        list_of_managers.append("Account not found within Entra ID")
        list_of_regions_for_accounts.append("Account not found within Entra ID")
        list_of_zip_codes.append("Account not found within Entra ID")
        list_of_employee_countries.append("Account not found within Entra ID")
        list_of_primary_emails.append("Account not found within Entra ID")
        list_of_mail_nicknames.append("Account not found within Entra ID")
    #Account field within JSON log wasn't found within an account within the cloud directory. Thus indicate account not found
    elif not account_already_enriched  and log_type=="JSON":
        log_object[f'{name_of_field}_UPN']="Account not found within Entra ID"
        log_object[f'{name_of_field}_User_Type']="Account not found within Entra ID"
        log_object[f'{name_of_field}_Account_Creation_Date']="Account not found within Entra ID"
        log_object[f'{name_of_field}_Last_Password_Change_TimeStamp']="Account not found within Entra ID"
        log_object[f'{name_of_field}_Job_Title']="Account not found within Entra ID"
        log_object[f'{name_of_field}_Company_Name']="Account not found within Entra ID"
        log_object[f'{name_of_field}_Department']="Account not found within Entra ID"
        log_object[f'{name_of_field}_employee_Id']="Account not found within Entra ID"
        log_object[f'{name_of_field}_Office_Location']="Account not found within Entra ID"
        log_object[f'{name_of_field}_Region']="Account not found within Entra ID"
        log_object[f'{name_of_field}_Postal_Code']="Account not found within Entra ID"
        log_object[f'{name_of_field}_Country']="Account not found within Entra ID"
        log_object[f'{name_of_field}_Email']="Account not found within Entra ID"
        log_object[f'{name_of_field}_Mail_Nickname']="Account not found within Entra ID"
        log_object[f'{name_of_field}_Manager']="Account not found within Entra ID"
