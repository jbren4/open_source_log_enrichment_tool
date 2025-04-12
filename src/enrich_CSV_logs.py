import json
from  logenrichment_functions import Obtain_VT_Ratings
from logenrichment_functions import Obtain_IP_Info_Geolocation_And_Hosting_Provider
from logenrichment_functions import Obtain_IPAbuseDB_Information
from logenrichment_functions import Obtain_VPN_And_Proxy_IPs
from logenrichment_functions import Compute_Bogon_IP_Ranges
from logenrichment_functions  import return_raw_string
from logenrichment_functions  import Enrich_Account_Values
import ipaddress
import requests
import pandas
import datetime

#This function is the backbone of enriching input CSV logs
    #IP fields are enriched with data from VirusTotal,IPInfo,IPAbuseDB,IPQualityScore
    #Account field types are enriched with data from Entra ID
def enrich_CSV_logs(log_df,field_to_enrich_df,dictionary_of_Private_IP_Ranges_And_Bogons,vt_api_key,ip_info_api_key,ip_AbuseDB_API_Key,ipqs_API_key,list_of_enabled_accounts_with_fields_to_enrich_on,bearer_token_for_graph_api_requests,script_config_df):
    print("Iterating through each field to enrich")
    #Iterate through all the fields that will be used to enrich the logs
    for field_to_enrich in field_to_enrich_df['field_name'].to_list():
        #Declare required lists to be added as columns to the dataframe for IP field enrichment
        list_of_IP_Ratings=[]
        VT_Safe_Engine_Score_For_IP=[]
        VT_Malicious_Engine_Score_For_IP=[]
        list_of_hostnames=[]
        list_of_IP_owners=[]
        list_of_ASN=[]
        list_of_countries=[]
        list_of_timezones=[]
        list_of_regions=[]
        list_of_cities=[]
        list_of_Public_And_Private_IPs=[]
        list_of_IP_Versions=[]
        list_of_Usage_Types=[]
        list_of_TOR_Ratings=[]
        list_of_IPAbuseDB_ConfidenceScores=[]
        list_of_proxy_IPs=[]
        list_of_VPN_IPs=[]
        list_of_Bot_IPs=[]
        list_of_IPQS_Owner=[]
        #Declare required lists to be added as columns to the dataframe for account field enrichment
        list_of_UPNs=[]
        list_of_User_Types=[]
        list_of_Account_Creation_Dates=[]
        list_of_Last_Password_Change_Time=[]
        list_of_Job_Titles=[]
        list_of_company_name=[]
        list_of_Departments=[]
        list_of_employee_IDs=[]
        list_of_office_location=[]
        list_of_managers=[]
        list_of_regions_for_accounts=[]
        list_of_zip_codes=[]
        list_of_employee_countries=[]
        list_of_primary_emails=[]
        list_of_mail_nicknames=[]
        #Iterate through all the values for a particular field within the log csv
        print("Iterating through each value for a field")
        for attribute_that_will_enrich_the_event_with in log_df[field_to_enrich].to_list():
            #Value is an IP Address
            if field_to_enrich_df[field_to_enrich_df['field_name']==field_to_enrich]['Type'].to_list()[0].lower().replace(' ','').replace('\n','')=='ip':
                #Check if the IP value is a Bogon IP
                already_enriched=False
                for bogon_ip_range in dictionary_of_Private_IP_Ranges_And_Bogons.keys():
                    if ipaddress.ip_address(attribute_that_will_enrich_the_event_with.upper()) in ipaddress.ip_network(bogon_ip_range):
                        Compute_Bogon_IP_Ranges("CSV",None,None,       dictionary_of_Private_IP_Ranges_And_Bogons.get(bogon_ip_range)[0],dictionary_of_Private_IP_Ranges_And_Bogons.get(bogon_ip_range)[1],dictionary_of_Private_IP_Ranges_And_Bogons.get(bogon_ip_range)[2],list_of_IP_Ratings,VT_Safe_Engine_Score_For_IP,VT_Malicious_Engine_Score_For_IP,list_of_ASN,list_of_countries,list_of_timezones,list_of_hostnames,list_of_regions,list_of_cities,list_of_IP_owners,list_of_IP_Versions,list_of_Public_And_Private_IPs,list_of_Usage_Types,list_of_TOR_Ratings,list_of_IPAbuseDB_ConfidenceScores,list_of_proxy_IPs,list_of_VPN_IPs,list_of_Bot_IPs,list_of_IPQS_Owner)
                        already_enriched=True
                #IP Address is not a bogon and is checked against VT,ipInfo,IPAbuseDB,IPQS
                if already_enriched!=True:
                    #Obtain IP rating from VT and add to output lists
                    Obtain_VT_Ratings(requests.get(url=f"https://www.virustotal.com/api/v3/ip_addresses/{attribute_that_will_enrich_the_event_with}",headers={"accept":"application/json","x-apikey":vt_api_key}).json().get('data').get('attributes').get('last_analysis_results'),"CSV",None,None,list_of_IP_Ratings,VT_Safe_Engine_Score_For_IP,VT_Malicious_Engine_Score_For_IP)
                    #Obtain IP city,region,country,ASN,timezone,hostname,owner per IPInfo from IPInfo
                    Obtain_IP_Info_Geolocation_And_Hosting_Provider(requests.get(url=f"https://ipinfo.io/{attribute_that_will_enrich_the_event_with}/",headers={"Authorization":f"Bearer {ip_info_api_key}","Accept":"application/json"}).json(),"CSV",None,None,list_of_cities,list_of_regions,list_of_countries,list_of_ASN,list_of_timezones,list_of_hostnames,list_of_IP_owners)
                    #Obtain IP type,Public/Private,Usage,Tor,AbuseConfidenceScore IPAbuseDB
                    Obtain_IPAbuseDB_Information(requests.get(url="https://api.abuseipdb.com/api/v2/check",params={"ipAddress":attribute_that_will_enrich_the_event_with,"Verbose":"Verbose"},headers={"Key":ip_AbuseDB_API_Key,"Accept":"Application/Json"}).json().get('data'),"CSV",None,None,list_of_IP_Versions,list_of_Public_And_Private_IPs,list_of_Usage_Types,list_of_TOR_Ratings , list_of_IPAbuseDB_ConfidenceScores)
                    #Obtain IP proxy,VPN,Bot info,Owner per IPQS from IPQS
                    Obtain_VPN_And_Proxy_IPs(requests.get(url=f"https://ipqualityscore.com/api/json/ip/{ipqs_API_key}/{attribute_that_will_enrich_the_event_with}/",params={'strictness':'1','public_access_pair':'False'}).json(),"CSV",None,None,list_of_proxy_IPs,list_of_VPN_IPs,list_of_Bot_IPs,list_of_IPQS_Owner)
                already_enriched=False
            #Value is an account
            elif field_to_enrich_df[field_to_enrich_df['field_name']==field_to_enrich]['Type'].to_list()[0].lower().replace(' ','').replace('\n','')=='Account'.lower().replace(' ','').replace('\n',''):
                Enrich_Account_Values("CSV",attribute_that_will_enrich_the_event_with,field_to_enrich_df[field_to_enrich_df['field_name']==field_to_enrich]['Unique_Account_Identifer'].to_list()[0],None,None,list_of_UPNs,list_of_User_Types,list_of_Account_Creation_Dates,list_of_Last_Password_Change_Time,list_of_Job_Titles,list_of_company_name,list_of_Departments,list_of_employee_IDs,list_of_office_location,list_of_regions_for_accounts,list_of_zip_codes,list_of_employee_countries,list_of_primary_emails,list_of_mail_nicknames,list_of_managers,list_of_enabled_accounts_with_fields_to_enrich_on,bearer_token_for_graph_api_requests)
        #The logDF is enriched with attributes for an IP Address field type
        if field_to_enrich_df[field_to_enrich_df['field_name']==field_to_enrich]['Type'].to_list()[0].lower().replace(' ','').replace('\n','')=='IP'.lower().replace(' ','').replace('\n',''):
            print("Enriching the log_df with new fields of IP type")
            log_df[f'{field_to_enrich}_Safe_Per_VT']=list_of_IP_Ratings
            log_df[f'Number_Of_Engines_That_Marked_{field_to_enrich}_As_Safe']=VT_Safe_Engine_Score_For_IP
            log_df[f'Number_Of_Engines_That_Marked_{field_to_enrich}_As_Malicious']=VT_Malicious_Engine_Score_For_IP
            log_df[f'ASN_Of_{field_to_enrich}']=list_of_ASN
            log_df[f'Country_Code_Of_{field_to_enrich}']=list_of_countries
            log_df[f'Timezone_Of_{field_to_enrich}']=list_of_timezones
            log_df[f'Hostname_Of_{field_to_enrich}']=list_of_hostnames
            log_df[f'Region_Of_{field_to_enrich}']=list_of_regions
            log_df[f'City_Of_{field_to_enrich}']=list_of_cities
            log_df[f'Owner_Of_{field_to_enrich}_From_IPInfo']=list_of_IP_owners
            log_df[f'Owner_Of_{field_to_enrich}_From_IPQS']=list_of_IPQS_Owner
            log_df[f'IP_Version_Of_{field_to_enrich}']=list_of_IP_Versions
            log_df[f'{field_to_enrich}_Is_Public_Or_Private']=list_of_Public_And_Private_IPs
            log_df[f'Usage_Information_Of_{field_to_enrich}']=list_of_Usage_Types
            log_df[f'{field_to_enrich}_Is_Tor']=list_of_TOR_Ratings
            log_df[f'IP_Abuse_DB_Confidence_Rating_Of_{field_to_enrich}']=list_of_IPAbuseDB_ConfidenceScores
            log_df[f'{field_to_enrich}_Is_Proxy']=list_of_proxy_IPs
            log_df[f'{field_to_enrich}_Is_VPN']=list_of_VPN_IPs
            log_df[f'{field_to_enrich}_Is_Bot_IP']=list_of_Bot_IPs
        #LogDF is enriched with attributes for an accountt field type
        elif field_to_enrich_df[field_to_enrich_df['field_name']==field_to_enrich]['Type'].to_list()[0].lower().replace(' ','').replace('\n','')=='Account'.lower().replace(' ','').replace('\n',''):
            print("Enriching the log_df with new fields of account type")
            log_df[f'{field_to_enrich}_UPN']=list_of_UPNs
            log_df[f'{field_to_enrich}_User_Type']=list_of_User_Types
            log_df[f'{field_to_enrich}_Account_Creation_Date']=list_of_Account_Creation_Dates
            log_df[f'{field_to_enrich}_Last_Password_Change_TimeStamp']=list_of_Last_Password_Change_Time
            log_df[f'{field_to_enrich}_Job_Title']=list_of_Job_Titles
            log_df[f'{field_to_enrich}_Company_Name']=list_of_company_name
            log_df[f'{field_to_enrich}_Department']=list_of_Departments
            log_df[f'{field_to_enrich}_employee_Id']=list_of_employee_IDs
            log_df[f'{field_to_enrich}_Office_Location']=list_of_office_location
            log_df[f'{field_to_enrich}_Manager']=list_of_managers
            log_df[f'{field_to_enrich}_Region']=list_of_regions_for_accounts
            log_df[f'{field_to_enrich}_Postal_Code']=list_of_zip_codes
            log_df[f'{field_to_enrich}_Country']=list_of_employee_countries
            log_df[f'{field_to_enrich}_Email']=list_of_primary_emails
            log_df[f'{field_to_enrich}_Mail_Nickname']=list_of_mail_nicknames
    #Write the enriched DF to disk as a CSV file
    current_timestamp=datetime.datetime(2025,4,11).now().strftime("%Y-%m-%d_%H_%M_%S_%f")
    print("Writing output report")
    log_df.to_csv(path_or_buf=f'{return_raw_string(script_config_df[script_config_df['Type']=='Output_Path']['setting_value'].to_list()[0])}enriched_CSV_logs_{current_timestamp}.csv',header=True,index=False)
    print("Output report written")
