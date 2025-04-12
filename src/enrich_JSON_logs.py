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

#This function is the backbone of enriching input JSON logs
    #IP fields are enriched with fields from VirusTotal,IPInfo,IPAbuseDB,IPQualityScore
    #Account field types are enriched with fields from Entra ID
def enrich_JSON_logs(raw_string_path_to_log_file,list_of_fields_to_enrich,field_to_enrich_df_param,dictionary_of_Private_IP_Ranges_And_Bogons,vt_api_key,ip_info_api_key,ip_AbuseDB_API_Key,ipqs_API_key,list_of_enabled_accounts_with_fields_to_enrich_on,bearer_token_for_graph_api_requests,script_config_df):
    #Read in list of JSON logs to be enriched via Batch Processing
    list_of_log_objects=[]
    print("Attempting to read in .JSON file of logs")
    with open(raw_string_path_to_log_file,'r') as file_obj:
        list_of_log_objects=json.load(file_obj)
    print("Successfully obtained JSON logs")
    #Iterate through each field_name that are utilized to enrich the log object
    for field_to_enrich in list_of_fields_to_enrich:
        print(f"Now enriching using field: {field_to_enrich}")
        
        #Utilize the current field's value in each log object to enrich the current log
        for log_object in list_of_log_objects:
            #Field is of type IP
            if field_to_enrich_df_param[field_to_enrich_df_param['field_name']==field_to_enrich]['Type'].to_list()[0].lower().replace(' ','').replace('\n','')=='ip':
                already_enriched=False
                #Check if IP is a bogon IP
                for bogon_ip_range in dictionary_of_Private_IP_Ranges_And_Bogons.keys():
                    if ipaddress.ip_address(log_object.get(field_to_enrich).upper()) in ipaddress.ip_network(bogon_ip_range):
                        Compute_Bogon_IP_Ranges("JSON",log_object,field_to_enrich,dictionary_of_Private_IP_Ranges_And_Bogons.get(bogon_ip_range)[0],dictionary_of_Private_IP_Ranges_And_Bogons.get(bogon_ip_range)[1],dictionary_of_Private_IP_Ranges_And_Bogons.get(bogon_ip_range)[2],None, None, None, None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None)
                        already_enriched=True
                #IP is not a bogon IP and API calls are made to enrich the log
                if already_enriched!=True:
                    #Obtain IP rating from VT
                    Obtain_VT_Ratings(requests.get(url=f"https://www.virustotal.com/api/v3/ip_addresses/{log_object.get(field_to_enrich)}",headers={"accept":"application/json","x-apikey":vt_api_key}).json().get('data').get('attributes').get('last_analysis_results'),"JSON" , log_object, field_to_enrich,None,None,None)
                    #Obtain IP city,region,country,ASN,timezone,hostname,owner from IPInfo and add fields to the current log's dictionary object
                    Obtain_IP_Info_Geolocation_And_Hosting_Provider(requests.get(url=f"https://ipinfo.io/{log_object.get(field_to_enrich)}/",headers={"Authorization":f"Bearer {ip_info_api_key}","Accept":"application/json"}).json(),"JSON",log_object,field_to_enrich,  None,None,None,None,None,None,None)
                    #Obtain IP type,Public/Private,Usage,Tor,AbuseConfidenceScore from IPAbuseDB and add fields to the current log's dictionary object
                    Obtain_IPAbuseDB_Information(requests.get(url="https://api.abuseipdb.com/api/v2/check",params={"ipAddress":log_object.get(field_to_enrich),"Verbose":"Verbose"},headers={"Key":ip_AbuseDB_API_Key,"Accept":"Application/Json"}).json().get('data'), "JSON",log_object,field_to_enrich, None,None,None,None , None)
                    #Obtain IP proxy,VPN,Bot rating, owner per IPQS from IPQS
                    Obtain_VPN_And_Proxy_IPs(requests.get(url=f"https://ipqualityscore.com/api/json/ip/{ipqs_API_key}/{log_object.get(field_to_enrich)}/",params={'strictness':'1','public_access_pair':'False'}).json(),"JSON",log_object,field_to_enrich,None,None,None,None)
                already_enriched=False
            #Field is of type account
            elif field_to_enrich_df_param[field_to_enrich_df_param['field_name']==field_to_enrich]['Type'].to_list()[0].lower().replace(' ','').replace('\n','')=='account':
                #Enrich_Account_Values() is used to enrich the log via the account value with info from the Entra ID cloud directory
                Enrich_Account_Values("JSON",log_object.get(field_to_enrich), field_to_enrich_df_param[field_to_enrich_df_param['field_name']==field_to_enrich]['Unique_Account_Identifer'].to_list()[0]   ,field_to_enrich,log_object,None,None,None,None,None,None,None,None,None,None,None,None,None,None,None,list_of_enabled_accounts_with_fields_to_enrich_on,bearer_token_for_graph_api_requests)
    #List of enriched JSON logs are written to disk
    print("Writing JSON logs out")
    current_timestamp=datetime.datetime(2025,4,11).now().strftime("%Y-%m-%d_%H_%M_%S_%f")
    output_path=return_raw_string(script_config_df[script_config_df['Type']=='Output_Path']['setting_value'].to_list()[0])
    with open(f'{output_path}enriched_JSON_logs_{current_timestamp}.json','w') as file_obj:
        json.dump(obj=list_of_log_objects,fp=file_obj,indent=3)
    print("Output JSON logs written")
