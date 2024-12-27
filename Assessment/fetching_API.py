import requests
from pymongo import MongoClient
import time
client = MongoClient("mongodb://localhost:27017/")  
db = client["Mufeeth"]  
collection = db["Vulnerabilities"] 

# API URL
api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
def fetch_total_cve_count():
    """
    Fetch the total count of CVE data available in the NVD API.
    """
    try:
        response = requests.get(api_url)  # Send GET request to API
        if response.status_code == 200:  # Check if request was successful
            total_cves = response.json().get("totalResults", 0)  # Get total count of CVE data
            return total_cves
        else:
            print(f"Error fetching total CVE count. Status code: {response.status_code}")  # Print error message
            return None
    except Exception as e:
        print(f"Error fetching total CVE count: {e}")  # Print error message
        return None

# Function to fetch total count of CVE data stored in MongoDB
def fetch_stored_cve_count():
    """
    Fetch the total count of CVE data stored in MongoDB.
    """
    try:
        stored_count = collection.count_documents({})  # Count documents in MongoDB collection
        return stored_count
    except Exception as e:
        print(f"Error fetching stored CVE count: {e}")  # Print error message
        return None

# Function to fetch CVE data from NVD API
def fetch_cve_data(start_index, results_per_page):
    try:
        response = requests.get(api_url, params={"startIndex": start_index, "resultsPerPage": results_per_page})
        if response.status_code == 200:  # Check if request was successful
            cve_data = response.json().get("vulnerabilities", [])  # Get CVE data from response
            return cve_data
        else:
            print(f"Error fetching CVE data. Status code: {response.status_code}")  # Print error message
            return []
    except Exception as e:
        print(f"Error fetching CVE data: {e}")  # Print error message
        return []

# Data cleansing and de-duplication function
def cleanse_and_deduplicate(cve_data):
    cleaned_data = []
    seen_cve_ids = set()  # Set to track already seen CVE IDs

    for vulnerability in cve_data:
        cve_id = vulnerability.get("cve", {}).get("id")
        if not cve_id or cve_id in seen_cve_ids:
            continue  # Skip if no CVE ID or if already processed
        
        seen_cve_ids.add(cve_id)

        # Cleansing: Ensure fields like 'published', 'lastModified', and 'vulnStatus' exist
        cve = vulnerability.get("cve", {})
        if 'published' not in cve or 'lastModified' not in cve:
            continue  # Skip if essential fields are missing
        
        # Clean date fields (ensure they are in correct format, otherwise skip)
        published = cve.get('published')
        last_modified = cve.get('lastModified')

        if not (published and last_modified):
            continue  # Skip if dates are missing

        # You can add more data cleansing steps depending on your needs here...

        # Append cleaned and validated CVE entry
        cleaned_data.append(vulnerability)

    return cleaned_data

# Function to store CVE data in MongoDB
def store_cve_data(cve_data):
    if cve_data:
        try:
            # Insert each document with CVE ID as the _id field, but first check for duplicates
            for vulnerability in cve_data:
                cve_id = vulnerability.get("cve", {}).get("id")
                if cve_id:
                    vulnerability["_id"] = cve_id

            # Insert only new records (upsert)
            for vulnerability in cve_data:
                cve_id = vulnerability.get("_id")
                if cve_id:
                    existing_record = collection.find_one({"_id": cve_id})
                    if existing_record:
                        print(f"CVE ID {cve_id} already exists. Skipping insertion.")
                    else:
                        collection.insert_one(vulnerability)
                        print(f"Stored CVE {cve_id} in the database.")
        except Exception as e:
            print(f"Error storing data in the database: {e}")  # Print error message

# Function to synchronize CVE data
def synchronize_cve_data():
    start_time = time.time()  # Record start time of synchronization process

    # Fetch total count of CVE data from API
    total_cves_api = fetch_total_cve_count()
    if total_cves_api is None:
        print("Failed to fetch total CVE count from API.")  # Print error message
        return

    # Fetch total count of CVE data stored in MongoDB
    total_cves_mongo = fetch_stored_cve_count()
    if total_cves_mongo is None:
        print("Failed to fetch total stored CVE count from MongoDB.")  # Print error message
        return

    # Check if there are new CVEs to synchronize
    if total_cves_mongo < total_cves_api:
        remaining_cves = total_cves_api - total_cves_mongo  # Calculate number of new CVEs
        print(f"Found {remaining_cves} new CVEs to synchronize.")  # Print message

        max_results_per_page = 2000  # Define maximum batch size for API requests
        num_batches = (remaining_cves + max_results_per_page - 1) // max_results_per_page  # Calculate number of batches

        # Fetch and store CVE data in batches
        for i in range(num_batches):
            start_index = total_cves_mongo + i * max_results_per_page
            current_results_per_page = min(max_results_per_page, remaining_cves - i * max_results_per_page)
            cve_data = fetch_cve_data(start_index, current_results_per_page)
            if cve_data:
                cleaned_data = cleanse_and_deduplicate(cve_data)  # Cleanse and deduplicate
                store_cve_data(cleaned_data)  # Store cleaned data in MongoDB

    else:
        print("Already all data are in the MongoDB.")  # Print message if no new CVEs

    end_time = time.time()  # Record end time of synchronization process
    print(f"CVE data synchronized successfully in {end_time - start_time:.2f} seconds")  # Print execution time

# Call the synchronize_cve_data function to start synchronization process
synchronize_cve_data()
