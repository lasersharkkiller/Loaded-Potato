import os
from sigma.collection import SigmaCollection
from sigma.backends.sentinelone import SentinelOneBackend
# If you are using PowerQuery (PQ), use this import instead:
# from sigma.backends.sentinelone_pq import SentinelOnePQBackend

def convert_sigma_to_s1(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File not found at {file_path}")
        return

    # 1. Load the Sigma rule(s)
    # SigmaCollection.from_yaml allows loading a single file or a directory string
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            rules = SigmaCollection.from_yaml(f.read())
    except Exception as e:
        print(f"Error loading YAML: {e}")
        return

    # 2. Initialize the SentinelOne Backend
    # This controls how the logic is translated (Deep Visibility syntax)
    backend = SentinelOneBackend()
    
    # If using PowerQuery:
    # backend = SentinelOnePQBackend()

    # 3. Convert the rules
    # The convert() method returns a list of query strings (one per rule/detection)
    queries = backend.convert(rules)

    # 4. Output the results
    print(f"--- Converted {len(queries)} query/queries from {os.path.basename(file_path)} ---")
    for idx, query in enumerate(queries):
        print(f"\nQuery #{idx + 1}:")
        print(query)

if __name__ == "__main__":
    # REPLACE THIS with the path to your sigma rule
    my_rule_path = r"C:\Users\ipn2\Desktop\Equifax stuff\S1\Know Normal\detections\sigma\A Member Was Added to a Security-Enabled Global Group.yml" 
    
    convert_sigma_to_s1(my_rule_path)