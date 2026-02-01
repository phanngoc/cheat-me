import time
from sitemap_service import SitemapService

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "user": "strix_user",
    "password": "strix_password",
    "dbname": "strix_pentesting"
}

def verify():
    # Wait for DB to be ready if needed
    time.sleep(2) 
    
    service = SitemapService(DB_CONFIG)
    
    print("--- Inserting first URL ---")
    url1 = "https://example.com/api/v1/users"
    service.insert_request(url1, request_id="req_001")
    
    print("--- Inserting overlapping URL ---")
    url2 = "https://example.com/api/v1/products"
    service.insert_request(url2, request_id="req_002")
    
    print("--- Inserting deeper URL ---")
    url3 = "https://example.com/api/v1/users/profile?id=123"
    service.insert_request(url3, request_id="req_003")

    print("\n--- Verifying Sitemap Roots ---")
    roots = service.get_sitemap_tree()
    for root in roots:
        print(f"Root: {root}")
        
        # Expanding first level
        children = service.get_sitemap_tree(root[0])
        for child in children:
            print(f"  Child: {child}")
            
            # Expanding second level
            grand_children = service.get_sitemap_tree(child[0])
            for gc in grand_children:
                print(f"    Grand-child: {gc}")

    service.close()
    print("\nVerification complete!")

if __name__ == "__main__":
    verify()
