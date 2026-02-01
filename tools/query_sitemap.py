from sitemap_service import SitemapService

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "user": "strix_user",
    "password": "strix_password",
    "dbname": "strix_pentesting"
}

def print_tree(service, parent_id=None, level=0):
    nodes = service.get_sitemap_tree(parent_id)
    for node in nodes:
        node_id, kind, label, has_descendants = node
        indent = "  " * level
        print(f"{indent}[{kind}] {label}")
        if has_descendants:
            print_tree(service, node_id, level + 1)

def main():
    service = SitemapService(DB_CONFIG)
    print("--- Current Sitemap Hierarchy ---")
    print_tree(service)
    service.close()

if __name__ == "__main__":
    main()
