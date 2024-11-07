def print_header(title: str):
    print("\n" + "=" * 60)
    print(f"[+] {title}")
    print("=" * 60)

def print_subheader(title: str):
    print("\n" + "-" * 40)
    print(f"[*] {title}")
    print("-" * 40)

def print_debug(message: str):
    print(f"[DEBUG] {message}")

def print_error(message: str):
    print(f"[-] ERROR: {message}")

def print_success(message: str):
    print(f"[+] SUCCESS: {message}")

def print_section(title: str, content: any, indent: int = 0):
    """Helper function to print formatted sections"""
    print("\n" + "=" * 50)
    print(f"{title}:")
    print("-" * 50)
    if isinstance(content, dict):
        for key, value in content.items():
            print(" " * indent + f"{key}: {value}")
    elif isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                for k, v in item.items():
                    print(" " * indent + f"{k}: {v}")
                print("-" * 30)
            else:
                print(" " * indent + str(item))
    else:
        print(" " * indent + str(content))