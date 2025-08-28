import sys
import pandas as pd
import json
import re

PII_PATTERNS = {
    'phone': re.compile(r'\b\d{10}\b'),
    'aadhar': re.compile(r'\b\d{12}\b'),
    'passport': re.compile(r'\b[A-Z]\d{7}\b'),
    'upi_id': re.compile(r'[\w.-]+@[\w.-]+') # A broad regex for UPI/Email
}

COMBINATORIAL_KEYS = [
    'name', 'email', 'address', 'ip_address', 'device_id'
]

def mask_string(value: str) -> str:
    """Masks a string, showing the first and last characters."""
    if len(value) < 4:
        return "**"
    # For full names, mask each part
    parts = value.split()
    masked_parts = [p[0] + 'X' * (len(p) - 2) + p[-1] if len(p) > 2 else '*' for p in parts]
    return " ".join(masked_parts)

def mask_number(value: str, visible_digits=4) -> str:
    """Masks a numerical string, leaving a few digits visible at the end."""
    if len(value) <= visible_digits:
        return 'X' * len(value)
    return 'X' * (len(value) - visible_digits) + value[-visible_digits:]
    
def mask_email_or_upi(value: str) -> str:
    """Masks an email or UPI ID."""
    if '@' in value:
        user, domain = value.split('@', 1)
        masked_user = user[0] + '' * (len(user) - 2) + user[-1] if len(user) > 2 else '**'
        return f"{masked_user}@{domain}"
    return mask_string(value)

def detect_and_redact_pii(data_json: str) -> (str, bool):
    """
    Analyzes a JSON string to detect and redact PII.

    Args:
        data_json (str): The input JSON string from the CSV.

    Returns:
        tuple: A tuple containing the redacted JSON string and a boolean indicating if PII was found.
    """
    try:
        data = json.loads(data_json)
    except json.JSONDecodeError:
        return data_json, False

    redacted_data = data.copy()
    is_pii_found = False
    
    for key, value in data.items():
        if isinstance(value, str):
            if key in PII_PATTERNS and PII_PATTERNS[key].fullmatch(value):
                is_pii_found = True
                if key == 'phone' or key == 'aadhar':
                    redacted_data[key] = mask_number(value)
                elif key == 'passport':
                    redacted_data[key] = mask_string(value)
                elif key == 'upi_id':
                    # UPI can also match email, so we handle it here
                    redacted_data[key] = mask_email_or_upi(value)

    present_combinatorial_keys = []
    for key, value in data.items():
        if key in COMBINATORIAL_KEYS:
            # Basic validation to avoid flagging empty values or single names
            if key == 'name' and len(str(value).split()) < 2:
                continue # Skip if it's not a full name
            if value: # Ensure value is not empty
                 present_combinatorial_keys.append(key)

    if len(present_combinatorial_keys) >= 2:
        is_pii_found = True
        for key in present_combinatorial_keys:
            value = str(redacted_data[key])
            if key == 'name' or key == 'address':
                redacted_data[key] = mask_string(value)
            elif key == 'email':
                redacted_data[key] = mask_email_or_upi(value)
            else: # For ip_address, device_id etc.
                redacted_data[key] = "[REDACTED]"

    return json.dumps(redacted_data), is_pii_found


def main(input_file_path):
    """Main function to process the CSV file."""
    try:
        df = pd.read_csv(input_file_path)
    except FileNotFoundError:
        print(f"Error: The file '{input_file_path}' was not found.")
        sys.exit(1)

    results = []
    for index, row in df.iterrows():
        record_id = row['record_id']
        data_json = row['data_json']
        
        redacted_json, is_pii = detect_and_redact_pii(data_json)
        
        results.append({
            'record_id': record_id,
            'redacted_data_json': redacted_json,
            'is_pii': is_pii
        })

    output_df = pd.DataFrame(results)
    output_file = 'redacted_output_Pagilla_Siddhartha_Reddy.csv'
    output_df.to_csv(output_file, index=False)
    print(f"Processing complete. Output saved to '{output_file}'.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 redaction.py <path_to_input_csv>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    main(input_file)
