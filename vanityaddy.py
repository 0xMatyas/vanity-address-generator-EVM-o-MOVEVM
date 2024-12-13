import os
import time
import hashlib
from eth_keys import keys
from eth_utils import to_checksum_address
import multiprocessing as mp
from concurrent.futures import ProcessPoolExecutor
import sys

def generate_move_address(private_key_bytes):
    """Generate a Move address from private key bytes."""
    public_key = keys.PrivateKey(private_key_bytes).public_key
    sha3_hash = hashlib.sha3_256(bytes.fromhex(str(public_key)[2:])).hexdigest()
    return "0x" + sha3_hash  # Return full 64 characters

def verify_address_cryptographically(address, private_key, chain_type):
    """Verify that the private key correctly derives to the address"""
    try:
        if chain_type == "evm":
            # Derive address from private key
            derived_public_key = private_key.public_key
            derived_address = to_checksum_address(derived_public_key.to_address())
            
            # Check if derived address matches
            if derived_address.lower() != address.lower():
                return False, "Private key does not derive to this address"
            
            # Verify checksum
            if not address.startswith("0x"):
                return False, "Invalid address format (must start with 0x)"
            
            # Additional EVM-specific checks
            if len(address[2:]) != 40:
                return False, "Invalid EVM address length"
                
        else:  # move
            # Derive Move address from private key
            derived_address = generate_move_address(private_key.to_bytes())
            
            if derived_address.lower() != address.lower():
                return False, "Private key does not derive to this address"
            
            # Move-specific checks
            if len(address[2:]) != 64:
                return False, "Invalid Move address length"
        
        return True, "✅ Address is cryptographically valid"
        
    except Exception as e:
        return False, f"Verification failed: {str(e)}"

def validate_prefix(prefix):
    """
    Validate and format the prefix input.
    Returns (formatted_prefix, error_message, case_sensitive)
    """
    # Remove any whitespace but preserve case
    prefix = prefix.strip()
    
    # Add 0x if not present
    if not prefix.startswith('0x'):
        prefix = '0x' + prefix
    
    # Check for valid hex characters after 0x
    valid_chars = set('0123456789abcdefABCDEF')
    invalid_chars = []
    for char in prefix[2:]:
        if char not in valid_chars:
            invalid_chars.append(char)
    
    if invalid_chars:
        unique_invalid = set(invalid_chars)
        return None, (
            f"Invalid characters found: {', '.join(unique_invalid)}\n"
            f"Allowed characters are:\n"
            f"- Numbers: 0-9\n"
            f"- Letters: a-f or A-F\n\n"
            f"Note: EVM addresses use checksummed format where case matters."
        ), False
    
    return prefix, None, True  # Always return True for case_sensitive

def worker(prefix, chain_type, postfix=None, batch_size=1000, case_sensitive=False):
    """Worker function to generate and check addresses in batches"""
    for _ in range(batch_size):
        private_key_bytes = os.urandom(32)
        if chain_type == "evm":
            private_key = keys.PrivateKey(private_key_bytes)
            public_key = private_key.public_key
            address = to_checksum_address(public_key.to_address())
            
            # Check both prefix and postfix if specified
            matches_prefix = (address.startswith(prefix) if case_sensitive 
                            else address.lower().startswith(prefix.lower()))
            matches_postfix = True
            if postfix:
                matches_postfix = (address.endswith(postfix) if case_sensitive 
                                 else address.lower().endswith(postfix.lower()))
                
            if matches_prefix and matches_postfix:
                return address, private_key
        else:  # move
            address = generate_move_address(private_key_bytes)
            private_key = keys.PrivateKey(private_key_bytes)
            if (address.lower().startswith(prefix.lower()) and 
                (not postfix or address.lower().endswith(postfix.lower()))):
                return address, private_key
    return None

def calculate_estimated_time(prefix, rate, postfix=None, case_sensitive=False):
    """Calculate estimated time based on prefix/postfix length and current rate"""
    if not prefix.startswith('0x'):
        prefix = '0x' + prefix
    
    # Calculate total search space based on both prefix and postfix
    prefix_length = len(prefix[2:]) if prefix != "0x" else 0
    postfix_length = len(postfix) if postfix else 0
    total_pattern_length = prefix_length + postfix_length
    
    # Base probability calculation
    # For n characters, probability is 1/(16^n)
    attempts_needed = 16 ** total_pattern_length
    
    # For case-sensitive search in EVM addresses
    if case_sensitive:
        letter_count = 0
        if prefix != "0x":
            letter_count += sum(1 for c in prefix[2:] if c.lower() in 'abcdef')
        if postfix:
            letter_count += sum(1 for c in postfix if c.lower() in 'abcdef')
        # Multiply by 2^letter_count for case combinations
        attempts_needed *= (2 ** letter_count)
    
    # Divide by 2 for average case
    attempts_needed /= 2
    
    # Calculate estimated seconds
    estimated_seconds = attempts_needed / rate if rate > 0 else float('inf')
    
    # Convert to human readable format
    if estimated_seconds < 60:
        return f"{estimated_seconds:.1f} seconds"
    elif estimated_seconds < 3600:
        return f"{estimated_seconds/60:.1f} minutes"
    elif estimated_seconds < 86400:
        return f"{estimated_seconds/3600:.1f} hours"
    elif estimated_seconds < 31536000:  # Less than a year
        return f"{estimated_seconds/86400:.1f} days"
    else:
        return f"{estimated_seconds/31536000:.1f} years"

def format_elapsed_time(seconds):
    """Format elapsed time into appropriate units"""
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} minutes"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.2f} hours"
    else:
        days = seconds / 86400
        return f"{days:.2f} days"

def generate_vanity_address(prefix="0xF", max_attempts=100000000, chain_type="evm", case_sensitive=False, postfix=None):
    """Generate an address with the desired prefix and optional postfix using multiple processes."""
    # Print initial setup information
    print(f"Starting vanity address generation for {chain_type.upper()}...")
    print(f"Using {mp.cpu_count()} CPU cores")
    print(f"Case-sensitive search: {'Yes' if case_sensitive else 'No'}")
    print(f"Expected address length: {'40 characters' if chain_type == 'evm' else '64 characters'}")
    print(f"Maximum attempts set to: {max_attempts:,}")
    
    # Initialize attempt counters and timers
    attempts = 0
    start_time = time.time()
    last_update = start_time
    last_estimate = start_time
    batch_size = 1000
    est_time = "calculating..."
    
    # Calculate number of workers based on CPU cores
    num_workers = mp.cpu_count()

    # Use ProcessPoolExecutor for parallel processing
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = []
        
        while attempts < max_attempts:
            # Submit worker tasks to executor
            futures = [
                executor.submit(worker, prefix, chain_type, postfix, batch_size, case_sensitive)
                for _ in range(num_workers)
            ]
            
            # Check results from futures
            for future in futures:
                result = future.result()
                if result:
                    address, private_key = result
                    elapsed_time = time.time() - start_time
                    print(f"\nMatch found in {attempts:,} attempts and {elapsed_time:.2f} seconds!")
                    return address, private_key
                
                attempts += batch_size
                
                # Update progress every 0.01 seconds
                current_time = time.time()
                if current_time - last_update >= 0.01:
                    rate = attempts / (current_time - start_time)
                    elapsed = current_time - start_time
                    
                    # Update estimated time every 2 seconds
                    if current_time - last_estimate >= 2:
                        est_time = calculate_estimated_time(prefix, rate, postfix, case_sensitive)
                        last_estimate = current_time
                    
                    print(f"\rAttempts: {attempts:,} | Rate: {rate:.2f} addr/sec | Time: {format_elapsed_time(elapsed)} | Est: {est_time}", end='\r')
                    last_update = current_time

    print("\nMax attempts reached. No match found.")
    return None, None

if __name__ == "__main__":
    while True:
        chain_type = input("Choose chain type (evm/move): ").lower()
        if chain_type in ["evm", "move"]:
            break
        print("Invalid choice. Please enter 'evm' or 'move'")

    print("\nAddress format information:")
    if chain_type == "evm":
        print("- EVM addresses use checksum format (mixed case for validation)")
        print("- Example: 0xAb5801a7D398351b8bE11C439e05C5B3259aeC9B")
    else:
        print("- Move addresses are always lowercase")
        print("- Example: 0x1234abcd...")
    
    # Ask for search type first
    while True:
        print("\nWhat would you like to search for?")
        print("1. Prefix (starting characters)")
        print("2. Postfix (ending characters)")
        print("3. Both prefix and postfix")
        search_type = input("Enter your choice (1/2/3): ").strip()
        
        if search_type in ['1', '2', '3']:
            break
        print("Invalid choice. Please enter 1, 2, or 3")

    formatted_prefix = None
    formatted_postfix = None
    
    # Handle prefix input if needed
    if search_type in ['1', '3']:
        while True:
            desired_prefix = input("\nEnter desired prefix (e.g., FACE or 0xFACE): ")
            formatted_prefix, error, _ = validate_prefix(desired_prefix)
            
            if error:
                print(f"\nError: {error}")
                print("Please try again with valid hexadecimal characters.")
                continue
            break
    
    # Handle postfix input if needed
    if search_type in ['2', '3']:
        while True:
            desired_postfix = input("\nEnter desired ending characters (e.g., DEAD): ")
            if desired_postfix.startswith('0x'):
                desired_postfix = desired_postfix[2:]
            formatted_postfix, error, _ = validate_prefix('0x' + desired_postfix)
            if error:
                print(f"\nError: {error}")
                print("Please try again with valid hexadecimal characters.")
                continue
            formatted_postfix = formatted_postfix[2:]  # Remove '0x' from postfix
            break
    
    # Only ask for case sensitivity on EVM addresses
    case_sensitive = False
    if chain_type == "evm":
        while True:
            case_sensitive_input = input("Enable case-sensitive search? (yes/no): ").lower()
            if case_sensitive_input in ['yes', 'no']:
                case_sensitive = case_sensitive_input == 'yes'
                break
            print("Please answer 'yes' or 'no'")
    
    # Display search criteria
    print("\nSearch criteria:")
    if formatted_prefix:
        print(f"- Starting with: {formatted_prefix}")
    if formatted_postfix:
        print(f"- Ending with: {formatted_postfix}")
    if chain_type == "evm" and case_sensitive:
        print("- Case-sensitive search enabled")
    else:
        print("- Case-insensitive search")

    address, private_key = generate_vanity_address(
        prefix=formatted_prefix or "0x", 
        chain_type=chain_type,
        case_sensitive=case_sensitive,
        postfix=formatted_postfix,
        max_attempts=100000000
    )

    if address:
        print(f"\nMatching Address: {address}")
        print(f"Private Key: {private_key}")
        print(f"Address length: {len(address[2:])} characters")
        
        is_valid, message = verify_address_cryptographically(address, private_key, chain_type)
        print(f"\nCryptographic verification: {message}")
        
        if is_valid:
            print("\n✅ Address successfully generated and verified!")
            
            # Ask user if they want to save the address
            while True:
                save = input("\nDo you want to save this address to verified_addresses.txt? (yes/no): ").lower()
                if save in ['yes', 'no']:
                    break
                print("Please answer 'yes' or 'no'")
            
            if save == 'yes':
                with open("verified_addresses.txt", "a") as f:
                    f.write(f"Chain: {chain_type}\n")
                    f.write(f"Address: {address}\n")
                    f.write(f"Private Key: {private_key}\n")
                    f.write(f"Cryptographically verified: Yes\n")
                    f.write("-" * 50 + "\n")
                print("Address saved to verified_addresses.txt")
            else:
                print("Address not saved")
        else:
            print("\n❌ Address failed verification")
    else:
        print("No matching address found.")