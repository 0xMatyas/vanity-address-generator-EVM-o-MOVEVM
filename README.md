# Vanity Address Generator

This project generates Ethereum or Move addresses with a specified prefix using multiple processes.

## Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/vanity-address-generator.git
   cd vanity-address-generator   ```

2. **Install dependencies:**

   Ensure you have Python 3.x installed. You may need to install the following packages:
   ```bash
   pip install eth-keys eth-utils   ```

3. **Run the script:**
   ```bash
   python3 vanityaddy.py   ```

4. **Follow the prompts:**

   - Choose the chain type (EVM or Move).
   - Enter the desired prefix.
   - Decide if the search should be case-sensitive.

## Notes

- The `verified_addresses.txt` file is ignored by Git to prevent accidental sharing of private keys.
- Ensure your system has enough CPU resources for optimal performance.

## License

This project is licensed under the MIT License. 