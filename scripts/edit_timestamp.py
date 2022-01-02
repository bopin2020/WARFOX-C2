import pefile
import sys
import string
from datetime import datetime, timedelta
import random

def main():

    pe = pefile.PE(sys.argv[1])

    print("[+] Files current epoch: {}".format(pe.FILE_HEADER.TimeDateStamp))

    random_subtract_days = random.randint(5, 100)
    thirty_days_ago = int((datetime.now() - timedelta(days=random_subtract_days)).timestamp())

    print("[+] Random days subtraction: {}".format(random_subtract_days))
    print("[+] New date to set: {}".format(thirty_days_ago))

    pe.FILE_HEADER.TimeDateStamp = thirty_days_ago
    
    random_name = "".join(random.choices(string.ascii_uppercase + string.digits + string.ascii_lowercase, k=10))
    print("[+] Outputted PE: {}".format(random_name))
    
    pe.write(random_name + ".dll")
    
    
if __name__ == "__main__":
    main()