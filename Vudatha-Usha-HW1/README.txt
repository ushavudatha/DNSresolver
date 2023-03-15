Language Used - Python

Part A - Mydig tool implementation
Libraries Used:
dnspython
Run Command:
python3 mydigTool.py <website name> <record type>
record type can be A/MX/NS

Example:
python3 mydigTool.py google.com A
output file : mydig_output.txt

Part B - DNSSEC implementation
Libraries used:
dnspython
pycrypto

Run Command:
python3 dnsSEC.py <website name>
Record type - default 'A'

Example:
python3 dnsSEC.py dnssec-failed.org
output file : mydig_output.txt

Part C- Experiments conducted on mydig tool, local DNS server, Google server
output file: PartC+DNSSEC.pdf


