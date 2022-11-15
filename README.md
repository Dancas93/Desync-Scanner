# Desync-Scanner
A simple tool to detect vulnerabilities described here https://portswigger.net/research/browser-powered-desync-attacks.

# Description
The tool will always make four requests below. Requests 1, 2 and 3 will be under different connections and Request 4 will be under the same connection as Request 3. If the response of Request 4 is the same as Request 1 and different from Request 2 we can safe assume the application is vulnerable.

For more details check the source code.
