# Testbed

## Objective
This testbed is used to check if a web browser supports the downgrade protection mechanism defined in RFC 8446.

## How to Use
1. Build the applications including the test TLS 1.3 server and the adversary by typing `make'

1. Set the DNS mapping between `www.alice.com' and the host address (e.g., 127.0.0.1) in the host file (e.g., /etc/hosts)

1. Insert the ca.pem file in the www.alice.com directory into a web browser's trusted certificate store

1. Run the test server with the port (e.g., 5001)

1. Run the active adversary with its own listening port (e.g., 5002) and the server's port (e.g., 5001)

1. Type the address https://www.alice.com:5002 on a web browser and press Enter to send the message

1. Find the warning message on the web browser or the alert message received at the server. If it is the `illegal parameter' warning/alert message, your web browser understands the downgrade sentinels in ServerHello. Otherwise, it does not.
