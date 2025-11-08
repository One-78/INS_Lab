#!/bin/bash


echo "=================================="
echo "Lab 5: Secure Apache Setup Script"
echo "=================================="

# Variables
CA_DIR="$HOME/ca_lab"
USERNAME=$(whoami)

# Function to check if command succeeded
check_status() {
    if [ $? -eq 0 ]; then
        echo "[SUCCESS] $1"
    else
        echo "[FAILED] $1"
        echo "Press Enter to continue or Ctrl+C to exit..."
        read
    fi
}

# Install Apache if not installed
echo ""
echo "Step 1: Installing Apache..."
if ! command -v httpd &> /dev/null; then
    echo "Apache not found. Installing..."
    sudo pacman -S apache --noconfirm
    check_status "Apache installation"
else
    echo "Apache already installed"
fi

# Start and enable Apache
echo "Starting Apache service..."
sudo systemctl start httpd 2>&1
check_status "Apache service started"

sudo systemctl enable httpd 2>&1
check_status "Apache service enabled"

# Create CA directory structure
echo ""
echo "Step 2: Creating CA directory structure..."
mkdir -p "$CA_DIR"
cd "$CA_DIR"
echo "Current directory: $(pwd)"

mkdir -p demoCA/certs demoCA/crl demoCA/newcerts demoCA/private
touch demoCA/index.txt
echo "1000" > demoCA/serial
check_status "CA directory structure created"

# Copy OpenSSL config
echo ""
echo "Step 3: Copying OpenSSL configuration..."
if [ -f /etc/ssl/openssl.cnf ]; then
    cp /etc/ssl/openssl.cnf .
    check_status "OpenSSL config copied"
else
    echo "[ERROR] OpenSSL config not found at /etc/ssl/openssl.cnf"
    exit 1
fi

# Generate CA certificate
echo ""
echo "Step 4: Generating CA certificate..."
echo "Generating CA with default values..."
openssl req -new -x509 -keyout ca.key -out ca.crt -config openssl.cnf \
    -passout pass:ca123 \
    -subj "/C=BD/ST=Sylhet/L=Sylhet/O=MyCA/OU=IT/CN=MyCA" 2>&1
check_status "CA certificate generated"

echo "CA files created:"
ls -lh ca.key ca.crt

# Generate certificate for example.com
echo ""
echo "Step 5: Generating certificate for example.com..."

echo "Generating private key..."
openssl genrsa -des3 -out server.key -passout pass:example123 1024 2>&1
check_status "Server key generated for example.com"

echo "Generating CSR..."
openssl req -new -key server.key -out server.csr -config openssl.cnf \
    -passin pass:example123 \
    -subj "/C=BD/ST=Sylhet/L=Sylhet/O=Example/OU=IT/CN=example.com" 2>&1
check_status "CSR generated for example.com"

echo "Signing certificate..."
openssl ca -batch -in server.csr -out server.crt -cert ca.crt -keyfile ca.key \
    -config openssl.cnf -passin pass:ca123 2>&1
check_status "Certificate signed for example.com"

# Generate certificate for webserverlab.com
echo ""
echo "Step 6: Generating certificate for webserverlab.com..."

echo "Generating private key..."
openssl genrsa -des3 -out webserver.key -passout pass:webserver123 1024 2>&1
check_status "Server key generated for webserverlab.com"

echo "Generating CSR..."
openssl req -new -key webserver.key -out webserver.csr -config openssl.cnf \
    -passin pass:webserver123 \
    -subj "/C=BD/ST=Sylhet/L=Sylhet/O=WebServerLab/OU=IT/CN=webserverlab.com" 2>&1
check_status "CSR generated for webserverlab.com"

echo "Signing certificate..."
openssl ca -batch -in webserver.csr -out webserver.crt -cert ca.crt -keyfile ca.key \
    -config openssl.cnf -passin pass:ca123 2>&1
check_status "Certificate signed for webserverlab.com"

# Remove password from keys for Apache
echo ""
echo "Step 7: Removing password from private keys..."
openssl rsa -in server.key -out server_nopass.key -passin pass:example123 2>&1
check_status "Password removed from example.com key"

openssl rsa -in webserver.key -out webserver_nopass.key -passin pass:webserver123 2>&1
check_status "Password removed from webserverlab.com key"

# Create web directories
echo ""
echo "Step 8: Creating web directories..."
sudo mkdir -p /srv/http/example.com/html
sudo mkdir -p /srv/http/webserverlab.com/html

echo "<html><body><h1>Example.com - HTTPS Enabled</h1><p>This is a secure connection</p></body></html>" | sudo tee /srv/http/example.com/html/index.html > /dev/null
echo "<html><body><h1>Webserverlab.com - HTTPS Enabled</h1><p>This is a secure connection</p></body></html>" | sudo tee /srv/http/webserverlab.com/html/index.html > /dev/null
check_status "Web directories created"

# Create example.com Apache config
echo ""
echo "Step 9: Creating Apache virtual host configurations..."
sudo tee /etc/httpd/conf/extra/example.com.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /srv/http/example.com/html
    ErrorLog /var/log/httpd/example.com_error.log
    CustomLog /var/log/httpd/example.com_access.log combined
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /srv/http/example.com/html
    ErrorLog /var/log/httpd/example.com_ssl_error.log
    CustomLog /var/log/httpd/example.com_ssl_access.log combined

    SSLEngine on
    SSLCertificateFile $CA_DIR/server.crt
    SSLCertificateKeyFile $CA_DIR/server_nopass.key
</VirtualHost>
EOF
check_status "example.com configuration created"

# Create webserverlab.com Apache config
sudo tee /etc/httpd/conf/extra/webserverlab.com.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerName webserverlab.com
    ServerAlias www.webserverlab.com
    DocumentRoot /srv/http/webserverlab.com/html
    ErrorLog /var/log/httpd/webserverlab.com_error.log
    CustomLog /var/log/httpd/webserverlab.com_access.log combined
</VirtualHost>

<VirtualHost *:443>
    ServerName webserverlab.com
    ServerAlias www.webserverlab.com
    DocumentRoot /srv/http/webserverlab.com/html
    ErrorLog /var/log/httpd/webserverlab.com_ssl_error.log
    CustomLog /var/log/httpd/webserverlab.com_ssl_access.log combined

    SSLEngine on
    SSLCertificateFile $CA_DIR/webserver.crt
    SSLCertificateKeyFile $CA_DIR/webserver_nopass.key
</VirtualHost>
EOF
check_status "webserverlab.com configuration created"

# Backup httpd.conf
echo ""
echo "Step 10: Backing up Apache configuration..."
sudo cp /etc/httpd/conf/httpd.conf /etc/httpd/conf/httpd.conf.backup 2>&1
check_status "Apache configuration backed up"

# Update main Apache config
echo ""
echo "Step 11: Updating main Apache configuration..."

if ! grep -q "LoadModule ssl_module" /etc/httpd/conf/httpd.conf; then
    echo "Adding SSL module configuration..."
    sudo tee -a /etc/httpd/conf/httpd.conf > /dev/null <<EOF

# SSL Configuration
LoadModule ssl_module modules/mod_ssl.so
LoadModule socache_shmcb_module modules/mod_socache_shmcb.so

# Virtual Hosts
Include conf/extra/example.com.conf
Include conf/extra/webserverlab.com.conf
EOF
    check_status "Apache configuration updated"
else
    echo "SSL module already loaded in configuration"
fi

# Update /etc/hosts
echo ""
echo "Step 12: Updating /etc/hosts..."
if ! grep -q "example.com" /etc/hosts; then
    echo "127.0.0.1 example.com www.example.com" | sudo tee -a /etc/hosts > /dev/null
    echo "127.0.0.1 webserverlab.com www.webserverlab.com" | sudo tee -a /etc/hosts > /dev/null
    check_status "/etc/hosts updated"
else
    echo "/etc/hosts already configured"
fi

# Test Apache configuration
echo ""
echo "Step 13: Testing Apache configuration..."
sudo apachectl configtest 2>&1
check_status "Apache configuration test"

# Restart Apache
echo ""
echo "Step 14: Restarting Apache..."
sudo systemctl restart httpd 2>&1
check_status "Apache restarted"

# Check Apache status
echo ""
echo "Step 15: Checking Apache status..."
sudo systemctl status httpd --no-pager | head -n 10

# Print summary
echo ""
echo "=================================="
echo "Setup Complete!"
echo "=================================="
echo ""
echo "Files created in: $CA_DIR"
ls -lh "$CA_DIR"/*.crt "$CA_DIR"/*.key 2>/dev/null
echo ""
echo "CA Certificate: $CA_DIR/ca.crt"
echo "example.com certificate: $CA_DIR/server.crt"
echo "webserverlab.com certificate: $CA_DIR/webserver.crt"
echo ""
echo "PASSWORDS:"
echo "- CA password: ca123"
echo "- example.com key password: example123"
echo "- webserverlab.com key password: webserver123"
echo ""
echo "To import CA certificate in Firefox:"
echo "1. Open Firefox"
echo "2. Go to Settings > Privacy & Security > View Certificates"
echo "3. Click 'Authorities' tab"
echo "4. Click 'Import' and select: $CA_DIR/ca.crt"
echo "5. Check 'Trust this CA to identify websites'"
echo ""
echo "Access websites:"
echo "- http://example.com"
echo "- https://example.com"
echo "- http://webserverlab.com"
echo "- https://webserverlab.com"
echo ""
echo "For OpenSSL test server (Task 2):"
echo "cd $CA_DIR"
echo "cp server_nopass.key server.pem"
echo "cat server.crt >> server.pem"
echo "openssl s_server -cert server.pem -www"
echo "Then access: https://example.com:4433/"
echo ""
echo "Script finished!"
