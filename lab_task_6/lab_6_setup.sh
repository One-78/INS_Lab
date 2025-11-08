#!/bin/bash


echo "=========================================="
echo "Lab 6: Apache Authentication Setup Script"
echo "=========================================="

# Variables
CA_DIR="$HOME/ca_lab"
APACHE_CONF="/etc/httpd/conf"
HTPASSWD_FILE="$APACHE_CONF/.htpasswd"

# Function to check status
check_status() {
    if [ $? -eq 0 ]; then
        echo "[SUCCESS] $1"
    else
        echo "[FAILED] $1"
        echo "Press Enter to continue or Ctrl+C to exit..."
        read
    fi
}

# Check if Apache is running
echo ""
echo "Checking Apache status..."
if ! systemctl is-active --quiet httpd; then
    echo "Apache is not running. Starting Apache..."
    sudo systemctl start httpd
    check_status "Apache started"
fi

#########################################
# TASK 1: HTTP to HTTPS Redirection
#########################################

echo ""
echo "=========================================="
echo "TASK 1: HTTP to HTTPS Redirection"
echo "=========================================="

echo ""
echo "Step 1: Enabling mod_rewrite module..."
if grep -q "LoadModule rewrite_module" /etc/httpd/conf/httpd.conf; then
    echo "mod_rewrite already enabled"
else
    echo "LoadModule rewrite_module modules/mod_rewrite.so" | sudo tee -a /etc/httpd/conf/httpd.conf > /dev/null
    check_status "mod_rewrite enabled"
fi

echo ""
echo "Step 2: Updating example.com configuration for HTTP to HTTPS redirect..."

sudo cp /etc/httpd/conf/extra/example.com.conf /etc/httpd/conf/extra/example.com.conf.task1.backup

sudo tee /etc/httpd/conf/extra/example.com.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /srv/http/example.com/html
    ErrorLog /var/log/httpd/example.com_error.log
    CustomLog /var/log/httpd/example.com_access.log combined

    RewriteEngine On
    RewriteCond %{HTTPS} !=on
    RewriteRule ^/?(.*)$ https://%{SERVER_NAME}/\$1 [R,L]
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
check_status "example.com configuration updated with redirect"

echo ""
echo "Step 3: Testing Apache configuration..."
sudo apachectl configtest 2>&1
check_status "Apache configuration test"

echo ""
echo "Step 4: Restarting Apache..."
sudo systemctl restart httpd
check_status "Apache restarted"

echo ""
echo "TASK 1 COMPLETE!"
echo "Visit http://example.com - it should redirect to https://example.com"
echo "Press Enter to continue to Task 2..."
read

#########################################
# TASK 2: Basic Authentication with .htpasswd
#########################################

echo ""
echo "=========================================="
echo "TASK 2: Basic Authentication"
echo "=========================================="

echo ""
echo "Step 1: Creating users with htpasswd..."

sudo htpasswd -bc $HTPASSWD_FILE saikat saikat123
check_status "First user 'saikat' created"

sudo htpasswd -b $HTPASSWD_FILE arpita arpita123
check_status "Second user 'arpita' created"

echo ""
echo "Step 2: Displaying .htpasswd contents..."
echo "Contents of $HTPASSWD_FILE:"
sudo cat $HTPASSWD_FILE
echo ""

echo ""
echo "Step 3: Updating HTTPS configuration with authentication..."

sudo cp /etc/httpd/conf/extra/example.com.conf /etc/httpd/conf/extra/example.com.conf.task2.backup

sudo tee /etc/httpd/conf/extra/example.com.conf > /dev/null <<EOF
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /srv/http/example.com/html
    ErrorLog /var/log/httpd/example.com_error.log
    CustomLog /var/log/httpd/example.com_access.log combined

    RewriteEngine On
    RewriteCond %{HTTPS} !=on
    RewriteRule ^/?(.*)$ https://%{SERVER_NAME}/\$1 [R,L]
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

    <Directory "/srv/http/example.com/html">
        AuthType Basic
        AuthName "Restricted Content"
        AuthUserFile $HTPASSWD_FILE
        Require valid-user
    </Directory>
</VirtualHost>
EOF
check_status "example.com configuration updated with authentication"

echo ""
echo "Step 4: Restarting Apache..."
sudo systemctl restart httpd
check_status "Apache restarted"

echo ""
echo "TASK 2 COMPLETE!"
echo "Visit https://example.com"
echo "Login credentials:"
echo "  Username: saikat, Password: saikat123"
echo "  Username: arpita, Password: arpita123"
echo "Press Enter to continue to Task 3..."
read

#########################################
# TASK 3: MySQL Database Authentication
#########################################

echo ""
echo "=========================================="
echo "TASK 3: MySQL Authentication"
echo "=========================================="

echo ""
echo "Step 1: Installing MySQL/MariaDB..."
if ! command -v mysql &> /dev/null; then
    echo "Installing MariaDB..."
    sudo pacman -S mariadb --noconfirm
    check_status "MariaDB installation"

    echo "Initializing MariaDB..."
    sudo mysql_install_db --user=mysql --basedir=/usr --datadir=/var/lib/mysql
    check_status "MariaDB initialization"
else
    echo "MySQL/MariaDB already installed"
fi

echo ""
echo "Starting MariaDB service..."
sudo systemctl start mysqld
sudo systemctl enable mysqld
check_status "MariaDB service started"

sleep 2

echo ""
echo "Step 2: Setting up MySQL root password..."
sudo mysqladmin -u root password 'cse' 2>/dev/null || echo "Root password already set"

echo ""
echo "Step 3: Checking MySQL service status..."
sudo systemctl status mysqld --no-pager | head -n 10

echo ""
echo "Step 4-7: Creating database and table..."

sudo mysql -u root -pcse 2>/dev/null <<EOF || sudo mysql -u root <<EOF
DROP DATABASE IF EXISTS apache;
CREATE DATABASE apache;
USE apache;
CREATE TABLE users (
    username VARCHAR(30) PRIMARY KEY,
    password VARCHAR(512) NOT NULL
);
EOF
check_status "Database and table created"

echo ""
echo "Step 8: Adding users to MySQL database..."

SAIKAT_HASH=$(htpasswd -bns saikat saikat123 | cut -d: -f2)
ARPITA_HASH=$(htpasswd -bns arpita arpita123 | cut -d: -f2)

echo "Saikat hash: $SAIKAT_HASH"
echo "Arpita hash: $ARPITA_HASH"

sudo mysql -u root -pcse apache 2>/dev/null <<EOF || sudo mysql -u root apache <<EOF
INSERT INTO users VALUES ('saikat', '$SAIKAT_HASH');
INSERT INTO users VALUES ('arpita', '$ARPITA_HASH');
SELECT * FROM users;
EOF
check_status "Users added to MySQL database"

echo ""
echo "Step 9: Installing Apache MySQL module..."
if ! pacman -Qq apr-util 2>/dev/null; then
    sudo pacman -S apr-util --noconfirm
    check_status "apr-util installed"
fi

echo ""
echo "Enabling required Apache modules..."

MODULES=(
    "dbd"
    "authn_dbd"
    "socache_shmcb"
    "authn_socache"
)

for module in "${MODULES[@]}"; do
    if ! grep -q "LoadModule ${module}_module" /etc/httpd/conf/httpd.conf; then
        echo "LoadModule ${module}_module modules/mod_${module}.so" | sudo tee -a /etc/httpd/conf/httpd.conf > /dev/null
        check_status "$module module enabled"
    else
        echo "$module module already enabled"
    fi
done

echo ""
echo "Step 10: Updating configuration with MySQL authentication..."

sudo cp /etc/httpd/conf/extra/example.com.conf /etc/httpd/conf/extra/example.com.conf.task3.backup

sudo tee /etc/httpd/conf/extra/example.com.conf > /dev/null <<'EOF'
<VirtualHost *:80>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /srv/http/example.com/html
    ErrorLog /var/log/httpd/example.com_error.log
    CustomLog /var/log/httpd/example.com_access.log combined

    RewriteEngine On
    RewriteCond %{HTTPS} !=on
    RewriteRule ^/?(.*)$ https://%{SERVER_NAME}/$1 [R,L]
</VirtualHost>

<VirtualHost *:443>
    ServerName example.com
    ServerAlias www.example.com
    DocumentRoot /srv/http/example.com/html
    ErrorLog /var/log/httpd/example.com_ssl_error.log
    CustomLog /var/log/httpd/example.com_ssl_access.log combined

    SSLEngine on
EOF

echo "    SSLCertificateFile $CA_DIR/server.crt" | sudo tee -a /etc/httpd/conf/extra/example.com.conf > /dev/null
echo "    SSLCertificateKeyFile $CA_DIR/server_nopass.key" | sudo tee -a /etc/httpd/conf/extra/example.com.conf > /dev/null

sudo tee -a /etc/httpd/conf/extra/example.com.conf > /dev/null <<'EOF'

    DBDriver mysql
    DBDParams "host=localhost dbname=apache user=root pass=cse"
    DBDMin 4
    DBDKeep 8
    DBDMax 20
    DBDExptime 300

    <Directory "/srv/http/example.com/html">
        AuthType Basic
        AuthName "My Server"
        AuthBasicProvider socache dbd
        AuthnCacheProvideFor dbd
        AuthnCacheContext my-server
        Require valid-user
        AuthDBDUserPWQuery "SELECT password FROM users WHERE username = %s"
    </Directory>
</VirtualHost>
EOF
check_status "example.com configuration updated with MySQL authentication"

echo ""
echo "Step 11: Testing Apache configuration..."
sudo apachectl configtest 2>&1
check_status "Apache configuration test"

echo ""
echo "Restarting Apache..."
sudo systemctl restart httpd
check_status "Apache restarted"

echo ""
echo "=========================================="
echo "LAB 6 COMPLETE!"
echo "=========================================="
echo ""
echo "TASK 1: HTTP to HTTPS Redirection"
echo "- Visit http://example.com (should redirect to HTTPS)"
echo ""
echo "TASK 2: Basic Authentication (.htpasswd)"
echo "- Configuration backed up as: example.com.conf.task2.backup"
echo ""
echo "TASK 3: MySQL Authentication (CURRENT)"
echo "- Visit https://example.com"
echo "- Login with MySQL credentials:"
echo "    Username: saikat, Password: saikat123"
echo "    Username: arpita, Password: arpita123"
echo ""
echo "MySQL Database: apache"
echo "MySQL Root Password: cse"
echo ""
echo "To view MySQL users:"
echo "  sudo mysql -u root -pcse apache -e 'SELECT * FROM users;'"
echo ""
echo "To switch between authentication methods:"
echo "  Task 2 (htpasswd): sudo cp /etc/httpd/conf/extra/example.com.conf.task2.backup /etc/httpd/conf/extra/example.com.conf"
echo "  Task 3 (MySQL):    sudo cp /etc/httpd/conf/extra/example.com.conf.task3.backup /etc/httpd/conf/extra/example.com.conf"
echo "  Then: sudo systemctl restart httpd"
echo ""
