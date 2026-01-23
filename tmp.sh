# 1. Take ownership of the XAMPP directory
# This allows 'wlampctl' (running as you) to write configs, logs, and lock files.
sudo chown -R $USER:$USER /opt/lampp

# 2. Comment out the default Listen 80 in the main config
# This prevents the permission error for port 80.
sed -i 's/^Listen 80/#Listen 80/' /opt/lampp/etc/httpd.conf

# 3. Comment out the default SSL Listen 443 (Optional but recommended)
# Prevents conflicts if SSL config is included.
sed -i 's/^Listen 443/#Listen 443/' /opt/lampp/etc/extra/httpd-ssl.conf

