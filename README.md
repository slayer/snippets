# Slayer's snippets

## mysql

GRANT
```
GRANT ALL PRIVILEGES ON *.* TO 'user'@'localhost' IDENTIFIED BY 'pass'; # WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'user'@'%' IDENTIFIED BY 'pass'; # WITH GRANT OPTION;
FLUSH PRIVILEGES;
```

dump
```
mysqldump -u USER -pPASSWORD DATABASE > /path/to/file/dump.sql

# schema only
mysqldump --no-data - u USER -pPASSWORD DATABASE > /path/to/file/schema.sql

# certain tables only
mysqldump -u USER -pPASSWORD DATABASE TABLE1 TABLE2 TABLE3 > /path/to/file/dump_table.sql
```


## gpg

```
### batch decrypt
echo mypass | gpg --decrypt --batch --passphrase-fd 0 $file

### batch encrypt with niced pbzip
nice ionice -c 3 pbzip2 -p2  | nice gpg -c --batch --passphrase-fd 3 3<(mypass) >$file
```

public / private keys
```
### pub/pri keys cheatsheet
gpg --gen-key
gpg --list-keys
gpg --list-secret-keys

gpg --keyserver pgp.mit.edu --send-keys 2871AA6619415A0E20A52EA398290B7291D02F3A
gpg --armor --output my_backups_02.pub --export my_Backups_02

gpg --import my_backups_02.pub # on remote side
gpg --search-keys --keyserver pgp.mit.edu backups@aytm.com

gpg --encrypt -u backups@aytm.com -r backups@aytm.com FILE
gpg --decrypt FILE.gpg >FILE

gpg --delete-keys ID
gpg --delete-secret-keys ID
gpg --delete-secret-and-public-keys ID

# after import you can get: It is NOT certain that the key belongs to the person named
# in the user ID.  If you *really* know what you are doing. To fix:
gpg --edit-key my_Backups_02 # after type 'edit', and answer '5'
# or use --always-trust
```



## ssh

```
# disable pub key auth:
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no user@host
ssh -o PreferredAuthentications=keyboard-interactive,password -o PubkeyAuthentication=no user@host

# key into env:
SSH_DEPLOY_KEY="`cat id_rsa | sed ':a;N;$!ba;s/ /_/g;s/\n/ /g'`"
# env into key for ssh-add
ssh-add <(echo "$SSH_DEPLOY_KEY" | sed "s/ /\n/g;s/_/ /g")

# remove host key
ssh-keygen -f "/root/.ssh/known_hosts" -R github.com

# manually add fingerprint
ssh-keyscan -t rsa github.com >> ~/.ssh/known_hosts

# Unable to negotiate with legacyhost: no matching key exchange method found. Their offer: diffie-hellman-group1-sha1
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 host

# get pub key from private
ssh-keygen -y -f ~/.ssh/id_rsa

# forward remote 5432 port to localhost:5432 (-nNT: no terminal is needed)
ssh -nNT -L 5432:localhost:5432 remote.host

# expose local port 3000 on remote server as 9000
ssh -R 9000:localhost:3000 remote.host

# run socks5 server on port 1080
ssh -D 1080 remote.host

```

## git

```
git config --global push.default matching

# set default remote for branches
git push -u origin
git push -u origin --all # for all!

```


## aws s3

copy bucket
```
# aws configure # do not forget
aws s3 sync s3://my-bucket-in-eu-west1 s3://my-bucket-in-eu-central1 --source-region=eu-west-1 --region=eu-central-1 --size-only
```

du
```
# aws s3 du
aws s3 ls s3://bucket --region=ca-central-1 --recursive | \
  grep -v -E "(Bucket: |Prefix: |LastWriteTime|^$|--)" | awk 'BEGIN {total=0}{total+=$3}END{print total/1024/1024/1024" GB"}'
```


## sync servers
```
rsync -avz --checksum --delete \
  --exclude /backups \
  --exclude /boot \
  --exclude /etc/network \
  --exclude /proc \
  --exclude /sys \
  --exclude /root \
  --exclude /run \
  old:/ .

# NOTE: do not forget to update /boot/grub/grub.conf for correct kernel version, root device, imagerd, etc
```

## openssl
```
# get site list from https host
true | openssl s_client -showcerts -connect host:443 2>&1 |
    openssl x509 -text | grep -o 'DNS:[^,]*' | cut -f2 -d:
```



## bash

do not display session in `w`
```
  bash -si
```

has prefix?
```
  if [ "${URL#http}" == "${URL}" ]; then
    echo no prefix # wildcard also works
  fi
```

add prefix if needed
```
  [ ${URL%%.sql.bz2.gpg} == ${URL} ] && URL="${URL}.sql.bz2.gpg"
```

stdout redirection
```
exec 6>&1           # Link file descriptor #6 with stdout.Saves stdout.
exec > logfile.txt
echo "ok"
exec 1>&6 6>&-      # Restore stdout and close file descriptor #6.

exec 4<&0
exec < $1            # Will read from input file.
# some code
exec 7>&1
exec > $2            # Will write to output file.  Assumes output file writable
```

read file
```
exec 3<> myfile.txt
while read line <&3
do {
  echo "$line"
  (( Lines++ ));                   #  Incremented values of this variable
                                   #+ accessible outside loop. No subshell, no problem.
}
done
exec 3>&-
```



## xkb capslock delay fix (?)
```
  /usr/share/X11/xkb/symbols/capslock:
  replace key <CAPS> {        repeat=no, [ ISO_Next_Group, Caps_Lock ] };
```

## apache2

rewrite if not ip
```
RewriteCond %{REMOTE_ADDR}       !^98\.3\.2\.1
RewriteRule ^.*$ /system/maintenance.html [L]
```

rewrite if file exists
```
RewriteCond %{DOCUMENT_ROOT}/system/maintenance.html -f
RewriteCond %{SCRIPT_FILENAME} !maintenance.html
RewriteRule ^.*$ /system/maintenance.html [L]
```


## simple http server

```
python -m SimpleHTTPServer 1337 &
```

## update kernel
```
update-grub
grub-set-default vmlinuz-4.4.0-66-generic
```


## ecrypt fs
mount manually
```
ecryptfs-mount-private
```

migrate home (encrypt)
```
sudo ecryptfs-migrate-home -u user
```


## openvpn
### to systemd
conf file: `/etc/openvpn/client.conf`
```
systemctl enable openvpn@client
systemctl start openvpn@client
systemctl status openvpn@client
```


## ufw
```
ufw allow www/tcp
ufw allow from 91.207.249.7/32 to any port www
ufw allow in on eth1 from any to any port www
ufw allow in on eth1 from any to any proto tcp port 22

ufw allow in on docker+
ufw allow in on docker+ from any to any
ufw allow in on tun+ from any

```
ufw+docker: https://svenv.nl/unixandlinux/dockerufw


## nginx
cut url prefix
```
  location /web {
    rewrite ^/web/(.*) /$1  break;
    proxy_pass http://127.0.0.1:8083/$uri$is_args$args;
  }
```

## sed

extract user_id=1212
```
sed 's/.* \(user_id=[0-9]\+\).*/\1/'
```


## docker
save all images
```
docker images --format='{{.ID}}' | while read i; do docker save "$i" > "${i}.tar.gz"; done
```

restore images
```
ls *.tar.gz | xargs -n1 docker load -i
```


## Go
### pprof
```
go tool pprof -inuse_space ./binary http://host:1323/debug/pprof/heap
```


## mdadm

```
cat /proc/mdstat  # show status of all raids
mdadm --detail /dev/md0 # detailed status of raid md0
mdadm --create /dev/md0 -n2 -l1 /dev/sda1 /dev/sdb1 # new raid /dev/md0 with 2 disks, raid level 1 on /dev/sda1 and /dev/sda2
mdadm --fail /dev/md0 /dev/sda1 ; mdadm --remove /dev/md0 /dev/sda1 # remove /dev/sda1 from /dev/md0
mdadm --add /dev/md0 /dev/sda1 # add /dev/sda1 to /dev/md0
```


## misc
shift+numpad keys = home/end like in windows
```
/etc/default/keyboard : XKBOPTIONS="numpad:microsoft" ?
```

