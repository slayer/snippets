> # slayer's snippets

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
gpg --full-gen-key
gpg --list-keys
gpg --list-secret-keys

# send pub key to remote server
gpg --keyserver pgp.mit.edu --send-keys 2871AA6619415A0E20A52EA398290B7291D02F3A
# export pub key
gpg --armor --output my_backups_02.pub --export my_Backups_02

# import pub key
gpg --import my_backups_02.pub # on remote side
gpg --search-keys --keyserver pgp.mit.edu name@aaa.com
gpg --keyserver keyserver.ubuntu.com --recv 2871AA6619415A0E20A52EA398290B7291D02F3A

# encrypt/decrypt file
gpg --encrypt-files -r name@aaa.com FILE
gpg --decrypt-files FILE.gpg

# delete
gpg --delete-keys ID
gpg --delete-secret-keys ID
gpg --delete-secret-and-public-keys ID

# after import you can get: It is NOT certain that the key belongs to the person named
# in the user ID.  If you *really* know what you are doing. To fix:
gpg --edit-key my_Backups_02 # after type 'trust', and answer '5'
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

cancel merge:
```
git reset --hard HEAD
# or
# git reset --hard ORIG_HEAD
```

set default protocol
```
git config --global url."git@github.com:".insteadOf "https://github.com/"
```


## gitlab
status:
```
gitlab-ctl status
```

stop/start/restart:
```
gitlab-ctl stop
gitlab-ctl start
gitlab-ctl restart
```

checks:
```
gitlab-rake gitlab:check
```

reconfigure:
```
sudo gitlab-ctl reconfigure
```

registry garbage collect
```
gitlab-ctl registry-garbage-collect
```

## AWS S3

copy bucket
```
# aws configure # do not forget
aws s3 sync s3://my-bucket-in-eu-west1 s3://my-bucket-in-eu-central1 --source-region=eu-west-1 --region=eu-central-1 --size-only
  # --acl public-read
```

copy by wildcard
```
aws s3 cp s3://bucket/folder/ . --recursive --exclude="*" --include="2017-12-20*"
```

sync (with public-read):

```
aws s3 sync . s3://bucket.bla.com/images/ --acl public-read
```

du
```
# aws s3 du
aws s3 ls s3://bucket --region=ca-central-1 --recursive | \
  grep -v -E "(Bucket: |Prefix: |LastWriteTime|^$|--)" | awk 'BEGIN {total=0}{total+=$3}END{print total/1024/1024/1024" GB"}'
```

set meta (acl, cache-control header)
```
aws s3 cp s3://static.site.com/images/ s3://static.site.com/images/ \
  --recursive --metadata-directive REPLACE --acl public-read --cache-control max-age=2592000,public

# only png+jpg
aws s3 cp s3://static.site.com/images/ s3://static.site.com/images/ --exclude "*" \
    --include "*.jpg" --include "*.png" \
    --recursive --metadata-directive REPLACE --expires 2022-01-01T00:00:00Z --acl public-read \
    --cache-control max-age=2592000,public

```


## rsync
### sync servers
```
rsync -avz --checksum  --delete --progress --human-readable \
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

### parallel rsync:
(untested)
first run with --dry-run:
`rsync -avzm --stats --safe-links --ignore-existing --dry-run --human-readable /data/projects REMOTE-HOST:/data/ > /tmp/transfer.log`

second:
`cat /tmp/transfer.log | parallel --will-cite -j 5 rsync -avzm --relative --stats --safe-links --ignore-existing --human-readable {} REMOTE-HOST:/data/ > result.log`


## openssl
get site list from https host
```
true | openssl s_client -showcerts -connect host:443 2>&1 |
    openssl x509 -text | grep -o 'DNS:[^,]*' | cut -f2 -d:

# full info
openssl s_client -connect 1.1.1.1:443  -msg
```

dump cert:
```
openssl x509 -text -noout -in cert.pem
```



## nmap

list ciphers
`nmap --script ssl-enum-ciphers -p 443 www.example.com`

`sslscan`  works too!



## bash

do not display session in `w`
```
bash -si
```

### vars and patterns

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

Remove the spaces from the variable using the pattern replacement parameter expansion:
```
[[ -z "${param// }" ]]
```
${parameter/pattern/string}

The pattern is expanded to produce a pattern just as in filename expansion.
Parameter is expanded and the longest match of pattern against its value is replaced with string.
If pattern begins with `/`, all matches of pattern are replaced with string.


Test whether the string contains some character other than space:
```
if [[ $param = *[!\ ]* ]]; then
  echo "\$param contains characters other than space"
else
  echo "\$param consists of spaces only"
fi
```

to test for space, tab or newline
```
[[ $param = *[$' \t\n']* ]]
```

set unless already set
```
: ${USERID:=33}
```

bell
```
echo -ne '\007'
```

### Redirections

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

append:
```
exec >>$LOG_FILE 2>&1
```

extended usage:
```
# Close STDOUT file descriptor
exec 1<&-
# Close STDERR FD
exec 2<&-

# Open STDOUT as $LOG_FILE file for read and write.
exec 1<>$LOG_FILE

# Redirect STDERR to STDOUT
exec 2>&1

echo "This line will appear in $LOG_FILE, not 'on screen'"
```

Redirect as "file"
```
vi <(ps ax)
```

## xkb capslock delay fix (?)
```
/usr/share/X11/xkb/symbols/capslock:
replace key <CAPS> {        repeat=no, [ ISO_Next_Group, Caps_Lock ] };
```

## x11

### paste by command
```
xdotool keydown Control key V keyup Control
```

### input devices
```
# list
xinput --list
# list props
xinput --list-props 'FocalTechPS/2 FocalTech Touchpad'
# set prop
xinput --set-prop 'FocalTechPS/2 FocalTech Touchpad' 'Device Enabled' 0
```



### find window
`xwininfo`
`xwininfo -root -tree`

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

## systemd
remove service
```
systemctl stop [servicename]
systemctl disable [servicename]
rm /etc/systemd/system/[servicename]
rm /etc/systemd/system/[servicename] symlinks that might be related
systemctl daemon-reload
systemctl reset-failed
```


## openvpn
### add ovpn config to to systemd
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

ufw allow in on vmbr0
ufw allow in on docker+
ufw allow in on docker+ from any to any
ufw allow in on tun+ from any

ufw allow in on eth1 from any to any proto udp port 1197 comment "openvpn s1-s2"

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
aliases
```
alias docker-rm-unused-images='docker images --filter "dangling=true" -q --no-trunc | xargs --no-run-if-empty docker rmi'
alias docker-rm-unused-volumes='docker volume rm $(docker volume ls -qf dangling=true)'
alias docker-rm-stopped-containers='docker ps --filter "status=exited" -q --no-trunc | xargs --no-run-if-empty docker rm'
```

some prune commands
```
docker image prune -a
docker system prune -a
docker image prune -af --filter "until=$(($(date +%s)-10*24*3600))" # 10 days
docker images | egrep " (weeks|months)" | awk '{print $3}' | uniq | xargs -r -n1 docker rmi

```

save all images
```
docker images --format='{{.ID}}' | while read i; do docker save "$i" > "${i}.tar.gz"; done
```

restore images
```
ls *.tar.gz | xargs -n1 docker load -i
```

get ips
`docker inspect --format '{{ .NetworkSettings.IPAddress }}' $(docker ps -q)`

get ports
`docker port container-id `

stats
`docker stats container-id`

container image diff
`docker diff container-id`

### terminal
manual set terminal size
```
stty size # current size
stty cols 146 rows 36
# docker exec -it $container -e COLUMNS=`tput cols` -e LINES=`tput lines` /bin/bash -l -i
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

get UUID:
```
mdadm --detail /dev/mdX
```


recreate `/etc/mdadm/mdadm.conf`
```
mdadm --examine --scan
mdadm --examine --scan >/etc/mdadm/mdadm.conf
update-initramfs -u
```

fix `resync=PENDING`
```
mdadm --readwrite /dev/mdX
```

destroy the raid:
```
mdadm --stop /dev/mdX
mdadm --detail /dev/mdX

```

## LVM
create Physical Volume
`pvcreate /dev/xda1`

create Volume Group:
`vgcreate vg-ssd /dev/xda1`

create logical volume 300G on volume-group `vg-hdd`:
```
lvcreate --name base-backups -L300G vg-hdd

```

create "thin volume" data:
```
lvcreate -L 100G -n data pve
lvconvert --type thin-pool pve/data
```


## misc
shift+numpad keys = home/end like in windows
```
/etc/default/keyboard : XKBOPTIONS="numpad:microsoft" ?
```


add swap
```
dd if=/dev/zero of=/swap bs=1M count=1024 && chmod go= /swap && mkswap /swap && echo "/swap swap  swap  sw  0 0" >>/etc/fstab  && swapon /swap
```

## img
remove EXIF info
```
sudo apt install exiv2 jhead libimage-exiftool-perl

exiftool -all= foo.jpg  # exiftool -geotag= foo.jpg
# or
jhead -purejpg foo.jpg
# or
exiv2 rm foo.jpg
# or
convert <input file> -strip <output file>

```

## sudo
```
deploy  ALL = NOPASSWD: /bin/systemctl
```

## locales
generate locales
```
locale-gen en_US.UTF-8
```

manually generate locales
```
localedef -i en_US -f UTF-8 en_US.UTF-8
```

check:
```
locale
```


## netcat
scan tcp ports
`nc -vnz 192.168.1.100 20-24`

scan udp ports
`nc -vnzu 192.168.1.100 5550-5560`

send udp packet
`echo -n "foo" | nc -u -w1 192.168.1.100 161`

send file
```
# remote
nc -lvp 5555           > /tmp/1.txt

# local
nc 192.168.1.100 5555  < /tmp/1.txt
```

simple http server
```
while true; do nc -lp 8888 < index.html; done
```

reverse shell
```
nc -e /bin/bash -lp 4444 # remote

nc 192.168.1.100 4444    # local
```


## tcpdump
dump http traffic on `lo` and port 3200

```
sudo stdbuf -oL -eL /usr/sbin/tcpdump -i lo -A -s 10240 "tcp port 3200 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)" | egrep -a --line-buffered ".+(GET |HTTP\/|POST )|^[A-Za-z0-9-]+: " | perl -nle 'BEGIN{$|=1} { s/.*?(GET |HTTP\/[0-9.]* |POST )/\n$1/g; print }'
```

### fping
network packet losses
```
fping -i10 -b1460 -o -l -q <addrs.txt
fping -i10 -b1460 -o -l -q -g 10.8.0.0/24
```

## golang
go install without vendor
`go install $(go list ./... | grep -v vendor/)`
or for glide
`go install $(glide nv)`

## proxmox
restore from dump
```
qmrestore vzdump-qemu-107-2017_12_02-00_10_54.vma.lzo 202 --storage lvm-nvme
```

## bitcoin
send all money

```
bitcoin-cli sendtoaddress ADDR `bitcoin-cli getbalance` "" "" true
```

## mosquitto

```
mosquitto_sub -v -h mqtt.flymon.net -t "+/+/uptime"
mosquitto_sub -v -h flyhub.org -u devvlad@gmail.com -P xxxxx -t "devvlad@gmail.com/HoneyWell-1/#"

mosquitto_pub -t user@domain.com/001122334455/temp -r -m 1234.56

```


## zfs
list
`zfs list`

create pool
`zpool create pool1 /dev/sda2`

status of pool
`zpool status`


snapshots:
`zfs snapshot pool1@NAME`
`zfs list -t snapshot`
`zfs destroy pool1@NAME`
`zfs rollback` # discard all changes made to a file system since a specific snapshot was created
`zfs rollback -r pool1@tuesday`  # recursive

## inputrc

to see codes do `cat /dev/null` and press keys, replace `^[` with `\e`.
example:

```sh
cat >/dev/null
ctrl-left: ^[[1;5D
ctrl-right: ^[[1;5C
```

and codes to `~/.inputrc`

```sh
cat >>~/.inputrc
"\e[1;5D": backward-word
"\e[1;5C": forward-word
```

to see current bindings:
`bind -p `


## Benchmarking

CPU

```sh
sysbench --test=cpu --cpu-max-prime=20000 run

# multithread
sysbench --test=cpu --cpu-max-prime=20000 --num-threads=16 run

```

Network:

```
iperf -s        # server
iperf -c host   # client
```

HTTP:
response time:
```
curl_time() {
    curl -so /dev/null -w "%{http_code}: size:%{size_download}b speed:%{speed_download}b/s\tdns:%{time_namelookup}s con:%{time_connect}s \
pretr:%{time_pretransfer}s sttra:%{time_starttransfer}s   total:%{time_total}s\n" "$@"
}

while sleep 0.5; do curl_time 0:3200/health; done
```

## tor proxy

```sh
docker run --name torproxy -d --restart=always -p 127.0.0.1:9051:9050/tcp dperson/torproxy
```


```
# gsettings set org.gnome.desktop.input-sources xkb-options "['caps:escape']"
```


## Letsencrypt wildcard domain
```
docker run -it --rm --name certbot \
  -v "/etc/letsencrypt:/etc/letsencrypt" \
  -v "/var/lib/letsencrypt:/var/lib/letsencrypt" certbot/certbot  \
  certonly --server https://acme-v02.api.letsencrypt.org/directory --manual --preferred-challenges dns
```

or

```
git clone https://github.com/certbot/certbot && cd certbot
./certbot-auto certonly --manual -d *.pv.vpn.aytm.com -d pv.vpn.aytm.com --agree-tos --manual-public-ip-logging-ok --preferred-challenges dns-01 --server https://acme-v02.api.letsencrypt.org/directory
```

With Cloudflare plugin:
```

# prepare cloudflare.ini file:
# dns_cloudflare_email = user@email.com
# dns_cloudflare_api_key = XXXXXXXXXXXXXXXXXXXXXXXXXXX

cloudflare_ini=/path/to/cloudflare.ini
docker run -it --rm --name certbot   \
    -v "/etc/letsencrypt:/etc/letsencrypt"   \
    -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
    -v "${cloudflare_ini}:/etc/letsencrypt/cloudflare.ini" \
    certbot/dns-cloudflare \
    certonly -m vlad@email.com \
            --agree-tos --manual-public-ip-logging-ok \
            --server https://acme-v02.api.letsencrypt.org/directory \
            --dns-cloudflare \
            --dns-cloudflare-credentials /etc/letsencrypt/cloudflare.ini  \
            --dns-cloudflare-propagation-seconds 60 \
            -d aaa.com -d *.aaa.com
```


# disable systemd-resolved
```
sudo systemctl disable systemd-resolved.service
sudo service systemd-resolved stop
rm /etc/resolv.conf ; echo "nameserver 1.1.1.1" >/etc/resolv.conf
```
Put the following line in the [main] section of your /etc/NetworkManager/NetworkManager.conf:

```
dns=default
```
Delete the symlink /etc/resolv.conf : `rm /etc/resolv.conf`
Restart network-manager : `sudo service network-manager restart`

## elasticsearch

curl -XPUT -H "Content-Type: application/json" http://localhost:9200/_all/_settings -d '{"index.blocks.read_only_allow_delete": null}'

## OOM
protect process  (postgres in this case)
```
pgrep -f postgres | while read PID; do echo -17 > /proc/$PID/oom_adj; done
```

show OOM score
```
alias show-oom-score="while read -r pid comm; do printf '%d\\t%d\\t%s\\n' \"\$pid\" \"\$(cat /proc/\$pid/oom_score)\" \"\$comm\"; done < <(ps -e -o pid= -o comm=)"
```


## IO tuning

- https://unix.stackexchange.com/questions/150211/how-to-reduce-disk-access

add to `/etc/sysctl.d/hdd-minimize-io.conf`
```
vm.dirty_background_ratio = 20
vm.dirty_expire_centisecs = 360000
vm.dirty_writeback_centisecs = 360000
```

update `/etc/fstab` of vm's, like:

```
UUID=e68e1459-b1cf-4255-b860-28cdc4074559 /               ext4    discard,noatime,nodiratime,relatime,errors=remount-ro 0       1

```


## GDB

get stacktrace from ruby process
```
call (void) close(1)
call (void) close(2)

shell tty

call (int) open("/dev/pts/0", 2, 0) # substitute output from `tty`
call (int) open("/dev/pts/0", 2, 0)

call (void)rb_backtrace()
```

## cron

backup file via cron with `date`
```
crontab -e

01 13 * * * sh -c "[ -f /home/user/file ] && cp /home/user/file /backups/`date +\%Y\%m\%d`-file"
```

## prometheus

### process-exporter for puma and sidekiq

`/etc/process-exporter/config.yaml`
```
process_names:
  - name: "{{.Matches.Worker}}"
    cmdline:
    - '(?P<Worker>puma: cluster worker \d)'
  - name: "{{.Matches.Sidekiq}}"
    cmdline:
    - '(?P<Sidekiq>sidekiq).*'
```

run:
```
docker run -d --name=prom-process-exporter --restart=always -p 1.1.1.1:9256:9256 --privileged -v /proc:/host/proc -v /etc/process-exporter/:/config ncabatoff/process-exporter --procfs /host/proc -config.path /config/config.yaml
```

### postgres exporter

create user and set permissions: https://github.com/wrouesnel/postgres_exporter#running-as-non-superuser

```
docker run --name prom-postgres-exporter -d --restart=always --net=host \
    -e DATA_SOURCE_NAME="postgresql://postgres_exporter:pass@1.1.1.1:5432/postgres?sslmode=disable" \
    wrouesnel/postgres_exporter --web.listen-address=1.1.1.1:9187 --log.level=debug
```

## block devices

list
```
lsblk
```

Set readahead cache:
The readahead value is <desired_readahead_bytes> / 512 bytes.
```
sudo blockdev --getra /dev/[DEVICE_ID]
sudo blockdev --setra [VALUE] /dev/[DEVICE_ID]
```

## mkfs

tuning:
disable journal, no reserved space for root user
```
mkfs.ext4 -m0 -O ^has_journal -E lazy_itable_init=0,lazy_journal_init=0,discard /dev/sdX
# tune2fs -O ^has_journal /dev/sdX # on existed fs
mount -o discard,nodiratime,noatime /dev/sdX /dir
```

## resize fs

to resize disk online run `cfdisk` and recreate partition from start block
then run `partprobe` and `lsblk`, then `resize2fs /dev/sdXn`


## zram

```
ZRAM_DISK_SIZE=5000 # Mb
ZRAM_DEV=zram1
modprobe zram num_devices=4
zramctl ${ZRAM_DEV} -a lz4 -s $((${ZRAM_DISK_SIZE}*1024*1024))
mkswap /dev/${ZRAM_DEV}
swapon -p10 /dev/${ZRAM_DEV}
swapon -s

```


## tmux

share tmux with other user (pair) without screen mirroring:

```
tmux new -s alice # one user

tmux new -s bob -t alice # second user

```
details: https://www.hamvocke.com/blog/remote-pair-programming-with-tmux/

## ntp

sync time
```
ntpdate -sb time.nist.gov
```

## envs

read env of process
```
xargs --null --max-args=1 echo < /proc/$$/environ
xargs -0 -L1 -a /proc/self/environ
```
