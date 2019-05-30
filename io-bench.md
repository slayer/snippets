
## fio

Sequential READ speed with big blocks
```
fio --name TEST --eta-newline=5s --filename=fio-tempfile.dat --rw=read --size=20g --io_size=10g \
    --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --direct=1 \
    --numjobs=4 --runtime=300 --group_reporting
```

Sequential WRITE speed with big blocks
```
fio --name TEST --eta-newline=5s --filename=fio-tempfile.dat --rw=write --size=20g --io_size=10g \
    --blocksize=1024k --ioengine=libaio --fsync=10000 --iodepth=32 --direct=1 \
    --numjobs=4 --runtime=300 --group_reporting
```

Random 4K read QD1
```
fio --name TEST --eta-newline=5s --filename=fio-tempfile.dat --rw=randread --size=20g --io_size=10g \
    --blocksize=4k --ioengine=libaio --fsync=1 --iodepth=1 --direct=1 \
    --numjobs=4 --runtime=300 --group_reporting
```


Mixed random 4K read and write QD1 with sync
```
fio --name TEST --eta-newline=5s --filename=fio-tempfile.dat --rw=randrw --size=20g --io_size=10g \
    --blocksize=4k --ioengine=libaio --fsync=1 --iodepth=1 --direct=1 \
    --numjobs=4 --runtime=300 --group_reporting
```


`sequential.fio` file
```ini
cat <<EOF >sequential.fio
[global]
ioengine=libaio
invalidate=1
ramp_time=5
size=32G
numjobs=4
iodepth=32
fsync=1
runtime=300
time_based

[write-fio-4k-para]
bs=4k
stonewall
filename=fio-tempfile.dat
rw=write
write_bw_log=4k-write.results
write_iops_log=4k-write.results
write_lat_log=4k-write.results

[read-fio-4k-para]
bs=4k
stonewall
filename=fio-tempfile.dat
rw=read
write_bw_log=4k-read.results
write_iops_log=4k-read.results
write_lat_log=4k-read.results

[read-fio-1m-para]
bs=1m
stonewall
filename=fio-tempfile.dat
rw=read
write_bw_log=1m-read.results
write_iops_log=1m-read.results
write_lat_log=1m-read.results
EOF
```

