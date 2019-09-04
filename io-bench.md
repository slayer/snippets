
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





The following example benchmarks maximum write throughput:

```
fio --ioengine=sync --direct=0 \
--fsync_on_close=1 --randrepeat=0 --nrfiles=1  --name=seqwrite --rw=write \
--bs=1m --size=20G --end_fsync=1 --fallocate=none  --overwrite=0 --numjobs=1 \
--directory=/mnt/gcfs --loops=10
```
The following example benchmarks maximum write IOPS:

```
fio --ioengine=sync --direct=0 \
--fsync_on_close=1 --randrepeat=0 --nrfiles=1  --name=randwrite --rw=randwrite \
--bs=4K --size=1G --end_fsync=1 --fallocate=none  --overwrite=0 --numjobs=80 \
--sync=1 --directory=/mnt/standard --loops=10
```

The following example benchmarks maximum read throughput:

```
fio --ioengine=sync --direct=0 \
--fsync_on_close=1 --randrepeat=0 --nrfiles=1  --name=seqread --rw=read \
--bs=1m --size=240G --end_fsync=1 --fallocate=none  --overwrite=0 --numjobs=1 \
--directory=/mnt/ssd --invalidate=1 --loops=10
```

The following example benchmarks maximum read IOPS:
```
fio --ioengine=sync --direct=0 \
--fsync_on_close=1 --randrepeat=0 --nrfiles=1  --name=randread --rw=randread \
--bs=4K --size=1G --end_fsync=1 --fallocate=none  --overwrite=0 --numjobs=20 \
--sync=1 --invalidate=1 --directory=/mnt/standard  --loops=10
```
