# EthicalHacking

See blackhatpy for curriculum and python scripts. 

# Writeup PERU

In this task we are given a pcap file, which can be opened with wireshark. 
To observere what is going on, we can click "Follow TCP stream". We can see that the there is a password token:

![Alt text](/figures/Peru1.png?raw=true )

We try to run the Pyhon command on the token:
<pre>
$ python 
>>> Token='TUNBezU4MDc2MjY2NzZ9'
>>> print(Token[13:] + Token[:13])
jY2NzZ9TUNBezU4MDc2M
</pre>

And the flag is 
ttm4536{jY2NzZ9TUNBezU4MDc2M}

# Writeup YEMEN

In this task we are given a pcap file, which can be opened with wireshark. 

To observere what is going on, we can click "Follow TCP stream" and then it can be seen that there several files being sent by looking at the file  signature in the beginning of the streams.

![Alt text](/figures/comm1.png?raw=true )

The, we can extract all the files as http objects into a folder. 

To get information about these objects filetype, file can be run on them:
<pre>
$ file * 
</pre>

We see that all the objects contain data, and recognize several filetypes: RIFF (little-endian) data, Web/P image, PDP-11 pure executable etc. However, object475 is a x.out archive which looks interesting. It does not work to use 7z or unzip to extract the data, but we have all the data in Wireshark. In Wireshark, we can copy all the raw data from the stream belonging to the archive into a new file named "RAW". As the file signature is the same, it is recognized:

![Alt text](/figures/comm2.png?raw=true )
<pre>
[:wiresharkobj0]$ file RAW
RAW: gzip compressed data, was "who.txt", last modified: Sun Sep 29 07:37:12 2019, from Unix, original size 153525
</pre>

We then extract the content of RAW:
<pre>
[wiresharkobj0]$ 7z x RAW

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=utf8,Utf16=on,HugeFiles=on,64 bits,4 CPUs x64)

Scanning the drive for archives:
1 file, 51945 bytes (51 KiB)

Extracting archive: RAW
--
Path = RAW
Type = gzip
Headers Size = 18

Everything is Ok

Size:       153525
Compressed: 51945
</pre>

<pre>
$ cat who.txt
</pre>
![Alt text](/figures/comm3.png?raw=true )

ttm4536{Banana-limk-shake2019}
