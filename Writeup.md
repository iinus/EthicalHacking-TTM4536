#### Writeup Communication

In this task we are given a pcap file, which can be opened with wireshark. 

To observere what is going on, we can click "Follow TCP stream" and then it can be seen that there several files being sent by looking at the file  signature in the beginning of the streams.

![Alt text](/figures/comm2.png?raw=true )

The, we can extract all the files as http objects into a folder. 

To get information about these objects filetype, file can be run on them:
<pre>
$ file * 
</pre>

We see that all the objects contain data, and recognize several filetypes: RIFF (little-endian) data, Web/P image, PDP-11 pure executable etc. However, object475 is a x.out archive which looks interesting. It does not work to use 7z or unzip to extract the data, but we have all the data in Wireshark. In Wireshark, we can copy all the raw data from the stream belonging to the archive into a new file. As the file signature is the same, it is recognized:

![Alt text](/figures/comm1.png?raw=true )
<pre>
[:wiresharkobj0]$ file RAW
RAW: gzip compressed data, was "who.txt", last modified: Sun Sep 29 07:37:12 2019, from Unix, original size 153525
</pre>

Running 7z x RAW extracts a text file, who.txt.

We run cat who.txt and find our flag in the end of the text file:
![Alt text](/figures/comm3.png?raw=true )

ttm4536{Banana-limk-shake2019}