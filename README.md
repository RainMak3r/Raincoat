# Raincoat

VBChk

VBChk - Checking file hash against VirusTotal.

Developer : Andy Yang Version : 0.1.0 License : GNU GENERAL PUBLIC LICENSE v3

RainMak3r@Could:~/Desktop# ruby VBChk.rb -h
               

EXAMPLE USAGE:

    ./VBchk.rb  -f '/User/eve/autorun.csv'

    -f, --CSV file path              CSV file that has file hashes to be checked with VirusTotal. 
    -h, --help                       Display help

Note: CSV file has two columns, col_1 is file path (or filename), col_2 is hash.

    For example: 

          demo.csv 
          
            |c:\program files (x86)\App_test\test.exe|MD5HASH|
            
            |c:\windows\syswow64\mal01.exe           |SHA1   |
            
            |mal02.dll                               |MD5    |
            
    

Example of usage.
RainMak3r@Could:~/Desktop#./VBChk.rb -f demo.csv 

[Info]    No detection for c:\program files (x86)\App_test\test.exe

[Info]    This file has not been submitted to VirusTotal : test.url

[Alert]   Potential malware detected : c:\windows\syswow64\mal01.exe

[Alert]   File detection rate : 38/54

[Alert]   VirusTotal Link : https://www[dot]virustotal[dot]com/en/file/3f55d34aa0b71daf4ad8a5937721ba4511e55cd31fdacd2e817e8977605232b8/analysis/

[Alert]   Potential malware detected : c:\windows\system32\mal02.dll

[Alert]   File detection rate : 40/54

[Alert]   VirusTotal Link : https://www[dot]virustotal[dot]com/en/file/521fb6ebc79e4bbb4d31d4f70c5a1a9c2b8c34099e6f67749f1f01f26a15ee95/analysis/

[Info] No detection for c:\windows\system32\drivers\legitmate.sys

[DONE]  Please check the output VBrating.csv file for details.

