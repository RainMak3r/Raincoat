#!/usr/bin/env ruby
# encoding: utf-8

require 'net/http'
require 'optparse'
require 'openssl'
require 'csv'

 def colorize(text, color_code)
    "\e[#{color_code}m#{text}\e[0m"
  end

  def 
    red(text); colorize(text, 31); 
    end
  def 
    green(text); colorize(text, 32);
  end
  
  def 
    yellow(text); colorize(text, 33); 
  end

  def 
    pink(text); colorize(text, 35); 
  end

def randomdelay(count)
    mod=count %37
    if (mod==0)
        sleep(rand(10))
    else
        sleep(rand(1))
    end

end  



def retrieveURL(hash)

    begin
        
        http = Net::HTTP.new('www.virustotal.com',443)
        http.use_ssl = true
        cookie='__utmt=1';
        pdata="query="+hash
        res = http.post('/en/search/',pdata,initheader = {'Cookie' =>cookie})
        location=res.get_fields('Location')
        slocation=location[0]
        slocation=slocation.chomp
        if slocation.include? "file/not/found/"           
            data=["Not FOUND","NA","NA","NA"]
        else
            uri = URI(slocation)
            res = http.get(uri.path ,initheader = {'Cookie' =>cookie})
            sStart_rate='Detection ratio:'
            body=res.body
            srate= body[body.index(sStart_rate)+sStart_rate.length, 120]
            istart=srate.index("\">")
            srate=srate[istart,120-istart]


            istart=srate.index("/")
            istart.to_s
            srate=srate[istart-4,istart+2]
            srate=srate.gsub!(/\s+/, '')
            srate=srate.gsub('<', '')

            sStart_anlzdate='Analysis date:'
            sanlzdate= body[body.index(sStart_anlzdate)+sStart_anlzdate.length, 140]
            istart=sanlzdate.index("<td >")
            sanlzdate=sanlzdate[istart+"<td >".length,140-istart]
            istart=sanlzdate.index("</td>")
            istart.to_s
            sanlzdate=sanlzdate[0,istart]
            sanlzdate=sanlzdate.gsub("\n",'')
            sanlzdate=sanlzdate.strip
            sanlzdate=sanlzdate.gsub(',', ' ')



            comts='NA'

            if (body.include? 'Probably harmless!')
                comts='Probably harmless'
            elsif  (body.include? 'Trusted source!')
                comts='Trusted source!'
            end

            data=[slocation,srate,sanlzdate,comts]
        end

        return data

  rescue Exception => e
    puts red("[Error]   An error occurred : "+ e.to_s)
    exit 1
  end 
end

def Vbchk(csvfile)
    i=0
    CSV.open("VBrating.csv", "w") do |csv|
        csv << ["File Path", "Detection","Analysis Date","Comments", "MD5","VBlink"]
        CSV.foreach(csvfile) {
            |row| 
            i=i+1
            print "\r"
                hash = row[1]
                path=row[0]
                det=retrieveURL(hash)

                drate=det[1]
                if drate.include? "NA"
                    puts pink("[Info]   This file has not been submitted to VirusTotal : "+ path) 
                    puts "\n"
                else    
                    drate=drate[0,drate.index("/")].strip
                    if  (drate !='0')
                       puts red("[Alert]   Potential malware detected : "+ path)
                       puts red("[Alert]   File detection rate : "+ det[1])  
                       puts red("[Alert]   VirusTotal Link : "+ det[0]) 
                       det[3]="Malicious"
                    else
                       print green("[Info] No detection for "+ path)
                    end

                end
                csv<<   [path,det[1],det[2],det[3],hash,det[0]]


            #avoid IPS by adding delay if hashes are over 100
            #enable it when it is necessary 
            #randomdelay(i)
        }
    end
    print "\n"
end

options = {}
optparse = OptionParser.new do|opts|
opts.banner =yellow(" //   ___      ___ ________  ________  ___  ___  ___  __       
//  |\\  \\    /  /|\\   __  \\|\\   ____\\|\\  \\|\  \\|\\  \\|\\  \\     
//  \\ \\  \\  /  / | \\  \\|\\/\\\\  \\___|\\ \\  \\\  \\  \\  \\/  /|_   
//   \\ \\  \\/  / / \\ \\   __  \\ \\ \\    \\ \\   __  \\ \\   ___  \\  
//    \\ \\    / /   \\ \\  \\|\\  \\ \\ \\____\\ \\  \\ \\   \\ \\  \\\\ \\  \\ 
//     \\ \\__/ /     \\ \\_______\\ \_______\\ \\__\\ \\__\\   \\__\\\\ \\__\\       Version - 0.1 by Andy Yang
//      \\|__|/       \\|_______|\\|_______|\\|__|\\|__|\\|__|   \\|__|      contactayang[AT]gmail[DOT]com
//                                                            
//                                                            
")
    opts.separator  "VBChk - Checking file hash against VirusTotal by Andy Yang"
    opts.separator ""
    opts.separator  "EXAMPLE USAGE:"
    opts.separator  "     ./VBchk.rb  -f \'/User/eve/autorun.csv\'"
    opts.separator ""
 
    options[:file] = nil
    opts.on( '-f', '--CSV file path', 'CSV file that has file hashes to be checked with VB' ) do |filepath|
       options[:file] = filepath
     end      
    opts.on( '-h', '--help', 'Display help' ) do
    puts opts
    exit
    end
   end
   
   begin optparse.parse! ARGV  
   rescue OptionParser::InvalidOption => e
    puts e
    puts optparse
    exit 1
  end 
 



if (options[:file] == nil) 
    puts green("[Info]     Please supply the CSV file path. ")
    puts green("[Info]     For more infomation please refer to the followings usage:")
    puts optparse
elsif (File.exist?(options[:file])==false)
    puts red("[Fail]  "+options[:file]+" file is not exist or readable!!!")
    puts optparse

else 
    f=options[:file]
    Vbchk(f)
    puts pink("\e[1m[DONE]  Please check the output VBrating.csv file for details.\e[0m")
end

