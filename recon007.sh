##!/bin/bash

Black="\033[0;30m"
Red="\033[0;31m"
Green="\033[0;32m"
Yellow="\033[0;33m"
Blue="\033[0;34m"
Purple="\033[0;35m"
Cyan="\033[0;36m"
White="\033[0;37m"
Reset="\033[0;m"


echo -e $Purple
echo -e "Use VPN or VPS for not getting banned."
echo -e "Results will be automatically saved in ~/Recon directory."
echo -e $Default

if [ ! -d "~/Recon" ]; then
	mkdir ~/Recon
fi

if [ ! -d "~/Recon/$1" ]; then
	mkdir ~/Recon/$1
fi

#dir=~/Recon/$1

if [ ! -f "~/Recon/$1/subs.txt" ];
	then
		echo -e "${Yellow} Running : Subdomain Enumeration${Reset}\n"
		subfinder -d $1 -o ~/Recon/$1/subfinder_results.txt 
		assetfinder --subs-only $1 $DEBUG_ERROR | anew -q ~/Recon/$1/assetfinder_results.txt
		amass enum -passive -d $1 -config $AMASS_CONFIG -o ~/Recon/$1/amass_results.txt
		findomain --quiet -t $1 -u ~/Recon/$1/findomain_results.txt
		crobat -s $1 $DEBUG_ERROR | anew -q ~/Recon/$1/crobat_results.txt
		timeout 5m waybackurls $1 | unfurl --unique domains | anew -q ~/Recon/$1/waybackurls_results.txt
	        curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u > ~/Recon/$1/dnsbuffer_results.txt
     	        curl -s "https://dns.bufferover.run/dns?q=.$1" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$1" | sort -u >> ~/Recon/$1/dnsbuffer_results.txt
		curl -s "https://tls.bufferover.run/dns?q=.$1" | jq -r .Results 2>/dev/null | cut -d ',' -f3 |grep -o "\w.*$1"| sort -u >> ~/Recon/$1/dnsbuffer_results.txt
	        sort -u ~/Recon/$1/dnsbuffer_results.txt -o ~/Recon/$1/dnsbuffer_results.txt
     	        echo -e "${Green}[+] Dns.bufferover.run Over => $(wc -l dnsbuffer_$1.txt|awk '{ print $1}')${Reset}"
		eval cat ~/Recon/$1/*results.txt $DEBUG_ERROR | sed "s/*.//" | anew ~/Recon/$1/subs.txt | wc -l
                rm ~/Recon/$1/*results.txt
fi


 if [ ! -f "~/Recon/$1/enum_subs.txt" ]
        then
            echo -e "${Yellow}#####starting shuffledns#####${Reset}"
            shuffledns -d $1 -w ~/Tools/subdomains.txt -r ~/Tools/resolvers.txt -t 1000 -o ~/Recon/$1/bruteforced.txt
            cat ~/Recon/$1/bruteforced.txt | tee -a ~/Recon/$1/subs.txt
            sort -u ~/Recon/$1/subs.txt -o ~/Recon/$1/enum_subs.txt
            rm ~/Recon/$1/bruteforced.txt
 fi



if [ ! -f "~/Recon/$1/dns_subs.txt" ]
        then
            shuffledns -d $1 -list ~/Recon/$1/subs.txt -r ~/Tools/resolvers -t 5000 -o ~/Recon/$1/dns_subs.txt
            $1 | dnsx -silent | anew -q ~/Recon/$1/dns_subs.txt
            dnsx -retry 3 -silent -cname -resp-only -l ~/Recon/$1/dns_subs.txt | grep ".$1$" | anew -q ~/Recon/$1/dns_subs.txt
fi



if [ ! -f "~/Recon/$1/probed.txt" ]
		then
			printf "${yellow} Checking for live subdomains" ${Reset}
			touch ~/Recon/$1/probed.txt
			cat ~/Recon/$1/*subs.txt| httpx -follow-redirects -status-code -timeout 15 -silent >> ~/Recon/$1/probed.txt
            cat ~/Recon/$1/*subs.txt| httpx >> ~/Recon/$1/probed_http.txt
fi



if [ ! -f "~/Recon/$1/nuclei" ]
        then
            echo -e "${Blue} Starting nuclei......... ${Reset}\n\n"
            mkdir ~/Recon/$1/nuclei
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/cves/ -o ~/Recon/$1/nuclei/cves.txt
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/files/ -o ~/Recon/$1/nuclei/files.txt
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/miscellaneous/ -o ~/Recon/$1/miscellaneous.txt
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/misconfiguration/ -o ~/Recon/$1/misconfiguration.txt
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/technologies/ -o ~/Recon/$1/technologies.txt
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/exposed-tokens/ -o ~/Recon/$1/exposed-tokens.txt
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/exposed-panels/ -o ~/Recon/$1/exposed-panels.txt
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/exposures/ -o ~/Recon/$1/exposures.txt
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/vulnerabilities/ -o ~/Recon/$1/vulnerabilities.txt
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/dns/ -o ~/Recon/$1/dns.txt
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/default-logins/ -o ~/Recon/$1/default-logins.txt
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/fuzzing/ -o ~/Recon/$1/fuzzing.txt
            cat ~/Recon/$1/probed_http.txt | nuclei -silent -t ~/nuclei-templates/workflows/ -o ~/Recon/$1/workflows.txt
fi            



if [ ! -f "~/Recon/$1/url_extracts.txt" ]
        then
            echo -e "${Blue} Starting url scans......... ${Reset}\n\n"
            cat ~/Recon/$1/probed_http.txt | gau | anew -q ~/Recon/$1/urls_temp.txt
            cat ~/Recon/$1/probed_http.txt | waybackurls | anew -q ~/Recon/$1/urls_temp.txt
	    cat ~/Recon/$1/urls_temp.txt | grep "$1" | grep "=" | eval qsreplace -a $DEBUG_ERROR | egrep -iv "\.(eot|jpg|jpeg|gif|css|tif|tiff|png|ttf|otf|woff|woff2|ico|pdf|svg|txt|js)" | anew -q ~/Recon/$1/urls_temp2.txt
            uddup -u ~/Recon/$1/urls_temp2.txt -o ~/Recon/$1/url_extracts.txt
	    rm ~/Recon/$1/urls_temp.txt
	    rm ~/Recon/$1/urls_temp2.txt
 fi



if [ ! -f "~/Recon/$1/fuzzing" ]
        then 
            mkdir -p ~/Recon/$1/fuzzing
            for script in $(cat ~/Recon/$1/probed_http.txt);do ffuf -c -w ~/Tools/fuzz_wordlist.txt -u $script/FUZZ -mc 200,402,403,302,500 -maxtime 300 -timeout 2 | tee -a ~/Recon/$1/fuzzing/$script.tmp ;done
	    eval cat ~/Recon/$1/fuzzing/$script.tmp $DEBUG_ERROR | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' | sed 's/\"//g' | anew -q ~/Recon/$1/fuzzing/${sub_out}.txt
	    rm ~/Recon/$1/fuzzing/$script.tmp
            echo -e "${Blue} fuzzing is done${Reset}\n\n"
fi




if [ ! -f "~/Recon/$1/reflected_xss.txt" ]
        then
            mkdir ~/Recon/$1/xss
            for script in $(cat ~/Recon/$1/probed_http.txt);do python3 ~/Tools/ParamSpider/paramspider.py -d $script --subs False --exclude png,jpg,svg,js,css,eot,ttf,woff,woff2,jpeg,axd --placeholder '"><script>confirm(1)</script>' --quiet --output ~/Recon/$1/xss/$script.txt ;done
            cat ~/Recon/$1/xss/*.txt >> ~/Recon/$1/xss/all_urls.txt
            cat ~/Recon/$1/xss/all_urls.txt | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo -e "$host ${Red}Vulnerable ${Reset}\n" || echo -e "$host ${Blue}Not Exploitable ${Reset}\n";done >> ~/Recon/$1/reflected_xss.txt
          
	  ###### To search for vulnerable urls  ###
	  ###### cat ~/Recon/$1/reflected_xss.txt | grep "Vulnerable" ###
fi



if [ ! -f "~/Recon/$1/gf" ]
        then
            mkdir ~/Recon/$1/gf
            cat ~/Recon/$1/url_extracts.txt | gf redirect > ~/Recon/$1/gf/redirect.txt
            cat ~/Recon/$1/url_extracts.txt | gf ssrf > ~/Recon/$1/gf/ssrf.txt
            cat ~/Recon/$1/url_extracts.txt | gf rce > ~/Recon/$1/gf/rce.txt
            cat ~/Recon/$1/url_extracts.txt | gf idor > ~/Recon/$1/gf/idor.txt
            cat ~/Recon/$1/url_extracts.txt | gf sqli > ~/Recon/$1/gf/sqli.txt
            cat ~/Recon/$1/url_extracts.txt | gf lfi > ~/Recon/$1/gf/lfi.txt
            cat ~/Recon/$1/url_extracts.txt | gf ssti > ~/Recon/$1/gf/ssti.txt
fi




  












    
    
