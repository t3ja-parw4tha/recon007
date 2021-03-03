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

if [[ ! $# -eq 2 ]];     
        then
                echo -e $Cyan "\n\tUsage:" $Green "recon_007.sh <program name>" $Reset
                exit 
fi


echo -e $Purple
echo -e "Use VPN or VPS for not getting banned."
echo -e "Results will be automatically saved in ~/Recon directory."
echo -e $Default

if [ ! -d ~/"Recon" ]; then
	mkdir ~/Recon
fi

dir=~/Recon/$domain

subdomain_enum(){
	if [ ! -f "$dir" ]
		then
            mkdir -p ~/Recon/$domain
			echo -e "${Yellow} Running : Subdomain Enumeration${Reset}\n"
			subfinder -d $domain -o $dir/subfinder_results.txt 
			assetfinder --subs-only $domain $DEBUG_ERROR | anew -q $dir/assetfinder_results.txt
			amass enum -passive -d $domain -config $AMASS_CONFIG -o $dir/amass_results.txt
			findomain --quiet -t $domain -u $dir/findomain_results.txt
			crobat -s $domain $DEBUG_ERROR | anew -q $dir/crobat_results.txt
			timeout 5m waybackurls $domain | unfurl --unique domains | anew -q $dir/waybackurls_results.txt
	        curl -s "https://dns.bufferover.run/dns?q=.$domain" | jq -r .FDNS_A[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$domain" | sort -u > $dir/dnsbuffer_results.txt
	        curl -s "https://dns.bufferover.run/dns?q=.$domain" | jq -r .RDNS[] 2>/dev/null | cut -d ',' -f2 | grep -o "\w.*$domain" | sort -u >> $dir/dnsbuffer_results.txt
	        curl -s "https://tls.bufferover.run/dns?q=.$domain" | jq -r .Results 2>/dev/null | cut -d ',' -f3 |grep -o "\w.*$domain"| sort -u >> $dir/dnsbuffer_results.txt
	        sort -u $dir/dnsbuffer_results.txt -o $dir/dnsbuffer_results.txt
	        echo -e "${Green}[+] Dns.bufferover.run Over => $(wc -l dnsbuffer_$domain.txt|awk '{ print $domain}')${Reset}"
            eval cat $dir/*results.txt $DEBUG_ERROR | sed "s/*.//" | anew $dir/subs.txt | wc -l
            rm $dir/*results.txt
        else
			printf "${Yellow} $domain is already processed, to force executing $domain delete $dir ${Reset}\n\n"
	fi
}

subdomain_bruteforce(){
    if [ ! -f "$dir/enum_subs.txt" ]
        then
            echo -e "${Yellow}#####starting shuffledns#####${Reset}"
            touch 
            shuffledns -d $domain -w ~/Tools/subdomains.txt -r ~/Tools/resolvers.txt -t 1000 -o $dir/bruteforced.txt
            cat $dir/bruteforced.txt | tee -a $dir/subs.txt
            sort -u $dir/subs.txt -o $dir/enum_subs.txt
            rm $dir/bruteforced.txt
            rm $dir/subs.txt
    fi
}

subdomain_bruteforce(){
    if [ ! -f "$dir/dns_subs.txt" 
        then
            shuffledns -d $domain -list $dir/subs.txt -r ~/Tools/resolvers -t 5000 -o $dir/dns_subs.txt
            $domain | dnsx -silent | anew -q $dir/dns_subs.txt
            dnsx -retry 3 -silent -cname -resp-only -l $dir/dns_subs.txt | grep ".$domain$" | anew -q $dir/dns_subs.txt
    fi
}

probing(){
	if [ ! -f "$dir/probed.txt" ]
		then
			printf "${yellow} Checking for live subdomains" ${Reset}
			touch $dir/probed.txt
			cat $dir/*subs.txt| httpx -follow-redirects -status-code -vhost -timeout 15 -silent >> $dir/probed.txt
            cat $dir/*subs.txt| httpx >> $dir/probed_http.txt
	fi
}

nuclei(){
    if [ ! -f "$dir/nuclei" ]
        then
            echo -e "${Blue} Starting nuclei......... ${Reset}\n\n"
            mkdir $dir/nuclei
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/cves/ -o $dir/nuclei/cves.txt
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/files/ -o $dir/nuclei/files.txt
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/miscellaneous/ -o nuclei_op/miscellaneous.txt
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/misconfiguration/ -o nuclei_op/misconfiguration.txt
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/technologies/ -o nuclei_op/technologies.txt
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/exposed-tokens/ -o nuclei_op/exposed-tokens.txt
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/exposed-panels/ -o nuclei_op/exposed-panels.txt
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/exposures/ -o nuclei_op/exposures.txt
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/vulnerabilities/ -o nuclei_op/vulnerabilities.txt
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/dns/ -o nuclei_op/dns.txt
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/default-logins/ -o nuclei_op/default-logins.txt
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/fuzzing/ -o nuclei_op/fuzzing.txt
            cat $dir/probed_http.txt | nuclei -silent -t ~/nuclei-templates/workflows/ -o nuceli_op/workflows.txt
    fi            
}

urls(){
    if [ ! -f "$dir/url_extracts.txt" ]
        then
            echo -e "${Blue} Starting url scans......... ${Reset}\n\n"
            cat $dir/probed_http.txt | gau | anew -q $dir/urls_temp.txt
            cat $dir/probed_http.txt | waybackurls | anew -q $dir/urls_temp.txt
            uddup -u $dir/urls_temp.txt -o $dir/url_extracts.txt
    fi
}

fuzzing(){
    if [ ! -f "$dir/fuzzing" ]
        then 
            mkdir -p $dir/fuzzing
            for script in $(cat $dir/probed_http.txt);do ffuf -c -w ~/Tools/fuzz_wordlist.txt -u $script/FUZZ -mc 200,402,403,302,500 -maxtime 300 -timeout 2 | tee -a $dir/fuzzing/$script.tmp
            cat $dir/fuzzing/$script.tmp | jq '[.results[]|{status: .status, length: .length, url: .url}]' | grep -oP "status\":\s(\d{3})|length\":\s(\d{1,7})|url\":\s\"(http[s]?:\/\/.*?)\"" | paste -d' ' - - - | awk '{print $2" "$4" "$6}' | sed 's/\"//g' | anew -q $dir/fuzzing/$script.txt
            rm $dir/fuzzing/$script.tmp
            echo -e "${Blue} fuzzing is done${Reset}\n\n"
    fi
}


###### do not automate ######
# 403_bypasser(){
#     if [ ! -f "$dir/403_bypasser" ]
#         then
#             echo -e "${Blue} Starting 403_bypass checks.... ${Reset}\n\n"
#             mkdir -p $dir/403_bypasser
#             cat $dir/fuzzing/*.txt | grep '^403*' >> 403_urls.txt
#     fi
# }
            
 xss_check(){
    if [ ! -f "$dir/reflected_xss.txt" ]
        then
            mkdir $dir/xss
            for script in $(cat $dir/probed_http.txt);do python3 ~/Tools/ParamSpider/paramspider.py -d $script --subs False --exclude png,jpg,svg,js,css,eot,ttf,woff,woff2,jpeg,axd --placeholder '"><script>confirm(1)</script>' --quiet --output $dir/xss/$script.txt ;done
            cat $dir/xss/*.txt >> $dir/xss/all_urls.txt
            cat $dir/xss/all_urls.txt | while read host do ; do curl --silent --path-as-is --insecure "$host" | grep -qs "<script>confirm(1)" && echo -e "$host ${Red}Vulnerable ${Reset}\n" || echo -e "$host ${Blue}Not Exploitable ${Reset}\n";done >> $dir/reflected_xss.txt
            # cat $dir/reflected_xss.txt | grep "Vulnerable" ####
    fi
}

gf_urls(){
    if [ ! -f "$dir/gf" ]
        then
            mkdir $dir/gf
            cat $dir/url_extracts.txt | gf redirect > $dir/gf/redirect.txt
            cat $dir/url_extracts.txt | gf ssrf > $dir/gf/ssrf.txt
            cat $dir/url_extracts.txt | gf rce > $dir/gf/rce.txt
            cat $dir/url_extracts.txt | gf idor > $dir/gf/idor.txt
            cat $dir/url_extracts.txt | gf sqli > $dir/gf/sqli.txt
            cat $dir/url_extracts.txt | gf lfi > $dir/gf/lfi.txt
            cat $dir/url_extracts.txt | gf ssti > $dir/gf/ssti.txt
    fi
}

  












    
    
