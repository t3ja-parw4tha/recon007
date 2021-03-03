#!/bin/bash

# ================  configurations ==========

amass_enum_timeout="30m" #(s:seconds,m:minutes,h:hours,d:days) amass sometime may go in loop because of wildcard domains or other, so this will let you stop amass after specific time
subjack_threads=50 # 200 #threads to used by subjack tool (reduce if you want to reduce cpu usage)
subjack_timeout=30       #(in seconds) max time that subjack should wait for requested page to load
massdns_concurrent_lookups_cnt=10000 #[default:10000]  1000 is for less false positives # higher the value , greater the aggresiveness aganist resolvers, may get banned from few resolver for higher values
wildcard_elimination_ptr_threshold=4 #(not doing exactly, use +x to actual value) in wildcard elimination, max number of domains that can point to same ip or cname
httprobe_concurrency_level=30 #[default:20] httprobe concurrency level
httprobe_timeout=3000    #(millisecods)[default:10000]
chromium_path=$(which chromium)
analysis_reverse_proxy_checks_max_procs=20  # not sure whether it uses all of these (haven't checked exatcly)
aquatone_threads=3 # 5                  #[default:number of logical CPUs] Number of concurrent threads used by aquatone web screenshot tool
aquatone_http_timeout=30000             #(milliseconds)[default: 3000] Timeout for HTTP requests
aquatone_scan_timeout=1000              #(milliseconds)[default: 100] Timeout for port scans
aquatone_screenshot_timeout=30000       #(milliseconds)[default: 30000] Timeout for screenshots
reports_assets_overview_max_procs=1 # 4 #(notaccurate , exec one proc more than specified) max procs to used while generating assets overview reports


masscan_rate=10000 # not using as it missed a lot of ports

# ================  configurations ends ==========

#set -o errexit # (a.k.a. set -e) to make your script exit when a command fails.  add || true to commands that you allow to fail.
#set -o nounset #(a.k.a. set -u) to exit when your script tries to use undeclared variables.
#set -o xtrace #(a.k.a set -x) to trace what gets executed. Useful for debugging (optional).
#set -o pipefail #in scripts to catch mysqldump fails in e.g. mysqldump |gzip. The exit status of the last command that threw a non-zero exit code is returned.

# trap ctrl-c and call ctrl_c()
trap ctrl_c INT

function ctrl_c() {
    echo -e $Yellow "[i]" $Red "Exiting abruptly .... :(" $Default
    exit
}


# \e[background;style;foregroundm
Black="\033[0;30m"
Red="\033[0;31m"
Green="\033[0;32m"
Yellow="\033[0;33m"
Blue="\033[0;34m"
Purple="\033[0;35m"
Cyan="\033[0;36m"
White="\033[0;37m"
Default="\033[0;m"

function show_usage(){
    echo -e $Cyan "\n\tUsage:" $Green "mr_sec_recon.sh <program name> <action>" $Default

    echo -e $Cyan "\n\tDetails:" $Green "<action> : start - execute the flow from begining irrespective of progress in flow of each domain" $Default
    echo -e $Cyan "\t        " $Green "         : resume - resume flow execution of each domain from previously halt" $Default

    echo -e $Cyan "\n\t        " $Green "1. when you run the tools for first time, project structure will be created. Then do following" $Default

    echo -e $Cyan "\t        " $Green "2.Fill <program name>/recon/root_domains/all_root_domains.txt with Top Level Domain Names." $Default

    echo -e $Cyan "\t        " $Green "3. Fill <program name>/inscope_patterns.txt with regex patterns that matches domains and subdomains in scope." $Default
    echo -e $Cyan"\t\t         " $Purple "If you have everything in scope fill this file with .* " $Default

    echo -e $Cyan "\t        " $Green "4. Fill <program name>/outscope_patterns.txt with regex patterns that matches domains and subdomains in scope." $Default
    echo -e $Cyan"\t\t         " $Purple "If you have nothing out of scope leave this file with empty" $Default

    echo -e $Cyan "\n\tExample:" $Green "mr_sec_recon.sh paypal start" $Default

    echo -e $Cyan "\n\tNote: " $Green "1. priority of execution flow of each domain depends on the order of appearence in all_root_domains.txt file" $Default
    echo -e $Cyan "\t      " $Green "2. flow will be in depth-first-order of root domains provided in all_root_domains.txt" $Default
    echo -e $Cyan "\t      " $Green "3. Make sure all the api-keys are working for better results" $Default
    echo -e $Cyan "\t      " $Green "4. If you find amass is using a lot of memery and time it might stuck with wildcard domains." $Default
    echo -e $Cyan "\t      " $Green "    In that case for specific domain use the next block progress code in proj_files/progress/<domain name>" $Default
}


if [[ ! $# -eq 2 ]]; then
    show_usage
    exit
fi

# ======== vpn connection check =========
echo -e $Purple
read -p " [+] Use VPN or VPS for not getting banned. Are you using any ? (y/n) " -n 1 -r
echo -e $Default
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[nN]$ ]]
then
    echo -e $Red "[-]" $Yellow "Sorry i won't let you run without using vpn or vps. If you wan't to run anyway Enter y on next run"
    exit
fi
# ======== vpn connection check done =========

program_name=$1
action_type=$2

cur_dir=$(pwd)

# ============= Building project structure =============
mkdir -p $cur_dir/$program_name
[[  ! -f $cur_dir/$program_name/inscope_patterns.txt ]] && touch $program_name/inscope_patterns.txt
[[  ! -f $cur_dir/$program_name/outscope_patterns.txt ]] && touch $program_name/outscope_patterns.txt

mkdir -p $cur_dir/$program_name/proj_files
mkdir -p $cur_dir/$program_name/proj_files/progress

mkdir -p $cur_dir/$program_name/burpsuite_data

mkdir -p $cur_dir/$program_name/notes
[[ ! -f $cur_dir/$program_name/notes/notes.md ]] && touch $cur_dir/$program_name/notes/notes.md
[[ ! -f $cur_dir/$program_name/notes/todo.md ]] && touch $cur_dir/$program_name/notes/todo.md
[[ ! -f $cur_dir/$program_name/notes/caution.md ]] && touch $cur_dir/$program_name/notes/caution.md

mkdir -p $cur_dir/$program_name/recon
mkdir -p $cur_dir/$program_name/recon/root_domains
[[  ! -f $cur_dir/$program_name/recon/root_domains/all_root_domains.txt ]] && touch $cur_dir/$program_name/recon/root_domains/all_root_domains.txt

mkdir -p $cur_dir/$program_name/recon/dns_resolvers

mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping/linked_and_js_discovery
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping/linked_and_js_discovery/burpsuite
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping/amass_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping/subfinder_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping/github-subdomains_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping/sonar_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping/tlsscanner_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping/sublist3r_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping/suip_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping/subdomains
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping/resolved_subdomains
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/scraping/resolved_subdomains/massdns_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/commonspeak_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/commonspeak_data/resolved_subdomains
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/commonspeak_data/resolved_subdomains/shuffledns_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/commonspeak_data/resolved_subdomains/massdns_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/dnsgen_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/dnsgen_data/subdomains
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/dnsgen_data/resolved_subdomains
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/dnsgen_data/resolved_subdomains/shuffledns_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/dnsgen_data/resolved_subdomains/massdns_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/resolved_subdomains
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/resolved_subdomains/massdns_data
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/resolved_subdomains/hostnames
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/resolved_subdomains/ipv4_addrs
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/resolved_subdomains/NXDOMAIN_with_valid_CNAME
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/inscoped_subdomains
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/tools_out
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/tools_out/scraping
mkdir -p $cur_dir/$program_name/recon/subdomain_enumeration/tools_out/scraping/amass_data

mkdir -p $cur_dir/$program_name/recon/data_scraping
mkdir -p $cur_dir/$program_name/recon/data_scraping/waybackurls_data
mkdir -p $cur_dir/$program_name/analysis
mkdir -p $cur_dir/$program_name/analysis/source_codea2enmod
mkdir -p $cur_dir/$program_name/analysis/web
mkdir -p $cur_dir/$program_name/analysis/web/aquatone_data
mkdir -p $cur_dir/$program_name/analysis/web/HTTP_Traceroute_data
mkdir -p $cur_dir/$program_name/analysis/web/fuzzing
mkdir -p $cur_dir/$program_name/analysis/ports
mkdir -p $cur_dir/$program_name/analysis/ports/httprobe_data
mkdir -p $cur_dir/$program_name/analysis/ports/masscan_data
mkdir -p $cur_dir/$program_name/analysis/ports/nmap_data

mkdir -p $cur_dir/$program_name/analysis/tools_out
mkdir -p $cur_dir/$program_name/analysis/tools_out/ports
mkdir -p $cur_dir/$program_name/analysis/tools_out/ports/nmap_data

mkdir -p $cur_dir/$program_name/vuln_identification
mkdir -p $cur_dir/$program_name/vuln_identification/subdomains_takeover
mkdir -p $cur_dir/$program_name/vuln_identification/subdomains_takeover/subjack_data
mkdir -p $cur_dir/$program_name/reports/
mkdir -p $cur_dir/$program_name/reports/assets_overview/
mkdir -p $cur_dir/$program_name/reports/assets_overview/root_domains
# ============= Done Building project structure =============

# ============= Check and init ===========
if [[ ! $action_type == "start" ]] && [[ !$action_type == "resume" ]]; then
    echo -e $Red " Invalid action !" $Default
    exit
fi

if [[ ! -s $cur_dir/$program_name/inscope_patterns.txt ]]; then
    echo -e $Red "[-]" $Purple "Fill ${cur_dir}/${program_name}/inscope_patterns.txt with regex patterns that matches domains and subdomains in scope." $Default
    echo -e $Red "[-]" $Purple "If you have everything in scope fill this file with .* " $Default
    exit
fi

if [[ ! -s $cur_dir/$program_name/recon/root_domains/all_root_domains.txt ]]; then
    echo -e $Red "[-]" $Purple "Fill ${cur_dir}/${program_name}/recon/root_domains/all_root_domains.txt with Top Level Domain Names." $Default
    exit
fi

all_root_domains_flie="${cur_dir}/${program_name}/recon/root_domains/all_root_domains.txt"
root_domains_flie=$all_root_domains_flie

if [[ $action_type == "start" ]]; then
    cat $root_domains_flie | xargs -I{} bash -c "echo 'started' > $cur_dir/$program_name/proj_files/progress/{}"
elif [[ $action_type == "resume" ]]; then
    for root_domain in $(cat $root_domains_flie); do
        [[ ! -f $cur_dir/$program_name/proj_files/progress/$root_domain ]] && echo "started" > $cur_dir/$program_name/proj_files/progress/$root_domain
    done
fi
# ============= Check and init done ===========


# ========== recon starts ============
## ======= generating root domain specific dns-resolvers ========
function recon_dns_resolvers(){
    cd $cur_dir/$program_name/recon/dns_resolvers
    local root_domain=$1
    echo -e $Green "[+]" $Purple "Generating dns resolvers specific to ${root_domain} ...." $Default
    python3 ~/tools/bass/bass.py -d ${root_domain} -o ./${root_domain}
}
## ======= generating root domain specific dns-resolvers ends ========
## ====== subdomain enumerations =======
### ===== subdomain scraping =======
function recon_subdomain_enum_linked_js_discovery(){
    cd $cur_dir/$program_name/recon/subdomain_enumeration/scraping/linked_and_js_discovery
    echo -e $Yellow "[M]" $Purple "Do Linked and Js discovery with Burp Suite V1 via spidering and fill files in $program_name/recon/subdomain_enumeration/scraping/linked_and_js_discovery/burp_suite/ while this script runs" $Default
    local root_domain
    for root_domain in $(cat $root_domains_flie); do
        [[ ! -f $cur_dir/$program_name/recon/subdomain_enumeration/scraping/linked_and_js_discovery/burpsuite/$root_domain ]] && touch $cur_dir/$program_name/recon/subdomain_enumeration/scraping/linked_and_js_discovery/burpsuite/$root_domain
    done
    echo "done"
}
function recon_subdomain_enum_scraping_amass(){
    cd $cur_dir/$program_name/recon/subdomain_enumeration/scraping
    local root_domain=$1
    echo -e $Green "[+]" $Purple "Scraping subdomains with amass (passive) ...." $Default

    #timeout $amass_enum_timeout unbuffer amass enum -d $root_domain -o ./amass_data/${root_domain}_new 2>&1 | tee ../tools_out/scraping/amass_data/$root_domain
    # TODO not using above as i am dns resolving later with massdns and uses project sonar dns dataset
    # so --pasive mode is enough
    unbuffer amass enum -d $root_domain --passive -o ./amass_data/${root_domain}_new 2>&1 >> ../tools_out/scraping/amass_data/$root_domain

    cat ./amass_data/${root_domain}_new >> ./amass_data/${root_domain}
    rm ./amass_data/${root_domain}_new
    sort -u -o ./amass_data/${root_domain} ./amass_data/${root_domain}

}
function recon_subdomain_enum_scraping_subfinder(){
    cd $cur_dir/$program_name/recon/subdomain_enumeration/scraping
    local root_domain=$1
    echo -e $Green "[+]" $Purple "Scraping subdomains with subfinder ...." $Default
    subfinder -d $root_domain -silent >> ./subfinder_data/$root_domain
    sort -u -o ./subfinder_data/$root_domain ./subfinder_data/$root_domain
}
function recon_subdomain_enum_scraping_github_subdomains(){
    cd $cur_dir/$program_name/recon/subdomain_enumeration/scraping
    local root_domain=$1
    echo -e $Green "[+]" $Purple "Scraping subdomains with github-subdomains ...." $Default
    python ~/tools/github-search/github-subdomains.py -d $root_domain >> ./github-subdomains_data/$root_domain
    sort -u -o ./github-subdomains_data/$root_domain ./github-subdomains_data/$root_domain
}
function recon_subdomain_enum_scraping_sonar(){
    cd $cur_dir/$program_name/recon/subdomain_enumeration/scraping
    local root_domain=$1
    echo -e $Green "[+]" $Purple "Scraping subdomains from project sonar dataset ...." $Default
    crobat-client -s $root_domain >> ./sonar_data/$root_domain;
    curl -s "https://dns.bufferover.run/dns?q=.$root_domain" | jq '.FDNS_A , .RDNS' | grep '"' | sed 's/"//g' | cut -d',' -f2 | sed 's/\*\.//'  >> ./sonar_data/$root_domain
    sort -u -o ./sonar_data/$root_domain ./sonar_data/$root_domain
}
function recon_subdomain_enum_scraping_tlsscanner(){
    cd $cur_dir/$program_name/recon/subdomain_enumeration/scraping
    local root_domain=$1
    echo -e $Green "[+]" $Purple "Scraping subdomains with tlsscanner ...." $Default
    curl -s "https://tls.bufferover.run/dns?q=.$root_domain" | jq '.Results' | grep '"' | sed 's/"//g' | cut -d',' -f3 | sed 's/\*\.//'  >> ./tlsscanner_data/$root_domain
    sort -u -o ./tlsscanner_data/$root_domain ./tlsscanner_data/$root_domain
}
function recon_subdomain_enum_scraping_sublist3r(){
    cd $cur_dir/$program_name/recon/subdomain_enumeration/scraping
    local root_domain=$1
    echo -e $Green "[+]" $Purple "Scraping subdomains with sublist3r ...." $Default
    python ~/tools/Sublist3r/sublist3r.py -d $root_domain -o ./sublist3r_data/${root_domain}_new >> /tmp/sublist3r_data_log
    cat ./sublist3r_data/${root_domain}_new >> sublist3r_data/$root_domain
    rm ./sublist3r_data/${root_domain}_new
    sort -u -o ./sublist3r_data/$root_domain ./sublist3r_data/$root_domain
}
function recon_subdomain_enum_scraping_suip(){
    cd $cur_dir/$program_name/recon/subdomain_enumeration/scraping
    local root_domain=$1
    echo -e $Green "[+]" $Purple "Scraping subdomains from suip.biz ...." $Default
    python ~/tools/owned/my-cyber-scripts/sudomains_gathering/subdomains_suip_biz.py -d $root_domain | sed 's/\"//g' >> ./suip_data/$root_domain
    sort -u -o ./suip_data/$root_domain ./suip_data/$root_domain
}
function recon_subdomain_enum_scraping_merge_resolve(){
    cd $cur_dir/$program_name/recon/subdomain_enumeration/scraping/
    local root_domain=$1
    echo -e $Green "[+]" $Purple "Merging Scraped subdomains ...." $Default
    cat ./linked_and_js_discovery/burpsuite/$root_domain >> ./subdomains/$root_domain
    cat ./amass_data/$root_domain >> ./subdomains/$root_domain
    cat ./subfinder_data/$root_domain >> ./subdomains/$root_domain
    cat ./github-subdomains_data/$root_domain >> ./subdomains/$root_domain
    cat ./sonar_data/$root_domain >> ./subdomains/$root_domain
    cat ./tlsscanner_data/$root_domain >> ./subdomains/$root_domain
    cat ./sublist3r_data/$root_domain >> ./subdomains/$root_domain
    cat ./suip_data/$root_domain >> ./subdomains/$root_domain
    sort -u -o ./subdomains/$root_domain ./subdomains/$root_domain

    echo -e $Green "[+]" $Purple "Resovling Scraped subdomains ...." $Default
    massdns -r $cur_dir/$program_name/recon/dns_resolvers/${root_domain} -s $massdns_concurrent_lookups_cnt -t A -o J --flush -w ./resolved_subdomains/massdns_data/${root_domain}_out ./subdomains/${root_domain}
    cat ./resolved_subdomains/massdns_data/${root_domain}_out | jq -crM ' . | select( .data.answers )' > ./resolved_subdomains/massdns_data/${root_domain}
    # TODO Uncommnet below after checking whether above works good
    #rm ./resolved_subdomains/massdns_data/${root_domain}


    #echo -e $Green "[+]" $Purple "Parsing hostnames ...." $Default
    #cat ./resolved_subdomains/massdns_data/$root_domain | awk '{print $1}' | sed 's/.$//' | sort -u > ./resolved_subdomains/hostnames/$root_domain
    #echo -e $Green "[+]" $Purple "Parsing Ipv4 addresses ...." $Default
    #cat ./resolved_subdomains/massdns_data/$root_domain | awk '{print $3}' | sort -u | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > ./resolved_subdomains/ipv4_addrs/$root_domain
    # TODO wildcard elimination (not accurate | removes a lot vaild once, like some same ip uses host header to server differenct content)
    #cat ./resolved_subdomains/massdns_data/${root_domain}_out | awk '{print $3}' | sort -u | while read part_3; do
    #    cat ./resolved_subdomains/massdns_data/${root_domain}_out | grep -m $wildcard_elimination_ptr_threshold $part_3 >> ./resolved_subdomains/massdns_data/$root_domain
    #done
    #sort -u -o ./resolved_subdomains/massdns_data/${root_domain} ./resolved_subdomains/massdns_data/${root_domain}
    # Done wildcard elimination
}
### ===== SUBDOMAIN SCRAPING ENDS =======
### ===== SUBDOMAIN BRUTEFORCE =======
function recon_subdomain_enum_bruteforcing_commonspeak(){
    local root_domain=$1
    cd $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/commonspeak_data
    echo -e $Green "[+]" $Purple "Bruteforcing subdomains using shuffledns with commonspeak2 subdomain wordlist .... " $Default
    shuffledns -v -d ${root_domain} -r $cur_dir/$program_name/recon/dns_resolvers/${root_domain} -t $massdns_concurrent_lookups_cnt -o ./resolved_subdomains/shuffledns_data/${root_domain} -w ~/dataSets/wordlists/commonspeak2-wordlists/subdomains/subdomains.txt
    massdns -r $cur_dir/$program_name/recon/dns_resolvers/${root_domain} -s $massdns_concurrent_lookups_cnt -t A -o J --flush -w ./resolved_subdomains/massdns_data/${root_domain} ./resolved_subdomains/shuffledns_data/${root_domain}
}
function recon_subdomain_enum_bruteforcing_dnsgen(){
    local root_domain=$1
    cd $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/dnsgen_data
    echo -e $Green "[+]" $Purple "Bruteforcing subdomains with dnsgen which generating combinations of already resolved subdomains ...." $Default
    cat $cur_dir/$program_name/recon/subdomain_enumeration/scraping/resolved_subdomains/massdns_data/${root_domain} \
        $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/commonspeak_data/resolved_subdomains/massdns_data/${root_domain} \
        | jq '.name' | sed 's/"//g' \
        | dnsgen - > ./sudomains/${root_domain}

    shuffledns -d ${root_domain} -r $cur_dir/$program_name/recon/dns_resolvers/${root_domain} \
               -t $massdns_concurrent_lookups_cnt -o ./resolved_subdomains/shuffledns_data/${root_domain} \
               -list ./subdomains/${root_domain}
    massdns -r $cur_dir/$program_name/recon/dns_resolvers/${root_domain} \
            -s $massdns_concurrent_lookups_cnt -t A -o J --flush \
            -w ./resolved_subdomains/massdns_data/${root_domain} ./resolved_subdomains/shuffledns_data/${root_domain}
}
### ===== SUBDOMAIN BRUTEFORCE ENDS =======

### ====== Merging and filtering all inscoped subdomains ============
function recon_subdomain_enum_merging_filtering_inscoped_sumdomains(){
    local root_domain=$1

    cd $cur_dir/$program_name/recon/subdomain_enumeration/resolved_subdomains
    echo -e $Green "[+]" $Purple "Merging all resolved subdomains ...." $Default
    cat $cur_dir/$program_name/recon/subdomain_enumeration/scraping/resolved_subdomains/massdns_data/${root_domain} > ./massdns_data/${root_domain}
    [[ -f $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/commonspeak_data/massdns_data/${root_domain} ]] \
      && cat $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/commonspeak_data/resolved_subdomains/massdns_data/${root_domain} >> ./massdns_data/${root_domain}
    [[ -f $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/dnsgen_data/resolved_subdomains/massdns_data/${root_domain} ]] \
      && cat $cur_dir/$program_name/recon/subdomain_enumeration/bruteforcing/dnsgen_data/resolved_subdomains/massdns_data/${root_domain} >> ./massdns_data/${root_domain}
    sort -u -o ./massdns_data/${root_domain} ./massdns_data/${root_domain}

    cat ./massdns_data/${root_domain} | jq -crM ' . | select( .status == "NXDOMAIN" ) | select ( .data.answers ) | .name' | sed 's/"//g' | sed 's/.$//' > ./NXDOMAIN_with_valid_CNAME/${root_domain}
    sort -u -o ./NXDOMAIN_with_valid_CNAME/${root_domain} ./NXDOMAIN_with_valid_CNAME/${root_domain}

    cat ./massdns_data/${root_domain} | jq -crM ' . | select( .status == "NOERROR" ) | select ( .data.answers ) | .name ' | sed 's/"//g' | sed 's/.$//' > ./hostnames/${root_domain}
    sort -u -o ./hostnames/${root_domain} ./hostnames/${root_domain}

    cat ./massdns_data/${root_domain} | jq -crM ' . | select( .status == "NOERROR" ) | select( .data.answers ) | .data.answers | .[] | select( .type == "A") | .data ' | sed 's/"//g' > ./ipv4_addrs/${root_domain}
    sort -u -o ./ipv4_addrs/${root_domain} ./ipv4_addrs/${root_domain}

    echo -e $Green "[+]" $Purple "Filtering inscoped subdomains ...." $Default
    cat ./hostnames/$root_domain | grep -h -f $cur_dir/$program_name/inscope_patterns.txt \
        | grep -h -v -f $cur_dir/$program_name/outscope_patterns.txt \
        > $cur_dir/$program_name/recon/subdomain_enumeration/inscoped_subdomains/$root_domain
    echo ${root_domain} >> $cur_dir/$program_name/recon/subdomain_enumeration/inscoped_subdomains/$root_domain  # as it is removed by inscoped filtering
    sort -u -o $cur_dir/$program_name/recon/subdomain_enumeration/inscoped_subdomains/$root_domain $cur_dir/$program_name/recon/subdomain_enumeration/inscoped_subdomains/$root_domain
    echo "done"
}
## ====== SUBDOMAIN ENUMERATIONS ENDS =======

## ====== Data scraping ========
function recon_data_scraping_waybackurls(){
    root_domain=$1
    cd $cur_dir/$program_name/recon/data_scraping/waybackurls_data
    echo -e $Green "[+]" $Purple "Scraping data with waybackurls ...." $Default
    VT_API_KEY="5aa8430678baabe4a74634fa62143b56bf3441b8a108739b2da3972bbcc5a7c7"
    # TODO even the domains that was not resolved now may have resolved before and may have data in waybackmachine
    # Think about it later
    cat $cur_dir/$program_name/analysis/ports/httprobe_data/$root_domain | waybackurls >> ./$root_domain
    sort -u -o ./$root_domain ./$root_domain
}
## ====== Data scraping ends ========
# ========== recon ends ============

# ========== analysis ============
## ========= web analysis =========
function analysis_reverse_proxy_checks(){
    root_domain=$1
    cd $cur_dir/$program_name/analysis/web/HTTP_Traceroute_data
    echo -e $Green "[+]" $Purple "Performing Reverse proxy checks with HTTP_Traceroute.py ...." $Default
    mkdir -p ./$root_domain
    cat $cur_dir/$program_name/recon/subdomain_enumeration/resolved_subdomains/hostnames/$root_domain | xargs -I{} --max-procs=$analysis_reverse_proxy_checks_max_procs bash -c "
        [[ -f ./${root_domain}/{} ]] && rm ./${root_domain}/{}
        python2 ~/tools/owned/my-cyber-scripts/networks/HTTP_Traceroute/HTTP-Traceroute.py -t {} -s https -p 443 >> ./${root_domain}/{}
        python2 ~/tools/owned/my-cyber-scripts/networks/HTTP_Traceroute/HTTP-Traceroute.py -t {} -s http -p 80 >> ./${root_domain}/{}
        "
    wait
    # you need to perform on both port 443, and 80
    # TODO not sure whether to perform on other ports and schemes
}
function analysis_web_aquatone(){
    root_domain=$1
    cd $cur_dir/$program_name/analysis/web/aquatone_data
    echo -e $Green "[+]" $Purple "Performing website scan with acquatone ...." $Default
    mkdir -p ./$root_domain
    # httprobe_data/$root_domain contians urls of alive host with 80 or 443 open
    cat $cur_dir/$program_name/analysis/ports/httprobe_data/$root_domain | aquatone -chrome-path $chromium_path -out ./$root_domain -threads $aquatone_threads -http-timeout $aquatone_http_timeout -scan-timeout $aquatone_scan_timeout -screenshot-timeout $aquatone_screenshot_timeout -silent
}
## ========= web analysis ends =========
## ========= port analysis =========
function analysis_ports_httprobe(){
    root_domain=$1
    cd $cur_dir/$program_name/analysis/ports/httprobe_data
    echo -e $Green "[+]" $Purple "Probing http ports(80,443) with httprobe ...." $Default
    cat $cur_dir/$program_name/recon/subdomain_enumeration/resolved_subdomains/hostnames/$root_domain | sort -u | httprobe -c $httprobe_concurrency_level -t $httprobe_timeout >> ./$root_domain
}
function analysis_ports_masscan(){
    # TODO i don't know why its not giving all the results , need to work on it later
    cd $cur_dir/$program_name/analysis/ports/masscan_data
    local root_domain=$1
    echo -e $Green "[+]" $Purple "Performing Port analysis with masscan ...." $Default
    sudo masscan -iL $cur_dir/$program_name/recon/subdomain_enumeration/resolved_subdomains/ipv4_addrs/$root_domain --rate $masscan_rate -p1-65535 -oL $root_domain
    # TODO need to effective use resume feature of masscan
}
function analysis_ports_nmap(){
    cd $cur_dir/$program_name/analysis/ports/nmap_data
    local root_domain=$1

    echo -e $Green "[+]" $Purple "Performing Port analysis with nmap ...." $Default
    local ip_addr
    for ip_addr in $(cat $cur_dir/$program_name/recon/subdomain_enumeration/resolved_subdomains/ipv4_addrs/${root_domain} ); do
        echo -e $Purple "[+]" $Yellow "Scanning $ip_addr ...." $Default
        if [[ "$action_type" == "resume" ]] && [[ -f ./$ip_addr ]]; then
            if grep -Fq "Nmap done" $ip_addr ;then
                #echo -e $Green "[+]" $Cyan "showing results of $ip_addr from previous scan ...." $Default
                #cat ./$ip_addr
                continue
            fi
        fi
        #sudo nmap -O -Pn -sTUV --top-ports 1000 -oN ./$ip_addr $ip_addr
        nmap --top-ports 1000 -sV -T3 -Pn -oN ./$ip_addr $ip_addr >> $cur_dir/$program_name/analysis/tools_out/ports/nmap_data/${root_domain}
    done
    #echo -e $Green "[+]" $Cyan "Unique port among the subdomains of $root_domain" $Default
    #cat ../*/* | grep -E "open|closed|filtered|unfiltered" | grep -v "ports" | awk '{print $1,$2,$3}' | sort -n | uniq -c
    #cat ./* | grep -E "open|closed|filtered|unfiltered" | grep -v "ports" | awk '{print $1,$2,$3}' | sort -n | uniq -c
}
## ========= port analysis ends =========
# ========== analysis done============

# ========== vulnerability identification ============
## ========= Subdomains takeover check =======
function vuln_identification_subdomain_takeover_subjack(){
    cd $cur_dir/$program_name/vuln_identification/subdomains_takeover
    local root_domain=$1
    echo -e $Green "[+]" $Purple "Checking subdomain takeover vulnerability with subjack .... " $Default
    subjack -a -ssl -t $subjack_threads -v -timeout $subjack_timeout -w $cur_dir/$program_name/recon/subdomain_enumeration/resolved_subdomains/hostnames/$root_domain -o ./subjack_data/${root_domain}.tmp > /tmp/subjack_data.log
    #echo -e $Purple "[+]" $Cyan "${root_domain}'s subdomains than can probably takeover :" $Default
    cat ./subjack_data/${root_domain}.tmp | grep -v "Not Vulnerable" | tee -a ./subjack_data/$root_domain
    subjack -a -ssl -t $subjack_threads -v -timeout $subjack_timeout -w $cur_dir/$program_name/recon/subdomain_enumeration/resolved_subdomains/NXDOMAIN_with_valid_CNAME/$root_domain -o ./subjack_data/${root_domain}.tmp >> /tmp/subjack_data.log
    cat ./subjack_data/${root_domain}.tmp | grep -v "Not Vulnerable" | tee -a ./subjack_data/$root_domain
    rm ./subjack_data/${root_domain}.tmp
    sort -u -o ./subjack_data/${root_domain} ./subjack_data/${root_domain}
}
## ========= Subdomains takeover check done =======
# ========== vulnerability identification done ============

# =========== Reports ===========
## =========== Reports of assets overview===============
function reports_assets_overview_subdomain(){
    cd "${cur_dir}/${program_name}/reports/assets_overview/root_domains/${1}"
    local sub_domain=$2
    echo -e $Green "[+]" $Yellow "Generating report for ${sub_domain} .... " $Default

    local subdomain_name_pattern=$(echo "$sub_domain" | sed 's/\./_/g')
    local http_screenshot_path=$(find "${cur_dir}/${program_name}/analysis/web/aquatone_data/${root_domain}/screenshots/" | awk /http__${subdomain_name_pattern}__.*/ )
    local https_screenshot_path=$(find "${cur_dir}/${program_name}/analysis/web/aquatone_data/${root_domain}/screenshots/" | awk /https__${subdomain_name_pattern}__.*/ )
    local http_response_headers_path=$(find "${cur_dir}/${program_name}/analysis/web/aquatone_data/${root_domain}/headers/" | awk /http__${subdomain_name_pattern}__.*/ )
    local https_response_headers_path=$(find "${cur_dir}/${program_name}/analysis/web/aquatone_data/${root_domain}/headers/" | awk /https__${subdomain_name_pattern}__.*/ )
    [[ -f ./${sub_domain}.html ]] && rm ./${sub_domain}.html
    echo "
        <html>
        <meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>
        <meta http-equiv='X-UA-Compatible' content='IE=edge'>
        <head>
            <title>assets overview of ${sub_domain}</title>
            <style>
                .status.fourhundred{color:#00a0fc}
                .status.redirect{color:#d0b200}
                .status.fivehundred{color:#DD4A68}
                .status.jackpot{color:#0dee00}
                .status.weird{color:#cc00fc}
                img{padding:2px;width:600px}
                img:hover{box-shadow:0 0 2px 1px rgba(0,140,186,.5)}
                pre{font-family:Inconsolata,monospace}
                pre{margin:0 0 20px}
                pre{overflow-x:auto}
                article,header,img{display:block}
                #wrapper:after,.blog-description:after,.clearfix:after{content:}
                .container{position:relative}
                html{line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}
                h1{margin:.67em 0}
                h1,h2{margin-bottom:20px}
                a{background-color:transparent;-webkit-text-decoration-skip:objects;text-decoration:none}
                .container,table{width:100%}
                .site-header{overflow:auto}
                .post-header,.post-title,.site-header,.site-title,h1,h2{text-transform:uppercase}
                p{line-height:1.5em}
                pre,table td{padding:10px}
                h2{padding-top:40px;font-weight:900}
                a{color:#00a0fc}
                body,html{height:100%}
                body{margin:0;background:#fefefe;color:#424242;font-family:Raleway,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,'Helvetica Neue',Arial,sans-serif;font-size:24px}
                h1{font-size:35px}
                h2{font-size:28px}
                p{margin:0 0 30px}
                pre{background:#f1f0ea;border:1px solid #dddbcc;border-radius:3px;font-size:16px}
                .row{display:flex}
                .column{flex:100%}
                table tbody>tr:nth-child(odd)>td,table tbody>tr:nth-child(odd)>th{background-color:#f7f7f3}
                table th{padding:0 10px 10px;text-align:left}
                .post-header,.post-title,.site-header{text-align:center}
                table tr{border-bottom:1px dotted #aeadad}
                ::selection{background:#fff5b8;color:#000;display:block}
                ::-moz-selection{background:#fff5b8;color:#000;display:block}
                .clearfix:after{display:table;clear:both}
                .container{max-width:100%}
                #wrapper{height:auto;min-height:100%;margin-bottom:-265px}
                #wrapper:after{display:block;height:265px}
                .site-header{padding:40px 0 0}
                .site-title{float:left;font-size:14px;font-weight:600;margin:0}
                .site-title a{float:left;background:#00a0fc;color:#fefefe;padding:5px 10px 6px}
                .post-container-left{width:49%;float:left;margin:auto}
                .post-container-right{width:49%;float:right;margin:auto}
                .post-header{border-bottom:1px solid #333;margin:0 0 50px;padding:0}
                .post-title{font-size:55px;font-weight:900;margin:15px 0}
                .blog-description{color:#aeadad;font-size:14px;font-weight:600;line-height:1;margin:25px 0 0;text-align:center}
                .single-post-container{margin-top:50px;padding-left:15px;padding-right:15px;box-sizing:border-box}
                body.dark{background-color:#1e2227;color:#fff}
                body.dark pre{background:#282c34}
                body.dark table tbody>tr:nth-child(odd)>td,body.dark table tbody>tr:nth-child(odd)>th{background:#282c34}
                table tbody>tr:nth-child(even)>th{background:#1e2227}
                input{font-family:Inconsolata,monospace}
                body.dark .status.redirect{color:#ecdb54}
                body.dark input{border:1px solid ;border-radius: 3px; background:#282c34;color: white}
                body.dark label{color:#f1f0ea}
                body.dark pre{color:#fff}
            </style>
            <script>
            document.addEventListener('DOMContentLoaded', (event) => {
              ((localStorage.getItem('mode') || 'dark') === 'dark') ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')
            })
            </script>

            <link rel='stylesheet' type='text/css' href='https://cdnjs.cloudflare.com/ajax/libs/material-design-lite/1.1.0/material.min.css'>
            <link rel='stylesheet' type='text/css' href='https://cdn.datatables.net/1.10.19/css/dataTables.material.min.css'>
            <script type='text/javascript' src='https://code.jquery.com/jquery-3.3.1.js'></script>
            <script type='text/javascript' charset='utf8' src='https://cdn.datatables.net/1.10.19/js/jquery.dataTables.js'></script>
            <script type='text/javascript' charset='utf8' src='https://cdn.datatables.net/1.10.19/js/dataTables.material.min.js'></script>
            <script>
                \$(document).ready( function () {
                    \$('#myTable').DataTable({
                        'paging':   true,
                        'ordering': true,
                        'info':     true,
                         'autoWidth': true,
                            'columns': [{ 'width': '5%' },{ 'width': '5%' },null],
                                'lengthMenu': [[10, 25, 50,100, -1], [10, 25, 50,100, 'All']],

                    });
                });
            </script>
        </head>
        <body class='dark'>
            <header class='site-header'>
                <div class='site-title'>
                    <p>
                        <a style='cursor: pointer' onclick='localStorage.setItem('mode', (localStorage.getItem('mode') || 'dark') === 'dark' ? 'bright' : 'dark'); localStorage.getItem('mode') === 'dark' ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')\' title=\'Switch to light or dark theme\'>🌓 Light|dark mode</a>
                    </p>
                </div>
            </header>
            <div id='wrapper'>
                <div id='container'>
                    <h1 class='post-title' itemprop='name headline'>
                        Assets overivew report for <a href='http://${sub_domain}' target='_blank'>${sub_domain}</a>
                    </h1>
                    <p class='blog-description'>
                        Generated by mr_sec_recon on $(date)
                    </p>
                    <div class='container single-post-container'>
                        <article class='post-container-left' itemscope='' itemtype='http://schema.org/BlogPosting'>
                            <header class='post-header'>
                            </header>
                            <div class='post-content clearfix' itemprop='articleBody'>
                                <h2>Content Discovery</h2>
                                <table id='myTable' class='stripe'>
                                    <thead>
                                        <tr>
                                            <th>Status Code</th>
                                            <th>Content-Length</th>
                                            <th>Url</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <!-- Need to add content after fuzzing -->
                                    <tbody>
                                </table>
                            </div>
                        </article>
                        <article class='post-container-right' itemscope='' itemtype='http://schema.org/BlogPosting'>
                            <header class='post-header'>
                            </header>
                            <div class='post-content clearfix' itemprop='articleBody'>
                                <h2>Screenshots</h2>
                                <pre style='max-height: 400px;overflow-y: scroll'>
                                    <div class='row'>
                                        <div class='column'>
                                            <span style='width: 100%;text-align: center; font-weight:bold'>
                                                Port 80
                                            </span>
                                            <a href='${http_screenshot_path}' target='_blank'>
                                                <img/src='${http_screenshot_path}'>
                                            </a>
                                        </div>
                                        <div class='column'>
                                            <span style='width: 100%;text-align: center; font-weight:bold'>
                                                Port 443
                                            </span>
                                            <a href='${https_screenshot_path}' target='_blank'>
                                                <img/src='${https_screenshot_path}'>
                                            </a>
                                        </div>
                                    </div>
                                </pre>

                                <h2>Response Headers</h2>
                                <pre style='max-height: 400px;overflow-y: scroll'>
                                    <div class='row'>
                                        <div class='column'>
                                            <span style='width: 100%;text-align: center; font-weight:bold'>
                                                Port 80
                                            </span>
                                            <pre>
                                            $([[ -f $http_response_headers_path ]] && cat $http_response_headers_path)
                                            <pre>
                                        </div>
                                        <div class='column'>
                                            <span style='width: 100%;text-align: center; font-weight:bold'>
                                                Port 443
                                            </span>
                                            <pre>
                                            $([[ -f $https_response_headers_path ]] && cat $https_response_headers_path)
                                            <pre>
                                        </div>
                                    </div>
                                </pre>

                                <h2>Dig Info</h2>
                                <pre style='max-height: 400px;overflow-y: scroll'>
                                    $(dig $sub_domain)
                                </pre>

                                <h2>Nmap Results</h2>
                                <pre style='max-height: 400px;overflow-y: scroll'>
                                " >> ./${sub_domain}.html

# TODO you can even get ip address from massdns_data
# i am still using this to verify if massdns misses any
    for ip_addr in  $(dig +noall +answer $sub_domain | awk '{print $5}' | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b"); do
        echo -e "=======================================" >> ./${sub_domain}.html
        echo -e "             $ip_addr                  " >> ./${sub_domain}.html
        echo -e "=======================================" >> ./${sub_domain}.html
        if [[ -f $cur_dir/$program_name/analysis/ports/nmap_data/$ip_addr ]]; then
            cat $cur_dir/$program_name/analysis/ports/nmap_data/$ip_addr >> ./${sub_domain}.html
        else
            echo -e "[-] Haven't scan it yet" >> ./${sub_domain}.html
        fi
        echo " " >> ./${sub_domain}.html
    done
    echo "                      </pre>
                            </div>
                        </article>
                    </div>
                </div>
            </div>
        </html>" >> ./${sub_domain}.html
}

function reports_assets_overview(){

    local root_domain=$1
    cd $cur_dir/$program_name/reports/assets_overview/root_domains
    mkdir -p $root_domain
    cd ./$root_domain
    echo -e $Green "[+]" $Purple "Generating reports on overivew of assets for visualisation .... " $Default
    for sub_domain_name in $(cat $cur_dir/$program_name/analysis/ports/httprobe_data/$root_domain | sed 's/http:\/\///g' |  sed 's/https:\/\///g' | sort -u) ; do
        reports_assets_overview_subdomain $root_domain $sub_domain_name &
        # allow only to execute $N jobs in parallel
        if [[ $(jobs -r -p | wc -l) -gt $reports_assets_overview_max_procs ]]; then
            # wait only for first job
            wait -n
        fi
    done
    # wait for pending jobs
    wait
    [[ -f ./${root_domain}_master.html ]] && rm ./${root_domain}_master.html
    echo "
        <html>
        <head>
            <meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>
            <meta http-equiv='X-UA-Compatible' content='IE=edge'>
            <title>Recon Report for ${root_domain}</title>
            <style>
                .status.redirect{color:#d0b200}
                .status.fivehundred{color:#DD4A68}
                .status.jackpot{color:#0dee00}
                img{padding:5px;width:360px}
                img:hover{box-shadow:0 0 2px 1px rgba(0,140,186,.5)}
                pre{font-family:Inconsolata,monospace}
                pre{margin:0 0 20px}
                pre{overflow-x:auto}
                article,header,img{display:block}
                #wrapper:after,.blog-description:after,.clearfix:after{content:}
                .container{position:relative}
                html{line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}
                h1{margin:.67em 0}
                h1,h2{margin-bottom:20px}
                a{background-color:transparent;-webkit-text-decoration-skip:objects;text-decoration:none}
                .container,table{width:100%}
                .site-header{overflow:auto}
                .post-header,.post-title,.site-header,.site-title,h1,h2{text-transform:uppercase}
                p{line-height:1.5em}
                pre,table td{padding:10px}
                h2{padding-top:40px;font-weight:900}
                a{color:#00a0fc}
                body,html{height:100%}
                body{margin:0;background:#fefefe;color:#424242;font-family:Raleway,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,'Helvetica Neue',Arial,sans-serif;font-size:24px}
                h1{font-size:35px}
                h2{font-size:28px}
                p{margin:0 0 30px}
                pre{background:#f1f0ea;border:1px solid #dddbcc;border-radius:3px;font-size:16px}
                .row{display:flex}
                .column{flex:100%}
                table tbody>tr:nth-child(odd)>td,table tbody>tr:nth-child(odd)>th{background-color:#f7f7f3}
                table th{padding:0 10px 10px;text-align:left}
                .post-header,.post-title,.site-header{text-align:center}
                table tr{border-bottom:1px dotted #aeadad}
                ::selection{background:#fff5b8;color:#000;display:block}
                ::-moz-selection{background:#fff5b8;color:#000;display:block}
                .clearfix:after{display:table;clear:both}
                .container{max-width:100%}
                #wrapper{height:auto;min-height:100%;margin-bottom:-265px}
                #wrapper:after{display:block;height:265px}
                .site-header{padding:40px 0 0}
                .site-title{float:left;font-size:14px;font-weight:600;margin:0}
                .site-title a{float:left;background:#00a0fc;color:#fefefe;padding:5px 10px 6px}
                .post-container-left{width:49%;float:left;margin:auto}
                .post-container-right{width:49%;float:right;margin:auto}
                .post-header{border-bottom:1px solid #333;margin:0 0 50px;padding:0}
                .post-title{font-size:55px;font-weight:900;margin:15px 0}
                .blog-description{color:#aeadad;font-size:14px;font-weight:600;line-height:1;margin:25px 0 0;text-align:center}
                .single-post-container{margin-top:50px;padding-left:15px;padding-right:15px;box-sizing:border-box}
                body.dark{background-color:#1e2227;color:#fff}
                body.dark pre{background:#282c34}
                body.dark table tbody>tr:nth-child(odd)>td,body.dark table tbody>tr:nth-child(odd)>th{background:#282c34}
                input{font-family:Inconsolata,monospace}
                body.dark .status.redirect{color:#ecdb54}
                body.dark input{border:1px solid ;border-radius: 3px; background:#282c34;color: white}
                body.dark label{color:#f1f0ea}
                body.dark pre{color:#fff}
            </style>
            <script>
                document.addEventListener('DOMContentLoaded', (event) => {
                  ((localStorage.getItem('mode') || 'dark') === 'dark') ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')
                })
            </script>

            <link rel='stylesheet' type='text/css' href='https://cdnjs.cloudflare.com/ajax/libs/material-design-lite/1.1.0/material.min.css'>
            <link rel='stylesheet' type='text/css' href='https://cdn.datatables.net/1.10.19/css/dataTables.material.min.css'>
            <script type='text/javascript' src='https://code.jquery.com/jquery-3.3.1.js'></script>
            <script type='text/javascript' charset='utf8' src='https://cdn.datatables.net/1.10.19/js/jquery.dataTables.js'></script>
            <script type='text/javascript' charset='utf8' src='https://cdn.datatables.net/1.10.19/js/dataTables.material.min.js'></script>
            <script>
                \$(document).ready( function () {
                    \$('#myTable').DataTable({
                        'paging':   true,
                        'ordering': true,
                        'info':     true,
                         'autoWidth': true,
                            'columns': [{ 'width': '5%' },{ 'width': '5%' },null],
                                'lengthMenu': [[10, 25, 50,100, -1], [10, 25, 50,100, 'All']],

                    });
                });
            </script>
        </head>

        <body class='dark'>
            <header class='site-header'>
                <div class='site-title'>
                    <p>
                        <a style='cursor: pointer' onclick='localStorage.setItem('mode', (localStorage.getItem('mode') || 'dark') === 'dark' ? 'bright' : 'dark'); localStorage.getItem('mode') === 'dark' ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')\' title=\'Switch to light or dark theme\'>🌓 Light|dark mode</a>
                    </p>
                </div>
            </header>

            <div id='wrapper'>
                <div id='container'>
                    <h1 class='post-title' itemprop='name headline'>
                        Assets overivew report for <a href='http://${root_domain}' target='_blank'>${root_domain}</a>
                    </h1>
                    <p class='blog-description'>
                        Generated by mr_sec_recon on $(date)
                    </p>
                    <div class='container single-post-container'>
                        <article class='post-container-left' itemscope='' itemtype='http://schema.org/BlogPosting'>
                            <header class='post-header'>
                            </header>
                            <div class='post-content clearfix' itemprop='articleBody'>
                                <h2>Total Scanned Subdomains</h2>
                                <table id='myTable' class='stripe'>
                                    <thead>
                                        <tr>
                                            <th>Subdomains</th>
                                           <!-- <th>Scanned Urls</th> -->
                                        </tr>
                                    </thead>
                                    <tbody> " >> ./${root_domain}_master.html

    for sub_domain_name in $( cat "${cur_dir}/${program_name}/analysis/ports/httprobe_data/${root_domain}" |  sed 's/\http\:\/\///g' |  sed 's/\https\:\/\///g' | sort -u ) ; do
        echo "                          <tr>
                                            <td><a href='${cur_dir}/${program_name}/reports/assets_overview/root_domains/${root_domain}/${sub_domain_name}.html' target='_blank'>${sub_domain_name}</a></td>
                                        <tr>
        " >> ./${root_domain}_master.html
    done

    echo "                           <tbody>
                                </table>
                                <div>
                                    <h2>Possible Subdomains Takeovers of ${root_domain}</h2></div>
                                    <pre>
                                        $(cat ${cur_dir}/${program_name}/vuln_identification/subdomains_takeover/subjack_data/${root_domain})
                                    </pre>

                                    <div>
                                        <h2>Wayback data</h2>
                                    </div>
                                    <table>
                                        <tbody>
    " >> ./${root_domain}_master.html

    [[ -f ${cur_dir}/${program_name}/recon/data_scraping/waybackurls_data/${root_domain} ]] && echo "
                                            <tr>
                                                <td><a href='${cur_dir}/${program_name}/recon/data_scraping/waybackurls_data/${root_domain}' target='_blank'>All Urls</a></td>
                                            </tr>
    " >> ./${root_domain}_master.html
    echo "
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </article>
                        <article class='post-container-right' itemscope='' itemtype='http://schema.org/BlogPosting'>
                            <header class='post-header'>
                            </header>
                            <div class='post-content clearfix' itemprop='articleBody'>
                                <h2><a href='${cur_dir}/${program_name}/analysis/web/aquatone_data/${root_domain}/aquatone_report.html' target='_blank'>View Aquatone Report</a> </h2>
                            </div>
                        </article>
                    </div>
                </div>
            </div>
        </body>
    " >> ./${root_domain}_master.html
}
## =========== Reports of assets overview ends===============
# =========== Reports ends ===========

# ============  Controlling the flow of execution ==========
for root_domain_name in $(cat $root_domains_flie); do
    echo ""
    echo -e $Green "[+]" $Cyan "$root_domain_name processing started ..! " $Default
    case "$(cat $cur_dir/$program_name/proj_files/progress/$root_domain_name)" in
        "started")
            echo "started" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            ;&
        "recon_dns_resolvers")
            echo "recon_dns_resolvers" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            recon_dns_resolvers $root_domain_name
            ;&
        "recon_subdomain_enum_linked_js_discovery")
            echo "recon_subdomain_enum_linked_js_discovery" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            recon_subdomain_enum_linked_js_discovery $root_domain_name
            ;&
        "recon_subdomain_enum_scraping_amass")
            echo "recon_subdomain_enum_scraping_amass" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            recon_subdomain_enum_scraping_amass $root_domain_name
            ;&
        "recon_subdomain_enum_scraping_subfinder")
            echo "recon_subdomain_enum_scraping_subfinder" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            recon_subdomain_enum_scraping_subfinder $root_domain_name
            ;&
        "recon_subdomain_enum_scraping_github_subdomains")
            echo "recon_subdomain_enum_scraping_github_subdomains" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            recon_subdomain_enum_scraping_github_subdomains $root_domain_name
            ;&
        "recon_subdomain_enum_scraping_sonar")
            echo "recon_subdomain_enum_scraping_sonar" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            recon_subdomain_enum_scraping_sonar $root_domain_name
            ;&
        "recon_subdomain_enum_scraping_tlsscanner")
            echo "recon_subdomain_enum_scraping_tlsscanner" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            recon_subdomain_enum_scraping_tlsscanner $root_domain_name
            ;&
        "recon_subdomain_enum_scraping_sublist3r")
            echo "recon_subdomain_enum_scraping_sublist3r" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            recon_subdomain_enum_scraping_sublist3r $root_domain_name
            ;&
        "recon_subdomain_enum_scraping_suip")
            echo "recon_subdomain_enum_scraping_suip" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            recon_subdomain_enum_scraping_suip $root_domain_name
            ;&
        "recon_subdomain_enum_scraping_merge_resolve")
            echo "recon_subdomain_enum_scraping_merge_resolve" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            recon_subdomain_enum_scraping_merge_resolve $root_domain_name
            ;&
        "recon_subdomain_enum_bruteforcing_commonspeak")
            echo "recon_subdomain_enum_bruteforcing_commonspeak" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            #recon_subdomain_enum_bruteforcing_commonspeak $root_domain_name
            ;&
        "recon_subdomain_enum_bruteforcing_dnsgen")
            echo "recon_subdomain_enum_bruteforcing_dnsgen" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            #recon_subdomain_enum_bruteforcing_dnsgen $root_domain_name
            ;&
        "recon_subdomain_enum_merging_filtering_inscoped_sumdomains")
            echo "recon_subdomain_enum_merging_filtering_inscoped_sumdomains" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            recon_subdomain_enum_merging_filtering_inscoped_sumdomains $root_domain_name
            ;&
        "vuln_identification_subdomain_takeover_subjack")
            echo "vuln_identification_subdomain_takeover_subjack" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            vuln_identification_subdomain_takeover_subjack $root_domain_name
            ;&
        "analysis_ports_httprobe")
            echo "analysis_ports_httprobe" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            analysis_ports_httprobe $root_domain_name
            ;&
        "analysis_reverse_proxy_checks")
            echo "analysis_reverse_proxy_checks" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            analysis_reverse_proxy_checks $root_domain_name
            ;&
        "analysis_web_aquatone")
            echo "analysis_web_aquatone" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            analysis_web_aquatone $root_domain_name
            ;&
        "recon_data_scraping_waybackurls")
            echo "recon_data_scraping_waybackurls" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            recon_data_scraping_waybackurls $root_domain_name
            ;&
        "analysis_ports_masscan")
            echo "analysis_ports_masscan" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            #analysis_ports_masscan $root_domain_name
            ;&
        "analysis_ports_nmap")
            echo "analysis_ports_nmap" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            #analysis_ports_nmap $root_domain_name
            ;&
        "reports_assets_overview")
            echo "reports_assets_overview" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            reports_assets_overview $root_domain_name
            ;&
        "finished")
            echo "finished" > $cur_dir/$program_name/proj_files/progress/$root_domain_name
            echo -e $Green "[+]" $Cyan "$root_domain_name processing finished ..! "
            ;;
    esac

done
# ============  Controlling the flow of execution ==========


# =========== Master report generation ===========

echo -e $Green "[+]" $Yellow "Generating Master Assets Overview Report for ${program_name} .... " $Default
cd ${cur_dir}/${program_name}/reports/assets_overview/
assets_overview_master_report_path="${cur_dir}/${program_name}/reports/assets_overview/assets_overview_master_report.html"
[[ -f $assets_overview_master_report_path ]] && rm $assets_overview_master_report_path

echo "
    <html>
    <head>
        <meta http-equiv='Content-Type' content='text/html; charset=UTF-8'>
        <meta http-equiv='X-UA-Compatible' content='IE=edge'>
        <title>Assets Overview report of ${program_name}</title>
        <style>
            .status.redirect{color:#d0b200}
            .status.fivehundred{color:#DD4A68}
            .status.jackpot{color:#0dee00}
            img{padding:5px;width:360px}
            img:hover{box-shadow:0 0 2px 1px rgba(0,140,186,.5)}
            pre{font-family:Inconsolata,monospace}
            pre{margin:0 0 20px}
            pre{overflow-x:auto}
            article,header,img{display:block}
            #wrapper:after,.blog-description:after,.clearfix:after{content:}
            .container{position:relative}
            html{line-height:1.15;-ms-text-size-adjust:100%;-webkit-text-size-adjust:100%}
            h1{margin:.67em 0}
            h1,h2{margin-bottom:20px}
            a{background-color:transparent;-webkit-text-decoration-skip:objects;text-decoration:none}
            .container,table{width:100%}
            .site-header{overflow:auto}
            .post-header,.post-title,.site-header,.site-title,h1,h2{text-transform:uppercase}
            p{line-height:1.5em}
            pre,table td{padding:10px}
            h2{padding-top:40px;font-weight:900}
            a{color:#00a0fc}
            body,html{height:100%}
            body{margin:0;background:#fefefe;color:#424242;font-family:Raleway,-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Oxygen,Ubuntu,'Helvetica Neue',Arial,sans-serif;font-size:24px}
            h1{font-size:35px}
            h2{font-size:28px}
            p{margin:0 0 30px}
            pre{background:#f1f0ea;border:1px solid #dddbcc;border-radius:3px;font-size:16px}
            .row{display:flex}
            .column{flex:100%}
            table tbody>tr:nth-child(odd)>td,table tbody>tr:nth-child(odd)>th{background-color:#f7f7f3}
            table th{padding:0 10px 10px;text-align:left}
            .post-header,.post-title,.site-header{text-align:center}
            table tr{border-bottom:1px dotted #aeadad}
            ::selection{background:#fff5b8;color:#000;display:block}
            ::-moz-selection{background:#fff5b8;color:#000;display:block}
            .clearfix:after{display:table;clear:both}
            .container{max-width:100%}
            #wrapper{height:auto;min-height:100%;margin-bottom:-265px}
            #wrapper:after{display:block;height:265px}
            .site-header{padding:40px 0 0}
            .site-title{float:left;font-size:14px;font-weight:600;margin:0}
            .site-title a{float:left;background:#00a0fc;color:#fefefe;padding:5px 10px 6px}
            .post-container-left{width:49%;float:left;margin:auto}
            .post-container-right{width:49%;float:right;margin:auto}
            .post-header{border-bottom:1px solid #333;margin:0 0 50px;padding:0}
            .post-title{font-size:55px;font-weight:900;margin:15px 0}
            .blog-description{color:#aeadad;font-size:14px;font-weight:600;line-height:1;margin:25px 0 0;text-align:center}
            .single-post-container{margin-top:50px;padding-left:15px;padding-right:15px;box-sizing:border-box}
            body.dark{background-color:#1e2227;color:#fff}
            body.dark pre{background:#282c34}
            body.dark table tbody>tr:nth-child(odd)>td,body.dark table tbody>tr:nth-child(odd)>th{background:#282c34}
            input{font-family:Inconsolata,monospace}
            body.dark .status.redirect{color:#ecdb54}
            body.dark input{border:1px solid ;border-radius: 3px; background:#282c34;color: white}
            body.dark label{color:#f1f0ea}
            body.dark pre{color:#fff}
        </style>
        <script>
            document.addEventListener('DOMContentLoaded', (event) => {
              ((localStorage.getItem('mode') || 'dark') === 'dark') ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')
            })
        </script>

        <link rel='stylesheet' type='text/css' href='https://cdnjs.cloudflare.com/ajax/libs/material-design-lite/1.1.0/material.min.css'>
        <link rel='stylesheet' type='text/css' href='https://cdn.datatables.net/1.10.19/css/dataTables.material.min.css'>
        <script type='text/javascript' src='https://code.jquery.com/jquery-3.3.1.js'></script>
        <script type='text/javascript' charset='utf8' src='https://cdn.datatables.net/1.10.19/js/jquery.dataTables.js'></script>
        <script type='text/javascript' charset='utf8' src='https://cdn.datatables.net/1.10.19/js/dataTables.material.min.js'></script>
        <script>
            \$(document).ready( function () {
                \$('#myTable').DataTable({
                    'paging':   true,
                    'ordering': true,
                    'info':     true,
                     'autoWidth': true,
                        'columns': [{ 'width': '5%' },{ 'width': '5%' },null],
                            'lengthMenu': [[10, 25, 50,100, -1], [10, 25, 50,100, 'All']],

                });
            });
        </script>
    </head>

    <body class='dark'>
        <header class='site-header'>
            <div class='site-title'>
                <p>
                    <a style='cursor: pointer' onclick='localStorage.setItem('mode', (localStorage.getItem('mode') || 'dark') === 'dark' ? 'bright' : 'dark'); localStorage.getItem('mode') === 'dark' ? document.querySelector('body').classList.add('dark') : document.querySelector('body').classList.remove('dark')\' title=\'Switch to light or dark theme\'>🌓 Light|dark mode</a>
                </p>
            </div>
        </header>

        <div id='wrapper'>
            <div id='container'>
                <h1 class='post-title' itemprop='name headline'>
                    Assets overivew report of ${program_name}
                </h1>
                <p class='blog-description'>
                    Generated by mr_sec_recon on $(date)
                </p>
                <div class='container single-post-container'>
                    <article class='post-container-left' itemscope='' itemtype='http://schema.org/BlogPosting'>
                        <header class='post-header'>
                        </header>
                        <div class='post-content clearfix' itemprop='articleBody'>
                            <h2>Scanned Root domains</h2>
                            <table id='myTable' class='stripe'>
                                <thead>
                                    <tr>
                                        <th>Root domains</th>
                                       <!-- <th>Scanned Urls</th> -->
                                    </tr>
                                </thead>
                                <tbody>

" >> $assets_overview_master_report_path

for root_domain_name in $( cat "${cur_dir}/${program_name}/recon/root_domains/all_root_domains.txt" ) ; do
    echo "                          <tr>
                                        <td><a href='${cur_dir}/${program_name}/reports/assets_overview/root_domains/${root_domain_name}/${root_domain_name}_master.html' target='_blank'>${root_domain_name}</a></td>
                                    <tr>
    " >> $assets_overview_master_report_path
done

echo "                           <tbody>
                            </table>
                            <div>
                                <h2>Possible Subdomains Takeovers of ${program_name}</h2></div>
                                <pre>
                                    $(cat ${cur_dir}/${program_name}/vuln_identification/subdomains_takeover/subjack_data/*)
                                </pre>

                            </div>
                        </div>
                    </article>
                    <article class='post-container-right' itemscope='' itemtype='http://schema.org/BlogPosting'>
                        <header class='post-header'>
                        </header>
                        <div class='post-content clearfix' itemprop='articleBody'>
                            <h2>Urls using Reverse proxy </h2>
                            <table id='myTable' class='stripe'>
                                <thead>
                                    <tr>
                                        <th>Subdomain</th>
                                        <th>Scanned Url</th>
                                    </tr>
                                </thead>
                                <tbody>
" >> $assets_overview_master_report_path

for scanned_url in $( grep -F "Found a reverse proxy" ${cur_dir}/${program_name}/analysis/web/HTTP_Traceroute_data/*/* -B 30 | grep -oE '(http|https)://.*/') ; do
    scanned_url_sub_domain_name=$(echo ${scanned_url} | awk -F/ '{print $3}' | awk -F: '{print $1}')
    scanned_url_sub_domain_report_path=$(find ${cur_dir}/${program_name}/reports/assets_overview/root_domains -path "*/${scanned_url_sub_domain_name}.html")
    echo "                          <tr>
                                        <td><a href='${scanned_url_sub_domain_report_path}' target='_blank'>${scanned_url_sub_domain_name}</a></td>
                                        <td><a href='${scanned_url}' target='_blannk'>${scanned_url}</a></td>
                                    <tr>
    " >> $assets_overview_master_report_path
done
echo "
                                </tbody>
                            </table>
                        </div>
                    </article>
                </div>
            </div>
        </div>
    </body>
" >> $assets_overview_master_report_path
# =========== Master report generation ends ===========
echo -e $Green "[*]" $Purple "Open Assets Overview Master Report ...."
xdg-open $assets_overview_master_report_path
