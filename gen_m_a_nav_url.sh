#!/bin/bash

# Either copy/paste the TopX list from elsec_dr2an
# run: ls -1 layers/ | ./gen_m_a_nav_url.sh

# Credit to https://gist.github.com/cdown/1163649
urlencode() {
    # urlencode <string>

    old_lc_collate=$LC_COLLATE
    LC_COLLATE=C

    local length="${#1}"
    for (( i = 0; i < length; i++ )); do
        local c="${1:$i:1}"
        case $c in
            [a-zA-Z0-9.~_-]) printf '%s' "$c" ;;
            *) printf '%%%02X' "'$c" ;;
        esac
    done

    LC_COLLATE=$old_lc_collate
}

urldecode() {
    # urldecode <string>

    local url_encoded="${1//+/ }"
    printf '%b' "${url_encoded//%/\\x}"
}

M_A_NAV="https://mitre-attack.github.io/attack-navigator/"

GH_PATH="https://raw.githubusercontent.com/ElasticSA/elsec_dr2an/master/layers/"

URL="${M_A_NAV}#layerURL=$(urlencode "${GH_PATH}All.json")"

while read jf; do 

    if [ -z "$jf" ]; then
        break
    fi
    
    # Force all first and Elastic last in list
    if [ 'All.json' = "$jf" -o 'Elastic.json' = "$jf" ]; then
        continue
    fi
    
    echo ">>> $jf <<<" >&2
    URL="${URL}&layerURL=$(urlencode "${GH_PATH}${jf%.json}.json")"

done

URL="${URL}&layerURL=$(urlencode "${GH_PATH}Elastic.json")"

echo $URL
