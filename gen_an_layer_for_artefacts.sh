#!/bin/bash

# !!! You will need this tool in your $PATH !!!
# https://github.com/TomWright/dasel/releases

COLOUR_eql='#fa744e'
COLOUR_machine_learning='#0077cc'
COLOUR_query='#54bcb2'
COLOUR_threshold='#fec514'
COLOUR_default='#44FF88'

# Test that programmes we are going to use are installed
for c in dasel jq git; do
    if [ ! -x "$(which $c)" ]; then
        echo "Programme '$c' appears to be missing" >&2
        exit 1
    fi
done

# first arg points to protections-artifacts that you need to check it out yourself
cd $1 || exit 1

# DEBUG_TID=T1055
NL=$'\n'

debug()
{
    return 0
    echo -e "DEBUG[$@]" >&2
}

get_info()
{
    dasel select -f "$PWD/$1" -p toml -n -c -s "$2" | tr -d '\n'
}

get_list()
{
    dasel select -f "$PWD/$1" -p toml -n -c -m "$2.-"
}

get_array()
{
    dasel select -f "$PWD/$1" -p toml -n -c -m "$2.[*]"
}

SEEN_TID=''
add_seen_tid()
{
    case "$SEEN_TID" in
        *$1*)
            return
        ;;
    esac
    SEEN_TID="$1 $SEEN_TID"
}

add_info2tid()
{
    ITEM="TINFO_${1//\./_}"
    
debug "1($1) 2($2) 3($3)"

    local NEW="{\"name\": $(echo -n "$2" | jq -Rs), \"value\": $(echo -n "$3" | jq -Rs)}"

    if [ -z "${!ITEM}" ]; then
        printf -v "$ITEM" "%s" "$NEW"
    else
        printf -v "$ITEM" "%s" "${!ITEM},$NL$NEW"
    fi
    
    if [ "$1" = "$DEBUG_TID" ]; then
        echo "~~~" >&2
        echo "$3" >&2
        echo "${!ITEM}" >&2
        echo "~~~" >&2
    fi
}


iter=""
for dr in behavior/rules/*toml; do

    for rt in $(get_list "$dr" 'threat'); do

        FW=$(get_info "$dr" "threat.[$rt].framework")
        echo "Framework=$FW Name=$(get_info "$dr" rule.name) ($dr)" >&2

        if [ 0 -ne $? -o "$FW" != 'MITRE ATT&CK' ]; then
            echo "SKIPPING: $dr (Not under MITRE ATT&CK framework" >&2
            continue
        fi 
        
        TID=$(get_info "$dr" "threat.[$rt].technique.[0].subtechnique.[0].id")
        if [ "$TID" = 'null' ]; then
            TID=$(get_info "$dr" "threat.[$rt].technique.[0].id")
        fi
        if [ "$TID" = 'null' ]; then
            continue
        fi
        
        add_seen_tid "$TID"
        
        for os in $(get_array "$dr" 'rule.os_list'); do

            DESC="$(get_info "$dr" "rule.name")" #:${NL}$(get_info "$dr" "rule.description")"
debug "os($os) desc($DESC)"
            add_info2tid "$TID" "$os" "$DESC"

        done
        
    done
    
    iter="${iter}."
    if [ "$ELDR2AN" = "quick" -a "$iter" = "................." ]; then
        break;
    fi
    if [ "$ELDR2AN" = "direct" -a "$TID" = "$DEBUG_TID" ]; then
        break;
    fi
done


echo "--- SEEN $SEEN_TID ---" >&2

cat <<_EOM_
{
    "name": "El.Sec. Endpoint Artefacts",
    "versions": {
        "attack": "11",
        "navigator": "4.3",
        "layer": "4.3"
    },
    "domain": "enterprise-attack",
    "description": "Mapping Elastic Endpoint Secrity Aretfact Rules to ATTACK Navigator",
    "filters": {
        "platforms": [
            "Windows",
            "macOS",
            "Linux"
        ]
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "showName": true,
        "showID": true
    },
    "hideDisabled": false,
    "techniques": [
_EOM_

comma=""
for TID in $SEEN_TID ; do
    ITEM="TINFO_${TID//\./_}"
    echo "--- $TID  ($ITEM) ---" >&2
    if [ "$TID" = "$DEBUG_TID" ]; then
        echo "${!ITEM}" >&2
        echo "${!ITEM}" | wc  >&2
    fi
    
#         COLOUR="COLOUR_$RT"
#         if [ -z "${!COLOUR}" ]; then
        COLOUR='COLOUR_default'
#         fi
    
    
    cat <<_EOM_
    $comma
    {
        "techniqueID": "$TID",
        "color": "${!COLOUR}",
        "enabled": true,
        "score": $(echo "${!ITEM}" | wc -l),
        "metadata": [
${!ITEM}
        ]
    }
_EOM_
#         "comment": "Showing at least one example endpoint rules:",
    #			"showSubtechniques": false
    #			"score": 1,
    #			"tactic": $(get_info "$dr" 'rule.threat.[0].tactic.name'),

    comma=","
        
done


cat <<_EOM_
    ],
    "legendItems": [
    ],
    "showTacticRowBackground": true,
    "tacticRowBackground": "#bbddff",
    "selectTechniquesAcrossTactics": false,
    "selectSubtechniquesWithParent": false
}
_EOM_


#         {
#             "label": "No Detction Rule taged with this Technique",
#             "color": "#FFFFFF"
#         },
#         {
#             "label": "EQL rule: https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html",
#             "color": "${COLOUR_eql}"
#         },
#         {
#             "label": "Query/KQL rule: https://www.elastic.co/guide/en/kibana/current/kuery-query.html",
#             "color": "${COLOUR_query}"
#         },
#         {
#             "label": "Machine Learning rule: https://www.elastic.co/guide/en/security/current/machine-learning.html",
#             "color": "${COLOUR_machine_learning}"
#         },
#         {
#             "label": "Threshold rule",
#             "color": "${COLOUR_threshold}"
#         }
