#!/bin/bash

# !!! You will need this tool in your $PATH !!!
# https://github.com/TomWright/dasel/releases

ELDR_URL=https://github.com/elastic/detection-rules.git

# Test that programmes we are going to use are installed
for c in dasel jq git; do
  test -x "$(which $c)" || _fail "Programme '$c' appears to be missing"
done

if [ -d detection-rules ]; then
    cd detection-rules
    git fetch  >&2
    git reset --hard  >&2
    git pull  >&2
    cd ..
else
    git clone $ELDR_URL  >&2
fi

cd detection-rules/rules

get_info()
{
    dasel select -f "$PWD/$1" -p toml -n -c -s "$2" | tr -d '\n' | jq -Rs
}

cat <<_EOM_
{
    "name": "Elastic Security",
    "versions": {
        "attack": "8",
        "navigator": "4.2",
        "layer": "4.1"
    },
    "domain": "enterprise-attack",
    "description": "Mapping Elastic Secrity Detection Rules (https://github.com/elastic/detection-rules) to ATTACK Navigator",
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

iter=""
comma=""
for dr in */*toml; do

    FW=$(get_info "$dr" 'rule.threat.[0].framework')
    echo "Framework=$FW Name=$(get_info "$dr" rule.name)" >&2

    if [ 0 -ne $? -o "$FW" != '"MITRE ATT&CK"' ]; then
        echo "SKIPPING: $dr (Not under MITRE ATT&CK framework" >&2
        continue
    fi 
    
    cat <<_EOM_
        $comma
        {
			"techniqueID": $(get_info "$dr" 'rule.threat.[0].technique.[0].id'),
			"color": "#11ff33",
			"comment": $(get_info "$dr" "rule.description" ),
			"enabled": true,
			"metadata": [
                {"name": "Rule name", "value": $(get_info "$dr" "rule.name")},
                {"name": "Rule type", "value": $(get_info "$dr" "rule.type")},
                {"name": "Rule tags", "value": $(get_info "$dr" "rule.tags")}
			]
        }
_EOM_
#			"showSubtechniques": false
#			"score": 1,
#			"tactic": $(get_info "$dr" 'rule.threat.[0].tactic.name'),

    comma=","
    iter="${iter}."
    
    if [ "$ELDR2AN" = "quick" -a "$iter" = ".........................." ]; then
        break;
    fi
    
done

cat <<_EOM_
    ],
    "showTacticRowBackground": true,
    "tacticRowBackground": "#bbddff",
    "selectTechniquesAcrossTactics": false,
    "selectSubtechniquesWithParent": false
}
_EOM_
