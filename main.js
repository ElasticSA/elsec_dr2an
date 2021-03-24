#!/usr/bin/env node

const co = require('co');
const prompt = require('co-prompt');
const program = require('commander');
const req = require('superagent');
const fs = require('fs');
const uuidb64 = require('uuid-base64');


var manav = {
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
    "techniques": [],
    "legendItems": [],
    "gradient": {
            "colors": [
                    "#bbffdd",
                    "#44ff66"
            ],
            "minValue": 0,
            "maxValue": 20
    },
    "showTacticRowBackground": true,
    "tacticRowBackground": "#bbddff",
    "selectTechniquesAcrossTactics": false,
    "selectSubtechniquesWithParent": false
}

var dr_types = {
    "eql": {
        "colour": '#fa744e',
        "label": "EQL Rule"
    },
    "machine_learning": {
        "colour": '#0077cc',
        "label": "ML Rule"
    },
    "query": {
        "colour": '#54bcb2',
        "label": "Query Rule"
    },
    "threshold": {
        "colour": '#fec514',
        "label": "Threshold"
    }
}
    
program
    .arguments('<file>')
//    .option('-u, --username <username>', 'The user to authenticate as')
//    .option('-p, --password <password>', 'The user\'s password')
    .action(function(file) {
        
        var creds = JSON.parse(fs.readFileSync(file))
        
        co(function *() {
            console.error('Hello, world!')
//            var username = yield prompt('username: ');
//            var password = yield prompt.password('password: ');
//            console.error('user: %s pass: %s file: %s',
//                //program.username, program.password, file);
//                username, password, file);
            var page = 1
            var total = 1
            var maxscore = manav.gradient.maxValue
            
            while ( (page-1)*100 < total) {
                var res = yield req
                    .get(`${creds.url}/s/security/api/alerts/_find?per_page=100&page=${page}&search_fields=consumer&search=siem`)
                    .set("kbn-xsrf", "true")
                    .auth(creds.un, creds.pw)
                    .accept('json')

                console.error(`Page(${page}) Total(${res.body.total})`)
                
                res.body.data.forEach(dr => {
                    
                    console.error(`Rule Name(${dr.name}) ID(${dr.id}) Type(${dr.params.type})`)
                    
                    var srid = uuidb64.encode(dr.params.ruleId)
                    
                    dr.params.threat.forEach( threat => {
                        
                        if (threat.framework != "MITRE ATT&CK") return
                        console.error("^ Has MITRE ATT&CK info")
                        
                        if (threat.technique === undefined) return
                        threat.technique.forEach( techn => {
                            
                            var mantq = manav.techniques.find(o => o.techniqueID == techn.id)
                            if (mantq === undefined) {
                                mantq = {
                                    "techniqueID": techn.id,
//                                     "comment": "Showing at least one example detection rules:",
                                    "enabled": true,
                                    "metadata": [],
                                    "score": 1
                                }
                                manav.techniques.push(mantq)
                            } 
                            else {
                                mantq.score += 1
                                if (mantq.score > maxscore) maxscore = mantq.score
                            }
                            
                            mantq.metadata.push({
                                "name": dr_types[dr.params.type].label,
                                "value": `${dr.name} (${srid})`
                            })
                            
                            // very ugly repetition
                            if (techn.subtechnique === undefined) return
                            techn.subtechnique.forEach( subtn => {
                                var manstq = manav.techniques.find(o => o.techniqueID == subtn.id)
                                if (manstq === undefined) {
                                    manstq = {
                                        "techniqueID": subtn.id,
    //                                     "comment": "Showing at least one example detection rules:",
                                        "enabled": true,
                                        "metadata": [],
                                        "score": 1
                                    }
                                    manav.techniques.push(manstq)
                                } 
                                else {
                                    manstq.score += 1
                                    if (manstq.score > maxscore) maxscore = manstq.score
                                }
                                
                                manstq.metadata.push({
                                    "name": dr_types[dr.params.type].label,
                                    "value": `${dr.name} (${srid})`
                                })
                            })
                        })
                    })
                })
                
                page+=1
                total = res.body.total
                

            }
            
            manav.gradient.maxValue = maxscore
            
            console.log(JSON.stringify(manav, null, 4))
            
        })
    })
    .parse(process.argv);
    
