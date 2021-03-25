#!/usr/bin/env node

const co = require('co');
const prompt = require('co-prompt');
const program = require('commander');
const req = require('superagent');
const fs = require('fs');
const uuidb64 = require('uuid-base64');


var ma_nav_templ = {
    "name": "Elastic Security: ",
    "versions": {
        "attack": "8",
        "navigator": "4.2",
        "layer": "4.1"
    },
    "domain": "enterprise-attack",
    "description": "Mapping Elastic Secrity (https://www.elastic.co/security) Detection Rules to MITRE ATT&CK Navigator",
    "filters": {
    },
    "sorting": 0,
    "layout": {
        "layout": "side",
        "showName": true,
        "showID": true
    },
    "hideDisabled": false,
//     "techniques": [],
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
    "selectSubtechniquesWithParent": false,
    "metadata": [
        {
                "name": "Elastic version",
                "value": "7.x"
        }
    ],
}

var ma_nav = {
    "All": { ...ma_nav_templ }
}
ma_nav.All.techniques = []

var dr_types = {
    "eql": {
        "colour": '#fa744e',
        "label": "EQL"
    },
    "machine_learning": {
        "colour": '#0077cc',
        "label": "ML"
    },
    "query": {
        "colour": '#54bcb2',
        "label": "Query"
    },
    "threshold": {
        "colour": '#fec514',
        "label": "Threshold"
    }
}

var valid_tag = /^[A-Za-z0-9 ]+$/

function update_entry(layer, dr, techn)
{
    var mantq = layer.techniques.find(o => o.techniqueID == techn.id)
    if (mantq === undefined) {
        mantq = {
            "techniqueID": techn.id,
            "enabled": true,
            "metadata": [],
            "score": 1,
        }
        layer.techniques.push(mantq)
    } 
    else {
        mantq.score += 1
        if (mantq.score > layer.gradient.maxValue)
                layer.gradient.maxValue = mantq.score
    }

    mantq.metadata.push({
        "name": `${dr_types[dr.params.type].label} / ${dr.params.severity}`,
        //"value": `${dr.name} (${srid})`
        "value": `${dr.name} (${dr.params.riskScore})`
    })
}

function update_layer(name, dr, techn)
{
    var layer = ma_nav[name]
    if (layer === undefined) {
        layer = { ...ma_nav_templ }
        layer.name += name
        layer.techniques = []
        ma_nav[name] = layer
    }
    
    update_entry(layer, dr, techn)
}
    
program
    .arguments('<file>')
//    .option('-u, --username <username>', 'The user to authenticate as')
//    .option('-p, --password <password>', 'The user\'s password')
    .action(function(file) {
        
        var conf = JSON.parse(fs.readFileSync(file))
        
        co(function *() {
            console.error('Hello, world!')
//            var username = yield prompt('username: ');
//            var password = yield prompt.password('password: ');
//            console.error('user: %s pass: %s file: %s',
//                //program.username, program.password, file);
//                username, password, file);
            
            var knstatus = yield req
                    .get(`${conf.url}/api/status`)
                    .set("kbn-xsrf", "true")
                    .auth(conf.un, conf.pw)
                    .accept('json')
                    
            ma_nav_templ.metadata.find(o => o.name == "Elastic version").value = knstatus.body.version.number
            
            var page = 1
            var total = 1

            var kn_api = "/api"
            if (conf.space) kn_api = `/s/${conf.space}/api`
        
            while ( (page-1)*100 < total) {
                var res = yield req
                    .get(`${conf.url}${kn_api}/alerts/_find?per_page=100&page=${page}&search_fields=consumer&search=siem`)
                    .set("kbn-xsrf", "true")
                    .auth(conf.un, conf.pw)
                    .accept('json')

                console.error(`Page(${page}) Total(${res.body.total})`)
                
                res.body.data.forEach(dr => {
                    
                    //To shorten the ID to 22 chars
                    var srid = uuidb64.encode(dr.params.ruleId)
                    console.error(`Rule Name(${dr.name}) ID(${dr.id} -> ${srid}) Type(${dr.params.type})`)
                    
                    dr.params.threat.forEach( threat => {
                        
                        if (threat.framework != "MITRE ATT&CK") return
                        console.error("^ Has MITRE ATT&CK info")
                        
                        if (threat.technique === undefined) return
                        threat.technique.forEach( techn => {
                            
                            update_entry(ma_nav.All, dr, techn)
                            
                            dr.tags.forEach(tag => {
                                if (! valid_tag.exec(tag)) return
                                    
                                update_layer(tag, dr, techn)
                            })
                            
                            if (techn.subtechnique === undefined) return
                            techn.subtechnique.forEach( subtn => {
                                update_entry(ma_nav.All, dr, subtn)
                            })
                        })
                    })
                })
                
                page+=1
                total = res.body.total
                
            }
            
            //console.log(JSON.stringify(ma_nav, null, 4))
            var layers = Object.keys(ma_nav);
            var out_dir = conf.out_dir || "./layers"
            
            console.log(layers)
            layers.forEach( name => {
                fs.writeFileSync(`${out_dir}/${name}.json`, JSON.stringify(ma_nav[name], null, 2))
            })
            
            
        })
    })
    .addHelpText('after', `

The file argument is a JSON configuration file in the format:
{
    "url": "https://kibana.exmaple.com",
    "un": "elastic",
    "pw": "password",
    "space": "security"
}

The 'space' key is optional, the others are not.
`)
    .parse(process.argv);
    
