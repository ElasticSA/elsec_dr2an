**Please note the https://github.com/elastic/detection-rules/ now auto generates an att&ck navigator layer, so we will no longer be updating layers here for new Elastic Security releases**

The link [https://ela.st/tj-mitre-an] will now redirect to that auto generated layer. However these scripts will remain here for those that want to use them for their own purposes.

# Elastic Security: Detection Rules ATT&CK Navigator layer generator

Generate an ATT&CK Navigator (AN) [https://mitre-attack.github.io/attack-navigator/] dashboard layer.
Also contains pre-generated layers you can just use.

### Quick start!

*Just click on*: https://ela.st/tj-mitre-an

## Getting Started

### New Javascript version 

This script will grab the information from any running Kibana instance.

Steps:
 - cd into this project directory
 - run: `npm install` to get all dependancies
 - run: `node ./main.js -h`
 
Read the printed help on creating a JSON config file; we'll assume you named this file "config".

Note: You could also use npm to install elsec_dr2an as a shell command; here we'll just run the script from the project directory.

 - run: `node ./main.js ./config`
 

### Old Bash script

This script will grab the information from the detection rules github repository.
Ensure you have the following shell tools installed: jq, dasel (https://github.com/TomWright/dasel/releases), git, & bash v3+.

Run the script: .\gen_an_layer.sh > output.json

Navigate to https://mitre-attack.github.io/attack-navigator/ and chose "Open Existing Layer", 
click on "Upload from local" and select the generated file.

For just a specific rule type run: .\gen_an_layer.sh TYPE > output.json


## Installing

Copy the scripts to a target system and use as needed.

## Deployment

These scripts are for demonstration purposes only, they do not follow all production deployment
recommendations.

## Contributing

Get in touch with me.

## Versioning

No versioning of the script themselves, use as-is. They are writen in a way that they can be used with any post 7.x deployment.

## Authors

Thorben Jändling <<thorbenj@users.noreply.github.com>>

## License

AGPL 3

## Acknowledgments

Many colleagues at Elastic.co!
