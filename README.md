# Elastic Security: Detection Rules ATT&CK Navigator layer generator

Use the gen_an_layer.sh script to generate an ATT&CK Navigator (AN) [https://mitre-attack.github.io/attack-navigator/] dashboard layer

## Getting Started

Ensure you have the following shell tools installed: jq, dasel, & git

Run the script: .\gen_an_layer.sh > output.json

Navigate to https://mitre-attack.github.io/attack-navigator/ and chose "Open Existing Layer", 
click on "Upload from local" and select the generated file.

For just a specific rule type run: .\gen_an_layer.sh TYPE > output.json

### Quick start!

Use the already generated AN layer in this repository:


Navigate to https://mitre-attack.github.io/attack-navigator/ and chose "Open Existing Layer", 
In "Load from URL" paste: `https://raw.githubusercontent.com/ElasticSA/elsec_dr2an/master/last_export.json`

### Prerequisites

 - bash (v3+)
 - dasel: https://github.com/TomWright/dasel/releases
 - jq
 - git 

### Installing

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
