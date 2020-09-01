# YARA scanner
[![forthebadge](https://forthebadge.com/images/badges/you-didnt-ask-for-this.svg)](https://forthebadge.com)

## Context
The original goal of this program is to be launched from a cron job. This is why there is no command line interface, everything is provided in the config file. It definitely should be used in parallel with [Zeek](https://zeek.org/), as seen in this [Black Hat Talk](https://i.blackhat.com/USA-19/Wednesday/us-19-Bernal-Detecting-Malicious-Files-With-YARA-Rules-As-They-Traverse-the-Network-wp.pdf) from David Bernal.

## What it does
1. It parses config.json. You can provide the path to the config file in argument. Otherwise, it will look in its own folder.
2. It launches recursive YARA scan with given rules on the folder specified in config file.
3. If it detects some infected files, it sends a mail to the recipient provided in config file to warn him.
4. If the `mail.attachInfected` parameter is set to `true`, it will zip the infected files and attach infected_files.zip to the mail.
5. Once the mail is sent, and if the `quarantine.destroyInfectedFiles` parameter is set to `true`, it will wipe infected files.
6. Otherwise, if the `quarantine.enabled` value is set to `true`, it will move the infected files into the `quarantineDir` provided in config file.


## Config file example
```json
{
    "rulesPath": "/path/to/yara/rules",
    "filesDir": "/path/to/files/to/scan",
    "quarantine": {
        "enabled": true,
        "quarantineDir": "/path/to/quarantine/directory",
        "destroyInfectedFiles": false
    },
    "mail":{
        "smtpServ": "smtp.host.com",
        "smtpPort": "587",
        "from": "example@domain.com",
        "to": "example@domain.com",
        "password": "big-fat-pass",
        "subject": "YARA alert!",
        "nickname": "YARA feedback",
        "attachInfected": true,
        "maxAttachementSize": 10
    }
}
```
(see mock-config.json)

Note that if `quarantine.enabled` and `quarantine.destroyInfectedFiles` are both set to `true`, only `quarantine.destroyInfectedFiles` will be effective.

## Requirements
* YARA (https://yara.readthedocs.io/en/stable/gettingstarted.html)
* Go (https://golang.org/doc/install)

## Installation
1. Clone the github repo :
```
git clone https://github.com/eze-kiel/YARA-scanner.git
```
2. Go to the repo folder and build the binary :
```
cd YARA-scanner && go build .
```
3. Rename mock-config.json to config.json :
```
mv mock-config.json config.json
```

## Demo
```
$ go run .
- rules file found: php_script_in_image.yara
- rules file found: pictures.yara
INFO[0000] Found 2 rule(s) in /home/ezekiel/lab/yara/rules 
WARN[0000] 4 alert(s) raised by YARA in /home/ezekiel/lab/yara/samples : 
[!] php_script_in_image triggered by /home/ezekiel/lab/yara/samples/embeded_script.png
[!] png triggered by /home/ezekiel/lab/yara/samples/online_package_tracking.png
[!] jpeg triggered by /home/ezekiel/lab/yara/samples/flag.jpg
[!] png triggered by /home/ezekiel/lab/yara/samples/embeded_script.png
INFO[0000] Scan duration: 13.679548ms                   
INFO[0000] Zipped File: infected_files.zip              
INFO[0003] Report sent by mail to example@domain.com
```
In the mailbox :
```
4 alert(s) raised by YARA scan on 01/09/2020 10:16:56

-- REPORT --

rule triggered:file infected

php_script_in_image:/home/ezekiel/lab/yara/samples/embeded_script.png

png:/home/ezekiel/lab/yara/samples/online_package_tracking.png

jpeg:/home/ezekiel/lab/yara/samples/flag.jpg

png:/home/ezekiel/lab/yara/samples/embeded_script.png

-- END --

<!> Please be careful when opening the attachement
```

## Security notes
* You are playing with infected files. Be careful if you decide to open them on your machine.
