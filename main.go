package main

import (
	"fmt"
	"net/smtp"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/domodwyer/mailyak"
	"github.com/logrusorgru/aurora"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/viper"
)

type smtpServer struct {
	host string
	port string
}

type scanReport struct {
	numOfAlerts    int
	rulesTriggered []string
	filesInfected  []string
}

type mailHeaders struct {
	from                 string
	to                   string
	password             string
	subject              string
	nickname             string
	server               string
	port                 string
	attachFiles          bool
	attachedFilesMaxSize int64
}

func main() {
	// read config file
	viper.SetConfigName("config")
	viper.SetConfigType("json")
	// check if config file path is given in args
	if len(os.Args) > 1 {
		viper.AddConfigPath(os.Args[1])
	}
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		log.Errorf("Error reading config file: %s", err)
	}

	rulesPath := viper.GetString("rulesPath")
	filesDir := viper.GetString("filesDir")
	quarantine := viper.Sub("quarantine")
	mailInfos := viper.Sub("mail")

	mail := mailHeaders{
		server:               mailInfos.GetString("smtpServ"),
		port:                 mailInfos.GetString("smtpPort"),
		from:                 mailInfos.GetString("from"),
		to:                   mailInfos.GetString("to"),
		password:             mailInfos.GetString("password"),
		subject:              mailInfos.GetString("subject"),
		nickname:             mailInfos.GetString("nickname"),
		attachFiles:          mailInfos.GetBool("attachInfected"),
		attachedFilesMaxSize: mailInfos.GetInt64("maxAttachementSize"),
	}

	// get a list of rules files from given path
	rulesList, err := GetRulesList(rulesPath)
	if err != nil {
		log.Warnf("Error executing command: %s", err)
	}
	log.Infof("Found %d rule(s) in %s", len(rulesList), rulesPath)

	// start execution timer
	start := time.Now()

	// execute YARA scan with given rule list
	warningList, err := executeYARAScan(rulesList, rulesPath, filesDir)
	if err != nil {
		log.Fatalf("Error while executing YARA scan: %s", err)
	}

	// end execution timer
	elapsed := time.Since(start)
	log.Warnf("%d alert(s) raised by YARA in %s :", len(warningList), filesDir)

	if len(warningList) == 0 {
		log.Infof("Scan duration: %s", elapsed)
		return
	}
	var report scanReport
	report.numOfAlerts = len(warningList)

	// display alerts
	for _, entry := range warningList {
		entryParts := strings.Split(entry, " ")
		fmt.Printf("%s %s triggered by %s\n", aurora.Red("[!]"), entryParts[0], entryParts[1])

		// add rules and files to report struct
		report.rulesTriggered = append(report.rulesTriggered, entryParts[0])
		report.filesInfected = append(report.filesInfected, entryParts[1])

	}

	log.Infof("Scan duration: %s", elapsed)

	// send mail routine
	err = sendMail(mail, report)
	if err != nil {
		log.Errorf("Error sending mail: %s", err)
	}
	log.Infof("Report sent by mail to %s", mail.to)

	// if destroyInfectedFiles is set to true in the config file,
	// the files in entry will be deleted from here
	if quarantine.GetBool("destroyInfectedFiles") {
		if DestroyInfectedFiles(report.filesInfected); err != nil {
			log.Errorf("Error removing files: %s", err)
		}
		log.Infof("Infected files wiped")
		// if destroyInfectedFiles is not set, and if quarantine.enabled is set,
		// this part moves the infected files to a given folder
	} else if quarantine.GetBool("enabled") {
		err := MoveInfectedFile(report.filesInfected, quarantine.GetString("quarantineDir"))
		if err != nil {
			log.Errorf("Error while moving files to %s: %s", quarantine.GetString("quarantineDir"), err)
		}
	}

}

// executeYARAScan calls yara bin on the system and get output
func executeYARAScan(rulesList []string, rulesPath, filesDir string) ([]string, error) {
	var warningList []string
	for _, rule := range rulesList {
		args := []string{"-r", rulesPath + "/" + rule, filesDir}
		out, err := exec.Command("yara", args...).Output()
		if err != nil {
			return nil, err
		}
		cleanOutput := strings.Split(string(out), "\n")

		for _, v := range cleanOutput {
			if len(v) > 0 {
				warningList = append(warningList, v)
			}
		}
	}

	return warningList, nil
}

func sendMail(mailHead mailHeaders, report scanReport) error {
	smtpServer := smtpServer{host: mailHead.server, port: mailHead.port}

	auth := smtp.PlainAuth("", mailHead.from, mailHead.password, smtpServer.host)

	// create a mail object and set it up
	mail := mailyak.New(smtpServer.Address(), auth)
	mail.To(mailHead.to)
	mail.From(mailHead.from)
	mail.FromName(mailHead.nickname)
	mail.Subject(mailHead.subject)

	mail.Plain().Set(strconv.Itoa(report.numOfAlerts) + " alert(s) raised by YARA scan on " +
		time.Now().Format("02/01/2006 15:04:05") + "\r\n" +
		"\n-- REPORT --\n\r\n" +
		"rule triggered:file infected\n\r\n" +
		ReportFormating(report.rulesTriggered, report.filesInfected) + "\r\n" +
		"-- END --\r\n" +
		"\n<!> Please be careful when opening the attachement\r\n")

	// attach infected files to mail
	if mailHead.attachFiles {
		// list of files to zip
		filesToZip := []string{}

		for _, filename := range report.filesInfected {
			file, err := os.Open(filename)
			if err != nil {
				return err
			}
			defer file.Close()

			fi, err := file.Stat()
			if err != nil {
				return err
			}

			// if size of file < max size (default: 10MB), add it to filesToZip
			if fi.Size() <= mailHead.attachedFilesMaxSize*1000000 {
				filesToZip = append(filesToZip, filename)
			}
		}

		// zip files in filesToZip
		output := "infected_files.zip"
		err := ZipFiles(output, filesToZip)
		if err != nil {
			return err
		}
		log.Infof("Zipped File: %s", output)

		outputReader, err := os.Open(output)
		if err != nil {
			return err
		}
		defer outputReader.Close()

		// attach zip files
		mail.Attach(output, outputReader)

		if os.Remove(output); err != nil {
			return err
		}
	}

	// send mail
	err := mail.Send()
	if err != nil {
		return err
	}

	return nil
}
