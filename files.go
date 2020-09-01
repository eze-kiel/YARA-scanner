package main

import (
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
)

// MoveInfectedFile gets a list of files to move to newLocation. It is called only
// if quarantine.enabled is et to true in config file.
func MoveInfectedFile(filesList []string, newLocation string) error {
	for _, filename := range filesList {
		parts := strings.Split(filename, "/")
		log.Infof("Moving %s to %s", filename, newLocation+"/"+parts[len(parts)-1])
		return os.Rename(filename, newLocation+parts[len(parts)-1])
	}
	return nil
}

// DestroyInfectedFiles removes infected files if the quarantine.destroyInfectedFiles is set to true
// in config file.
func DestroyInfectedFiles(filesList []string) error {
	for _, filename := range filesList {
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			return nil
		}
		os.Remove(filename)
	}

	return nil
}
