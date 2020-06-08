package secure_backend

import (
	"fmt"
	"log"
)

type Logger struct {
	Info  func(message string)
	Error func(message string)
}

func (it *Logger) logInfo(message string) {
	if it.Info != nil {
		it.Info(message)
	} else {
		log.Println(fmt.Sprintf("go-secure-backend.Info: %v", message))
	}
}

func (it *Logger) logError(message string) {
	if it.Error != nil {
		it.Error(message)
	} else {
		log.Println(fmt.Sprintf("go-secure-backend.Error: %v", message))
	}
}
