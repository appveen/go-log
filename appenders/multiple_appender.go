package appenders

import (
	"fmt"

	"github.com/appveen/go-log/layout"
	"github.com/appveen/go-log/levels"
)

type multipleAppender struct {
	currentLayout   layout.Layout
	listOfAppenders []Appender
}

func Multiple(layout layout.Layout, appenders ...Appender) Appender {
	return &multipleAppender{
		listOfAppenders: appenders,
		currentLayout:   layout,
	}
}

func (this *multipleAppender) Layout() layout.Layout {
	return this.currentLayout
}

func (this *multipleAppender) SetLayout(l layout.Layout) {
	this.currentLayout = l
}

func (this *multipleAppender) UpdateCustomHeaders(headers map[string]string) {
	fmt.Println("NewM Custom Headers - ", headers)
	UpdateRollingCustomHeaders(headers)
}

func (this *multipleAppender) Write(level levels.LogLevel, message string, args ...interface{}) {
	for _, appender := range this.listOfAppenders {
		appender.Write(level, message, args...)
	}
}
