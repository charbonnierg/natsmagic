package natslogger

import "go.uber.org/zap"

type NatsLogger struct {
	*zap.SugaredLogger
}

func (l *NatsLogger) Noticef(format string, v ...interface{}) {
	l.Infof(format, v...)
}

func (l *NatsLogger) Tracef(format string, v ...interface{}) {
	l.Debugf(format, v...)
}

func New(logger *zap.Logger) *NatsLogger {
	return &NatsLogger{logger.WithOptions(zap.AddCallerSkip(4)).Sugar()}
}
