package main

import (
	"testing"
)

func Test_smtpServer_address(t *testing.T) {
	type fields struct {
		host string
		port string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "google",
			fields: fields{
				"smtp.gmail.com",
				"587",
			},
			want: "smtp.gmail.com:587",
		},
		{
			name: "fastmail",
			fields: fields{
				"smtp.fastmail.com",
				"587",
			},
			want: "smtp.fastmail.com:587",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &smtpServer{
				host: tt.fields.host,
				port: tt.fields.port,
			}
			if got := s.Address(); got != tt.want {
				t.Errorf("smtpServer.Address() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_reportFormating(t *testing.T) {
	type args struct {
		rules []string
		files []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test1",
			args: args{
				[]string{"png"},
				[]string{"toto.png"},
			},
			want: "png:toto.png\n\n",
		},
		{
			name: "test2",
			args: args{
				[]string{"jpg", "png"},
				[]string{"toto.jpg", "sandwich.png"},
			},
			want: "jpg:toto.jpg\n\npng:sandwich.png\n\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ReportFormating(tt.args.rules, tt.args.files); got != tt.want {
				t.Errorf("ReportFormating() = %v, want %v", got, tt.want)
			}
		})
	}
}
