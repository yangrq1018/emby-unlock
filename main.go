package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"gopkg.in/elazarl/goproxy.v1"
)

const (
	PortDefault = 29967
)

func NewResponse(r *http.Request, contentType string, status int, body string) *http.Response {
	resp := &http.Response{}
	resp.Request = r
	resp.TransferEncoding = r.TransferEncoding
	resp.Header = make(http.Header)
	resp.Header.Add("Content-Type", contentType)
	resp.Header.Add("cache-control", "max-age=2592000")
	resp.Header.Add("access-control-allow-credentials", "true")
	resp.Header.Add("access-control-allow-headers", "*")
	resp.Header.Add("access-control-allow-method", "*")
	resp.Header.Add("access-control-allow-origin", "*")
	resp.StatusCode = status
	buf := bytes.NewBufferString(body)
	resp.ContentLength = int64(buf.Len())
	resp.Body = ioutil.NopCloser(buf)
	return resp
}

func getProxy() *goproxy.ProxyHttpServer {
	// 防止回环
	setEnvErr := os.Unsetenv("HTTP_PROXY")
	setEnvErr = os.Unsetenv("HTTPS_PROXY")
	if setEnvErr != nil {
		panic(fmt.Errorf("设置代理环境变量失败: %s", setEnvErr))
	}

	initCAErr := initCA()
	if initCAErr != nil {
		panic(fmt.Errorf("加载证书失败: %s", initCAErr))
	}

	proxyServer := goproxy.NewProxyHttpServer()
	proxyServer.OnRequest(goproxy.ReqHostIs("mb3admin.com:443")).HandleConnect(goproxy.AlwaysMitm)
	proxyServer.OnRequest(goproxy.ReqHostIs("mb3admin.com:443")).DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			path := req.URL.Path
			log.Println("intercept windows validate device request")
			if path == "/admin/service/registration/validateDevice" {
				// Windows Emby validation calls this route
				return req, NewResponse(req, `application/json`, http.StatusOK, `{"cacheExpirationDays": 365, "message": "Device Valid","resultCode": "GOOD"}`)
			} else if path == "/admin/service/appstore/register" {
				return req, NewResponse(req, `application/json`, http.StatusOK, `{"featId":"","registered":true,"expDate":"2099-01-01","key":""}`)
			} else if path == "/admin/service/registration/validate" {
				return req, NewResponse(req, `application/json`, http.StatusOK, `{"featId":"","registered":true,"expDate":"2099-01-01","key":""}`)
			} else if path == "/admin/service/registration/getStatus" {
				return req, NewResponse(req, `application/json`, http.StatusOK, `{"planType":"Cracked","deviceStatus":"","subscriptions":[]}`)
			} else if path == "/admin/service/supporter/retrievekey" {
				return req, NewResponse(req, `application/json`, http.StatusOK, `{"Success":false,"ErrorMessage":"Supporter not found"}`)
			}
			return req, NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "bee-bee-")
		})
	proxyServer.OnRequest(goproxy.ReqHostIs("www.gstatic.com:80"), goproxy.UrlIs("/generate_204")).DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			return req, NewResponse(req, goproxy.ContentTypeText, http.StatusNoContent, "")
		})
	proxyServer.OnRequest(goproxy.Not(goproxy.ReqHostIs("mb3admin.com:443"))).DoFunc(
		func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			return req, NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "bee-bee-")
		})
	return proxyServer
}

func main() {
	var address string
	var port uint
	flag.StringVar(&address, "host", "127.0.0.1", "proxy listen address")
	flag.UintVar(&port, "port", PortDefault, "specify proxy listen port")
	flag.Parse()
	log.Printf("EmbyUnlockProxy listen at http://%s:%d\n", address, port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf("%s:%d", address, port), getProxy()))
}
