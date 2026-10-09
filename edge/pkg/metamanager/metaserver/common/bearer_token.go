/*
Copyright 2025 The KubeEdge Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package common

import (
	"context"
	"net/http"
	"strings"
)

// bearerTokenContextKey 是存放原始 Authorization Bearer token 的 context key 类型。
// 用非导出的具名类型而不是裸字符串，避免和其他包的 context key 冲突。
type bearerTokenContextKey struct{}

// CaptureBearerToken 在认证中间件删除 Authorization 头之前，把其中的 Bearer token
// 存进请求 context，供后续 handler（如 unhold-upgrade 内部对 MetaServer 自身的自
// 调用）取用。
//
// 必须在 genericapifilters.WithAuthentication 外层调用：该中间件认证成功后会主动
// 删除请求的 Authorization 头（k8s.io/apiserver 标准安全行为，避免凭证被下游继续
// 传递），之后 handler 内部就再也拿不到原始 token 了。
func CaptureBearerToken(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		const prefix = "Bearer "
		auth := req.Header.Get("Authorization")
		if strings.HasPrefix(auth, prefix) {
			token := strings.TrimPrefix(auth, prefix)
			req = req.WithContext(context.WithValue(req.Context(), bearerTokenContextKey{}, token))
		}
		handler.ServeHTTP(w, req)
	})
}

// BearerTokenFromContext 取出 CaptureBearerToken 存入 context 的原始 Bearer token；
// 不存在时返回空字符串。
func BearerTokenFromContext(ctx context.Context) string {
	token, _ := ctx.Value(bearerTokenContextKey{}).(string)
	return token
}
