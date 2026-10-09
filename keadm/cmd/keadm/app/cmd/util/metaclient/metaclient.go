/*
Copyright 2024 The KubeEdge Authors.

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

package metaclient

import (
	"fmt"
	"time"

	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/kubeedge/api/apis/common/constants"
	cfgv1alpha2 "github.com/kubeedge/api/apis/componentconfig/edgecore/v1alpha2"
	"github.com/kubeedge/api/client/clientset/versioned"
	keadutil "github.com/kubeedge/kubeedge/keadm/cmd/keadm/app/cmd/util"
)

func KubeClient() (kubernetes.Interface, error) {
	config, err := keadutil.ParseEdgecoreConfig(constants.EdgecoreConfigPath)
	if err != nil {
		return nil, fmt.Errorf("get edge config failed with err: %v", err)
	}
	return KubeClientWithConfig(config)
}

// KubeClientWithToken 用给定的 Bearer token 构造客户端——供 MetaServer 内部处理
// unhold-upgrade 等请求时，把外层请求已通过认证的 Authorization token 原样转发给
// 内部对自身（127.0.0.1）发起的自调用使用。不这样做的话，内部自调用是匿名请求，
// 会被同一个 MetaServer 的认证过滤器拒绝（401 Unauthorized），即使外层请求本身的
// token 完全合法。
func KubeClientWithToken(token string) (kubernetes.Interface, error) {
	config, err := keadutil.ParseEdgecoreConfig(constants.EdgecoreConfigPath)
	if err != nil {
		return nil, fmt.Errorf("get edge config failed with err: %v", err)
	}
	kubeConfig, err := GetKubeConfigWithConfig(config)
	if err != nil {
		return nil, err
	}
	kubeConfig.BearerToken = token
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	return kubeClient, nil
}

func KubeClientWithConfig(config *cfgv1alpha2.EdgeCoreConfig) (kubernetes.Interface, error) {
	kubeConfig, err := GetKubeConfigWithConfig(config)
	if err != nil {
		return nil, err
	}
	kubeClient, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	return kubeClient, nil
}

func GetKubeConfig() (*restclient.Config, error) {
	config, err := keadutil.ParseEdgecoreConfig(constants.EdgecoreConfigPath)
	if err != nil {
		return nil, fmt.Errorf("get edge config failed with err: %v", err)
	}
	return GetKubeConfigWithConfig(config)
}

func GetKubeConfigWithConfig(config *cfgv1alpha2.EdgeCoreConfig) (*restclient.Config, error) {
	if !config.Modules.MetaManager.MetaServer.Enable {
		return nil, fmt.Errorf("metaserver don't open")
	}

	url := config.Modules.MetaManager.MetaServer.Server
	ok, requireAuthorization := config.FeatureGates["requireAuthorization"]
	if ok && requireAuthorization {
		url = "https://" + url
	} else {
		url = "http://" + url
	}
	kubeConfig, err := clientcmd.BuildConfigFromFlags(url, "")
	if err != nil {
		return nil, err
	}

	if ok && requireAuthorization {
		// 只设置 CAFile 用于校验 MetaServer 自身的 serving 证书；不设置 CertFile/KeyFile。
		// MetaServer 的 TLSCertFile/TLSPrivateKeyFile 是 EdgeHub 连 CloudHub 用的节点证书，
		// 由 CloudCore 的 CA 签发，而 MetaServer 的 ClientCAs 信任池用的是它自己独立的
		// metaserver/ca.crt —— 两者不是同一条信任链，把前者当客户端证书出示会被 MetaServer
		// 以 "tls: unknown certificate authority" 拒绝。认证本来就走 Authorization Bearer
		// token（见 edge/pkg/metamanager/metaserver/auth），MetaServer 的 ClientAuth 是
		// VerifyClientCertIfGiven（客户端证书可选），不出示即可。
		tlsCaFile := config.Modules.MetaManager.MetaServer.TLSCaFile
		kubeConfig.TLSClientConfig.CAFile = tlsCaFile
	}
	kubeConfig.Timeout = 1 * time.Minute
	return kubeConfig, nil
}

func VersionedKubeClient() (versioned.Interface, error) {
	config, err := keadutil.ParseEdgecoreConfig(constants.EdgecoreConfigPath)
	if err != nil {
		return nil, fmt.Errorf("get edge config failed with err: %v", err)
	}
	return VersionedKubeClientWithConfig(config)
}

func VersionedKubeClientWithConfig(config *cfgv1alpha2.EdgeCoreConfig) (versioned.Interface, error) {
	kubeConfig, err := GetKubeConfigWithConfig(config)
	if err != nil {
		return nil, err
	}
	versionedClient, err := versioned.NewForConfig(kubeConfig)
	if err != nil {
		return nil, err
	}
	return versionedClient, nil
}
