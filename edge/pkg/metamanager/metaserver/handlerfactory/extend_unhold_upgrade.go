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

package handlerfactory

// [1.22.2-fix] unhold-upgrade 改为直接读本地 meta_v2 缓存：
// 官方实现会通过 metaclient 用同一组 TLSCaFile/TLSCertFile/TLSPrivateKeyFile 构造一个
// HTTPS client 回调 MetaServer 自己（https://127.0.0.1:10550），而服务端证书是 CSR 流程
// 用集群 CA 签发的、客户端证书是 KubeEdge CA 签发的，单一 tlsCaFile 无法同时满足两侧，
// 于是 handler 内部必然失败（x509 unknown authority / remote error unknown CA），
// release 永远不生效。本地缓存读取不引入 TCP/TLS/证书，且不改变 hold/release 协议。
import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"

	beehiveContext "github.com/kubeedge/beehive/pkg/core/context"
	"github.com/kubeedge/beehive/pkg/core/model"
	"github.com/kubeedge/kubeedge/edge/pkg/common/modules"
	metav2 "github.com/kubeedge/kubeedge/edge/pkg/metamanager/dao/v2"
	"github.com/kubeedge/kubeedge/edge/pkg/metamanager/metaserver/common"
	"github.com/kubeedge/kubeedge/edge/pkg/metamanager/metaserver/kubernetes/storage/sqlite/imitator"
)

// localResourceKey 构造 meta_v2 的 key：/<group>/<version>/<resource>/<namespace>/<name>，
// 空 namespace/name 用 "null"（与 pkg/metaserver.ParseKey 的口径一致）。
func localResourceKey(resource, namespace, name string) string {
	if namespace == "" {
		namespace = metav2.NullNamespace
	}
	if name == "" {
		name = metav2.NullName
	}
	return fmt.Sprintf("/%s/v1/%s/%s/%s", metav2.GroupCore, resource, namespace, name)
}

// getLocalPod 从 EdgeCore 本地 meta_v2 读取 Pod（不再经 HTTPS 回调 MetaServer 自己）。
func getLocalPod(ctx context.Context, namespace, name string) (*v1.Pod, error) {
	resp, err := imitator.DefaultV2Client.Get(ctx, localResourceKey("pods", namespace, name))
	if err != nil {
		return nil, err
	}
	if resp.Kvs == nil || len(*resp.Kvs) != 1 {
		return nil, fmt.Errorf("pod %s/%s not found in local meta cache", namespace, name)
	}
	var pod v1.Pod
	if err := json.Unmarshal([]byte((*resp.Kvs)[0].Value), &pod); err != nil {
		return nil, fmt.Errorf("failed to decode pod %s/%s from local meta cache: %w", namespace, name, err)
	}
	return &pod, nil
}

// localNodeExists 校验 Node 是否在本地 meta_v2 中（key 用 null namespace）。
func localNodeExists(ctx context.Context, nodeName string) error {
	resp, err := imitator.DefaultV2Client.Get(ctx, localResourceKey("nodes", "", nodeName))
	if err != nil {
		return err
	}
	if resp.Kvs == nil || len(*resp.Kvs) != 1 {
		return fmt.Errorf("node %s not found in local meta cache", nodeName)
	}
	return nil
}

// listLocalPods 列出本地 meta_v2 中缓存的全部 Pod（空 namespace/name -> null/null）。
func listLocalPods(ctx context.Context) ([]v1.Pod, error) {
	resp, err := imitator.DefaultV2Client.List(ctx, localResourceKey("pods", "", ""))
	if err != nil {
		return nil, err
	}
	if resp.Kvs == nil {
		return nil, nil
	}
	pods := make([]v1.Pod, 0, len(*resp.Kvs))
	for _, meta := range *resp.Kvs {
		var pod v1.Pod
		if err := json.Unmarshal([]byte(meta.Value), &pod); err != nil {
			return nil, fmt.Errorf("failed to decode pod from local meta cache: %w", err)
		}
		pods = append(pods, pod)
	}
	return pods, nil
}

func (f *Factory) UnholdUpgrade() http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		logger := klog.FromContext(ctx).WithName("unholdUpgrade")
		logger.V(4).Info("start to unhold upgrade")

		keyBytes, err := limitedReadBody(req, int64(3*1024*1024))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		key := string(keyBytes)

		parts := strings.SplitN(key, "/", 2)
		if len(parts) != 2 {
			http.Error(w, "invalid format, expected <namespace>/<name>", http.StatusBadRequest)
			return
		}
		namespace, name := parts[0], parts[1]

		// [1.22.2-fix] Unhold 是纯本地操作：直接从 meta_v2 读 Pod，
		// 不再用 HTTPS 回调 MetaServer 自己（见文件头说明）。
		pod, err := getLocalPod(ctx, namespace, name)
		if err != nil {
			http.Error(w, fmt.Sprintf("pod not found in local meta cache: %v", err), http.StatusNotFound)
			return
		}

		// validate pod annotation and status
		if pod.Annotations["edge.kubeedge.io/hold-upgrade"] != "true" {
			http.Error(w, "pod is not marked with hold-upgrade annotation", http.StatusBadRequest)
			return
		}

		if pod.Status.Phase != v1.PodPending {
			http.Error(w, "pod is not in pending phase", http.StatusBadRequest)
			return
		}

		resource := fmt.Sprintf("%s/pod/%s", namespace, name)
		msg := model.NewMessage("").
			BuildRouter(modules.MetaManagerModuleName, "", resource, model.UnholdUpgradeOperation)
		beehiveContext.Send(modules.EdgedModuleName, *msg)

		w.WriteHeader(http.StatusOK)
	})
	return h
}

func (f *Factory) UnholdUpgradeNode() http.Handler {
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := req.Context()
		logger := klog.FromContext(ctx).WithName("unholdUpgradeNode")
		logger.V(4).Info("start to unhold node-wide upgrade")

		keyBytes, err := limitedReadBody(req, int64(3*1024*1024))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		nodeName := strings.TrimSpace(string(keyBytes))
		if nodeName == "" {
			http.Error(w, "node name required in body", http.StatusBadRequest)
			return
		}

		// [1.22.2-fix] 同样改为本地读取：先确认 Node 在缓存里，再列出缓存中的 Pod 并按
		// spec.nodeName 过滤（不再构造 kube client、不再发 HTTPS 请求）。
		if err := localNodeExists(ctx, nodeName); err != nil {
			http.Error(w, fmt.Sprintf("node not found in local meta cache: %v", err), http.StatusNotFound)
			return
		}

		pods, err := listLocalPods(ctx)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to list pods from local meta cache: %v", err), http.StatusInternalServerError)
			return
		}

		for i := range pods {
			pod := pods[i]
			if pod.Spec.NodeName != nodeName {
				continue
			}
			if pod.Annotations["edge.kubeedge.io/hold-upgrade"] != common.TrueStr || pod.Status.Phase != v1.PodPending {
				continue
			}
			resource := fmt.Sprintf("%s/pod/%s", pod.Namespace, pod.Name)
			msg := model.NewMessage("").
				BuildRouter(modules.MetaManagerModuleName, "", resource, model.UnholdUpgradeOperation)
			beehiveContext.Send(modules.EdgedModuleName, *msg)
			logger.V(4).Info(fmt.Sprintf("Unhold message sent for pod %s/%s on node %s", pod.Namespace, pod.Name, nodeName))
		}

		w.WriteHeader(http.StatusOK)
	})
	return h
}
