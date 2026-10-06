package client

import (
	"encoding/json"
	"fmt"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"

	policyv1alpha1 "github.com/kubeedge/api/apis/policy/v1alpha1"
	"github.com/kubeedge/beehive/pkg/core/model"
	"github.com/kubeedge/kubeedge/edge/pkg/common/message"
	"github.com/kubeedge/kubeedge/edge/pkg/common/modules"
	"github.com/kubeedge/kubeedge/edge/pkg/metamanager/dao"
)

// ServiceAccountTokenGetter is interface to get client service account token
type ServiceAccountTokenGetter interface {
	ServiceAccountToken() ServiceAccountTokenInterface
}

// ServiceAccountTokenInterface is interface for client service account token
type ServiceAccountTokenInterface interface {
	GetServiceAccountToken(namespace string, name string, tr *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error)
	DeleteServiceAccountToken(podUID types.UID)
}

type serviceAccountToken struct {
	send SendInterface
}

const maxTTL = 24 * time.Hour

func newServiceAccountToken(s SendInterface) *serviceAccountToken {
	return &serviceAccountToken{
		send: s,
	}
}

func (c *serviceAccountToken) DeleteServiceAccountToken(podUID types.UID) {
	svcAccounts, err := dao.QueryAllMeta("type", model.ResourceTypeServiceAccountToken)
	if err != nil {
		klog.Errorf("query meta failed: %v", err)
		return
	}
	for _, sa := range *svcAccounts {
		var tr authenticationv1.TokenRequest
		err = json.Unmarshal([]byte(sa.Value), &tr)
		if err != nil || tr.Spec.BoundObjectRef == nil {
			klog.Errorf("unmarshal resource %s token request failed: %v", sa.Key, err)
			continue
		}
		if podUID == tr.Spec.BoundObjectRef.UID {
			err := dao.DeleteMetaByKey(sa.Key)
			if err != nil {
				klog.Errorf("delete meta %s failed: %v", sa.Key, err)
				return
			}
		}
	}
}

// requiresRefresh returns true if the token is older than 80% of its total
// ttl, or if the token is older than 24 hours.
func requiresRefresh(tr *authenticationv1.TokenRequest) bool {
	if tr.Spec.ExpirationSeconds == nil {
		cpy := tr.DeepCopy()
		cpy.Status.Token = ""
		klog.Errorf("expiration seconds was nil for tr: %#v", cpy)
		return false
	}
	now := time.Now()
	exp := tr.Status.ExpirationTimestamp.Time
	iat := exp.Add(-1 * time.Duration(*tr.Spec.ExpirationSeconds) * time.Second)

	if now.After(iat.Add(maxTTL)) {
		return true
	}
	// Require a refresh if within 20% of the TTL from the expiration time.
	if now.After(exp.Add(-1 * time.Duration((*tr.Spec.ExpirationSeconds*20)/100) * time.Second)) {
		return true
	}
	return false
}

// baseKey is the spec-derived key prefix that identifies the logical token
// (independent of which generation). All generations of the same logical token
// share this prefix. Used for prefix lookup in metaDB.
//
// 这是 v1.22.2 原 KeyFunc 的函数体，拆出来专门做前缀。keys 不含机密，可安全打日志。
func baseKey(name, namespace string, tr *authenticationv1.TokenRequest) string {
	var exp int64
	if tr.Spec.ExpirationSeconds != nil {
		exp = *tr.Spec.ExpirationSeconds
	}

	var ref authenticationv1.BoundObjectReference
	if tr.Spec.BoundObjectRef != nil {
		ref = *tr.Spec.BoundObjectRef
	}

	return fmt.Sprintf("%q/%q/%#v/%#v/%#v", name, namespace, tr.Spec.Audiences, exp, ref)
}

// KeyFunc returns the per-generation storage key for a TokenRequest. The key is
// the base (spec-derived) key suffixed with the token's expiration timestamp so
// that successive refreshed tokens for the same logical token are stored as
// separate rows.
//
// 为什么要按世代分键（backport 自 kubeedge#6828）：MetaServer 用「DB 里是否存在该 token」
// 做认证（CheckTokenExist）。v1.22.2 原实现在 token 到达刷新阈值时**先删本地行再去云端取新的**，
// 一旦此刻处于分区（RQ3 的 edgecore-restart-during-partition 场景）或重连瞬间，远端取不到，
// 本地行就永久消失 → 之后 Pod 带着任一 token 来都认证失败（tokenData not found，恒久 401）。
// 改为「新旧世代各自一行、刷新窗口内并存」后，旧 token 在传播窗口内仍可通过认证；过期行由
// RunExpiredTokenGC 清理。
//
// 写入侧（process.go 的 parseResource）与读取侧（getTokenLocally 前缀查询）共用本函数：
// 写入用完整世代键落行，读取用 baseKey 前缀一次取回同一逻辑 token 的所有世代。
//
// keys 不含机密，可安全打日志。
func KeyFunc(name, namespace string, tr *authenticationv1.TokenRequest) string {
	base := baseKey(name, namespace, tr)
	if tr.Status.ExpirationTimestamp.IsZero() {
		// 防御：没有 exp 的写入是异常数据。回退到 base（退化成 v1.22.2 的「一个逻辑 token 一行、
		// 刷新即覆盖」行为），不比原来更糟。正常写入路径的 token 响应都带 Status.ExpirationTimestamp。
		return base
	}
	return fmt.Sprintf("%s/%d", base, tr.Status.ExpirationTimestamp.UnixNano())
}

func getTokenLocally(name, namespace string, tr *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error) {
	prefix := baseKey(name, namespace, tr)
	// 前缀查询一次取回同一逻辑 token 的所有世代（也兼容升级前写入的「无 exp 后缀」旧行：
	// LIKE 'base%' 同样命中 base 本身）。
	metas, err := dao.QueryMetaByKeyPrefix(prefix)
	if err != nil {
		klog.Errorf("query meta by prefix %s failed: %v", prefix, err)
		return nil, err
	}
	if metas == nil || len(*metas) == 0 {
		return nil, fmt.Errorf("no cached token for %s", prefix)
	}

	// 选出最新的未过期世代。更旧的世代可能仍在（刻意保留以覆盖刷新传播窗口，过期后由 GC 清理），
	// 但要返回给调用方的是最新那一个。
	now := time.Now()
	var newest *authenticationv1.TokenRequest
	for _, v := range *metas {
		var cur authenticationv1.TokenRequest
		if err := json.Unmarshal([]byte(v), &cur); err != nil {
			klog.Errorf("unmarshal cached token under prefix %s failed: %v", prefix, err)
			continue
		}
		// 升级前的旧行可能没有 ExpirationTimestamp：此时无法判断是否过期，跳过它，
		// 促使走远端刷新拿到带 exp 的新世代（而不是把一个无法判定寿命的 token 当作有效）。
		if cur.Status.ExpirationTimestamp.IsZero() || !cur.Status.ExpirationTimestamp.Time.After(now) {
			continue
		}
		if newest == nil || cur.Status.ExpirationTimestamp.Time.After(newest.Status.ExpirationTimestamp.Time) {
			snapshot := cur
			newest = &snapshot
		}
	}
	if newest == nil {
		return nil, fmt.Errorf("no un-expired cached token for %s", prefix)
	}

	if requiresRefresh(newest) {
		// 最新世代已过刷新阈值（TTL 的 80%），触发远端刷新。
		// **关键：这里不删除任何本地行**（这正是 v1.22.2 恒久 401 的根因修复）。刷新得到的
		// 新 token 会以新的世代键写入（见 KeyFunc），新旧行在传播窗口内并存；过期行由
		// RunExpiredTokenGC 清理。
		klog.V(4).Infof("resource %s token requires refresh", prefix)
		return nil, fmt.Errorf("resource %s token requires refresh", prefix)
	}
	return newest, nil
}

func getTokenRemotely(resource string, tr *authenticationv1.TokenRequest, c *serviceAccountToken) (*authenticationv1.TokenRequest, error) {
	tokenMsg := message.BuildMsg(modules.MetaGroup, "", modules.EdgedModuleName, resource, model.QueryOperation, tr)
	msg, err := c.send.SendSync(tokenMsg)
	if err != nil {
		klog.Errorf("get service account token from metaManager failed, err: %v", err)
		return nil, fmt.Errorf("get service account token from metaManager failed, err: %v", err)
	}

	content, err := msg.GetContentData()
	if err != nil {
		klog.Errorf("parse message to serviceaccount token failed, err: %v", err)
		return nil, fmt.Errorf("marshal message to serviceaccount token failed, err: %v", err)
	}

	if msg.GetOperation() == model.ResponseOperation && msg.GetSource() == modules.MetaManagerModuleName {
		return handleServiceAccountTokenFromMetaDB(content)
	}
	return handleServiceAccountTokenFromMetaManager(content)
}

func (c *serviceAccountToken) GetServiceAccountToken(namespace string, name string, tr *authenticationv1.TokenRequest) (*authenticationv1.TokenRequest, error) {
	tokenReq, err := getTokenLocally(name, namespace, tr)
	if err != nil {
		resource := fmt.Sprintf("%s/%s/%s", namespace, model.ResourceTypeServiceAccountToken, name)
		return getTokenRemotely(resource, tr, c)
	}
	return tokenReq, nil
}

func handleServiceAccountTokenFromMetaDB(content []byte) (*authenticationv1.TokenRequest, error) {
	var lists []string
	err := json.Unmarshal(content, &lists)
	if err != nil {
		return nil, fmt.Errorf("unmarshal message to serviceaccount list from db failed, err: %v", err)
	}

	if len(lists) != 1 {
		return nil, fmt.Errorf("serviceaccount length from meta db is %d", len(lists))
	}

	var tokenRequest authenticationv1.TokenRequest
	err = json.Unmarshal([]byte(lists[0]), &tokenRequest)
	if err != nil {
		return nil, fmt.Errorf("unmarshal message to serviceaccount token from db failed, err: %v", err)
	}
	return &tokenRequest, nil
}

func handleServiceAccountTokenFromMetaManager(content []byte) (*authenticationv1.TokenRequest, error) {
	var serviceAccount authenticationv1.TokenRequest
	err := json.Unmarshal(content, &serviceAccount)
	if err != nil {
		return nil, fmt.Errorf("unmarshal message to service account failed, err: %v", err)
	}
	return &serviceAccount, nil
}

// ServiceAccountGetter is interface to get Client service account
type ServiceAccountsGetter interface {
	ServiceAccounts(namespace string) ServiceAccountInterface
}

// ServiceAccountInterface is interface for Client service account token
type ServiceAccountInterface interface {
	Get(name string) (*corev1.ServiceAccount, error)
}

type serviceAccount struct {
	namespace string
}

func newServiceAccount(namespace string) *serviceAccount {
	return &serviceAccount{namespace: namespace}
}

func (s *serviceAccount) Get(name string) (*corev1.ServiceAccount, error) {
	rst, err := dao.QueryMeta("type", model.ResourceTypeSaAccess)
	if err != nil {
		return nil, err
	}
	for _, v := range *rst {
		var saAccess policyv1alpha1.ServiceAccountAccess
		err = json.Unmarshal([]byte(v), &saAccess)
		if err != nil {
			klog.Errorf("failed to unmarshal saAccess %v", err)
			return nil, err
		}
		if saAccess.Namespace == s.namespace && saAccess.Spec.ServiceAccount.Name == name {
			rst := saAccess.Spec.ServiceAccount
			rst.UID = saAccess.Spec.ServiceAccountUID
			return &rst, nil
		}
	}
	return nil, fmt.Errorf("serviceaccount %s/%s not found", s.namespace, name)
}

func CheckTokenExist(token string) bool {
	if token == "" {
		return false
	}
	metas, err := dao.QueryMeta("type", model.ResourceTypeServiceAccountToken)
	if err != nil {
		klog.Errorf("query meta %s failed: %v", model.ResourceTypeServiceAccountToken, err)
		return false
	}

	for _, v := range *metas {
		var tokenRequest authenticationv1.TokenRequest
		err = json.Unmarshal([]byte(v), &tokenRequest)
		if err != nil {
			klog.Errorf("unmarshal resource %s token request failed: %v", model.ResourceTypeServiceAccountToken, err)
			return false
		}
		if tokenRequest.Status.Token == token {
			return true
		}
	}
	return false
}

// RunExpiredTokenGC periodically scans all service-account token rows in metaDB
// and deletes any whose Status.ExpirationTimestamp has passed.
//
// 为什么需要 GC（backport 自 kubeedge#6828）：刷新后的 token 以「每世代一个键」存储、不再覆盖
// 旧世代（见 KeyFunc），过期世代因此会累积，必须在这里清掉。以 10 分钟 token TTL、80% 刷新阈值
// 估算，单个逻辑 token 的稳态行数约为 2；下面的扫描间隔足够宽松。stopCh 关闭时退出。
func RunExpiredTokenGC(stopCh <-chan struct{}, interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			gcExpiredTokensOnce()
		}
	}
}

// gcExpiredTokensOnce 扫描一次 serviceaccounttoken 行，删除所有已过期（含无 exp 的异常行）的。
func gcExpiredTokensOnce() {
	rows, err := dao.QueryAllMeta("type", model.ResourceTypeServiceAccountToken)
	if err != nil {
		klog.Errorf("GC: query SA tokens failed: %v", err)
		return
	}
	if rows == nil {
		return
	}
	now := time.Now()
	for _, m := range *rows {
		var tr authenticationv1.TokenRequest
		if err := json.Unmarshal([]byte(m.Value), &tr); err != nil {
			klog.Errorf("GC: unmarshal SA token row %s failed: %v", m.Key, err)
			continue
		}
		// 已过期即删除。无 exp 的异常行同样删除：它无法参与认证（getTokenLocally 会跳过它），
		// 留着只会占行、并在重启后造成误导性的“有行却认证不过”。
		if tr.Status.ExpirationTimestamp.IsZero() || !tr.Status.ExpirationTimestamp.Time.After(now) {
			if err := dao.DeleteMetaByKey(m.Key); err != nil {
				klog.Errorf("GC: delete expired SA token %s failed: %v", m.Key, err)
			}
		}
	}
}
