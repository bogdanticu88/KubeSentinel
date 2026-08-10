from types import SimpleNamespace

from kubernetes.client.exceptions import ApiException
from urllib3.exceptions import MaxRetryError

from kubesentinel.collector.collector import CollectionResult, _collect_kind, _count_nodes


class FakeApiClient:
    def sanitize_for_serialization(self, item):
        return item


def test_collect_kind_appends_normalized_resources():
    result = CollectionResult()
    raw_pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "app", "namespace": "default", "uid": "123", "labels": {"team": "payments"}},
        "spec": {"containers": [{"name": "app"}], "hostNetwork": True},
    }

    _collect_kind(result, FakeApiClient(), "Pod", lambda: SimpleNamespace(items=[raw_pod]))

    assert len(result.resources) == 1
    resource = result.resources[0]
    assert resource.name == "app"
    assert resource.namespace == "default"
    assert resource.labels == {"team": "payments"}
    assert resource.data["hostNetwork"] is True
    assert result.warnings == []


def test_collect_kind_records_permission_denied_without_raising():
    result = CollectionResult()

    def denied():
        raise ApiException(status=403, reason="Forbidden")

    _collect_kind(result, FakeApiClient(), "ClusterRole", denied)

    assert result.resources == []
    assert len(result.warnings) == 1
    assert result.warnings[0].resource_kind == "ClusterRole"
    assert "permission denied" in result.warnings[0].message


def test_collect_kind_records_other_api_errors_without_raising():
    result = CollectionResult()

    def server_error():
        raise ApiException(status=500, reason="Internal Server Error")

    _collect_kind(result, FakeApiClient(), "Pod", server_error)

    assert result.warnings[0].message.startswith("failed to list Pod")


def test_collect_kind_records_a_connection_failure_without_raising():
    # A list call can fail below the HTTP layer entirely, a timeout or a
    # dropped connection mid-scan raises straight from urllib3 rather than
    # coming back as an ApiException, that still has to degrade to a
    # warning instead of taking the whole scan down.
    result = CollectionResult()

    def connection_dropped():
        raise MaxRetryError(pool=None, url="https://cluster/api/v1/pods", reason=Exception("connection refused"))

    _collect_kind(result, FakeApiClient(), "Pod", connection_dropped)

    assert result.resources == []
    assert len(result.warnings) == 1
    assert "could not reach the API server" in result.warnings[0].message


def test_count_nodes_records_a_connection_failure_without_raising():
    result = CollectionResult()

    class UnreachableCore:
        def list_node(self):
            raise MaxRetryError(pool=None, url="https://cluster/api/v1/nodes", reason=Exception("timed out"))

    assert _count_nodes(result, UnreachableCore()) == 0
    assert len(result.warnings) == 1
    assert result.warnings[0].resource_kind == "Node"


def _pod_owned_by(kind: str, name: str = "child") -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": "default",
            "ownerReferences": [{"kind": kind, "name": "owner", "controller": True}],
        },
        "spec": {"containers": [{"name": "app"}]},
    }


def test_pods_owned_by_a_replicaset_statefulset_daemonset_or_job_are_skipped():
    for owner_kind in ("ReplicaSet", "StatefulSet", "DaemonSet", "Job"):
        result = CollectionResult()
        pod = _pod_owned_by(owner_kind)
        _collect_kind(result, FakeApiClient(), "Pod", lambda pod=pod: SimpleNamespace(items=[pod]))
        assert result.resources == [], f"pod owned by {owner_kind} should have been skipped"


def test_a_job_owned_by_a_cronjob_is_skipped():
    result = CollectionResult()
    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": "nightly-backup-28912345",
            "namespace": "default",
            "ownerReferences": [{"kind": "CronJob", "name": "nightly-backup", "controller": True}],
        },
        "spec": {"template": {"spec": {"containers": [{"name": "backup"}]}}},
    }

    _collect_kind(result, FakeApiClient(), "Job", lambda: SimpleNamespace(items=[job]))

    assert result.resources == []


def test_a_static_pod_owned_by_a_node_is_not_skipped():
    # kubelet sets the Node as owner for a static pod like kube-apiserver,
    # that is not a controller kind this collector also lists, so there is
    # nothing to duplicate against, the pod has to stay.
    result = CollectionResult()
    static_pod = _pod_owned_by("Node", name="kube-apiserver-control-plane")

    _collect_kind(result, FakeApiClient(), "Pod", lambda: SimpleNamespace(items=[static_pod]))

    assert len(result.resources) == 1
    assert result.resources[0].name == "kube-apiserver-control-plane"


def test_a_pod_with_no_owner_at_all_is_not_skipped():
    result = CollectionResult()
    orphan_pod = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "debug-shell", "namespace": "default"},
        "spec": {"containers": [{"name": "shell"}]},
    }

    _collect_kind(result, FakeApiClient(), "Pod", lambda: SimpleNamespace(items=[orphan_pod]))

    assert len(result.resources) == 1


def test_a_deployment_with_an_owner_is_never_skipped():
    # The skip list only applies to Pod and Job, a Deployment managed by an
    # operator or an ArgoCD Application still has to be collected, there is
    # no duplicate Deployment-shaped resource anywhere else to defer to.
    result = CollectionResult()
    deployment = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "app",
            "namespace": "default",
            "ownerReferences": [{"kind": "Application", "name": "my-app", "controller": True}],
        },
        "spec": {"template": {"spec": {"containers": [{"name": "app"}]}}},
    }

    _collect_kind(result, FakeApiClient(), "Deployment", lambda: SimpleNamespace(items=[deployment]))

    assert len(result.resources) == 1


def test_collect_kind_skips_a_malformed_item_without_dropping_the_rest():
    result = CollectionResult()

    class BrokenApiClient:
        def sanitize_for_serialization(self, item):
            if item == "broken":
                raise TypeError("not serializable")
            return item

    good_pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "good"}, "spec": {}}

    _collect_kind(result, BrokenApiClient(), "Pod", lambda: SimpleNamespace(items=["broken", good_pod]))

    assert len(result.resources) == 1
    assert result.resources[0].name == "good"
    assert len(result.warnings) == 1
    assert "malformed" in result.warnings[0].message
