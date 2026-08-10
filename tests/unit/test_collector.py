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
