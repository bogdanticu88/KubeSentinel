from kubesentinel.collector.normalize import normalize_resource


def test_pod_spec_extracted_directly():
    raw = {"spec": {"containers": [{"name": "app"}], "hostNetwork": True}}
    data = normalize_resource("Pod", raw)
    assert data["containers"] == [{"name": "app"}]
    assert data["hostNetwork"] is True


def test_deployment_spec_extracted_from_template():
    raw = {"spec": {"template": {"spec": {"containers": [{"name": "app"}], "hostPID": True}}}}
    data = normalize_resource("Deployment", raw)
    assert data["containers"] == [{"name": "app"}]
    assert data["hostPID"] is True


def test_statefulset_and_daemonset_use_the_same_template_path():
    raw = {"spec": {"template": {"spec": {"containers": [{"name": "app"}]}}}}
    assert normalize_resource("StatefulSet", raw)["containers"] == [{"name": "app"}]
    assert normalize_resource("DaemonSet", raw)["containers"] == [{"name": "app"}]


def test_cronjob_spec_extracted_from_nested_job_template():
    raw = {
        "spec": {
            "jobTemplate": {
                "spec": {"template": {"spec": {"containers": [{"name": "worker"}], "hostIPC": True}}}
            }
        }
    }
    data = normalize_resource("CronJob", raw)
    assert data["containers"] == [{"name": "worker"}]
    assert data["hostIPC"] is True


def test_workload_normalization_tolerates_missing_spec():
    assert normalize_resource("Pod", {}) == {}
    assert normalize_resource("Deployment", {}) == {}
    assert normalize_resource("CronJob", {}) == {}


def test_role_and_clusterrole_expose_rules_at_top_level():
    raw = {"rules": [{"resources": ["pods"], "verbs": ["get"]}]}
    assert normalize_resource("Role", raw) == {"rules": raw["rules"]}
    assert normalize_resource("ClusterRole", raw) == {"rules": raw["rules"]}


def test_role_without_rules_key_normalizes_to_empty_list():
    assert normalize_resource("Role", {}) == {"rules": []}


def test_bindings_expose_subjects_and_role_ref():
    raw = {"subjects": [{"kind": "ServiceAccount", "name": "default"}], "roleRef": {"name": "admin"}}
    data = normalize_resource("RoleBinding", raw)
    assert data["subjects"] == raw["subjects"]
    assert data["roleRef"] == raw["roleRef"]


def test_service_account_exposes_automount_flag():
    raw = {"automountServiceAccountToken": False}
    assert normalize_resource("ServiceAccount", raw) == {"automountServiceAccountToken": False}


def test_service_and_ingress_pass_spec_through():
    raw = {"spec": {"type": "NodePort"}}
    assert normalize_resource("Service", raw) == {"type": "NodePort"}

    raw = {"spec": {"tls": [{"hosts": ["example.com"]}]}}
    assert normalize_resource("Ingress", raw) == {"tls": [{"hosts": ["example.com"]}]}
