"""Kubernetes API client construction and connectivity checks."""

from kubernetes import client, config
from kubernetes.client.exceptions import ApiException
from urllib3.exceptions import MaxRetryError

from kubesentinel.collector.errors import (
    AuthenticationError,
    ClusterUnreachableError,
    KubeConfigError,
)


def build_client(kube_context: str | None = None) -> client.ApiClient:
    """Load kubeconfig and return a configured API client.

    Tries the standard kubeconfig file first, since that is how an operator
    running the CLI from a laptop will normally be authenticated, and falls
    back to in-cluster config for when KubeSentinel runs as a pod inside the
    cluster it is scanning.
    """
    try:
        config.load_kube_config(context=kube_context)
    except config.ConfigException as kube_config_error:
        try:
            config.load_incluster_config()
        except config.ConfigException:
            context_note = f" context {kube_context!r}" if kube_context else ""
            raise KubeConfigError(
                f"could not load a kubeconfig{context_note} and no in-cluster service "
                f"account was found. Original error: {kube_config_error}"
            ) from kube_config_error
    return client.ApiClient()


def verify_connectivity(api_client: client.ApiClient) -> str:
    """Confirm the API server is reachable and return its version string."""
    version_api = client.VersionApi(api_client)
    try:
        version_info = version_api.get_code()
    except ApiException as api_error:
        if api_error.status in (401, 403):
            raise AuthenticationError(
                f"the cluster rejected the current credentials (HTTP {api_error.status}). "
                "Check that your kubeconfig context still has a valid token or certificate."
            ) from api_error
        raise ClusterUnreachableError(
            f"the API server returned an unexpected error while checking connectivity: "
            f"HTTP {api_error.status} {api_error.reason}"
        ) from api_error
    except (MaxRetryError, OSError) as connection_error:
        raise ClusterUnreachableError(
            f"could not reach the API server: {connection_error}"
        ) from connection_error
    return version_info.git_version


def current_context_name(kube_context: str | None = None) -> str:
    """Best-effort label for the cluster being scanned.

    Falls back to "in-cluster" when there is no kubeconfig file to read a
    context name from, which is expected when running inside the cluster.
    """
    if kube_context:
        return kube_context
    try:
        _, active_context = config.list_kube_config_contexts()
    except config.ConfigException:
        return "in-cluster"
    return active_context["name"]
