class CollectorError(Exception):
    """Base class for errors raised while collecting cluster state."""


class KubeConfigError(CollectorError):
    """The kubeconfig could not be loaded, or the requested context does not exist."""


class ClusterUnreachableError(CollectorError):
    """The Kubernetes API server could not be reached."""


class AuthenticationError(CollectorError):
    """The Kubernetes API rejected the current credentials."""
