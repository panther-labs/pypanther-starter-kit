from enum import Enum


class CustomLogType(str, Enum):
    HOST_IDS = "Custom.HostIDS"
    NETWORK_IDS = "Custom.NetworkIDS"
