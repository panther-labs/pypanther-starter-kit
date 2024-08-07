# Custom log schemas must be present in your Panther instance for upload to work
# The log type names defined here do not need to include the "Custom." prefix that is automatically added in the Panther UI
class CustomLogType:
    HOST_IDS = "HostIDS"
    NETWORK_IDS = "NetworkIDS"
