ROLE_PERMISSIONS = {
    "Admin": {
        "permissions": ["read", "write", "delete", "manage_users"],
        "collections": ["*"]
    },
    "Data Scientist": {
        "permissions": ["read", "write"],
        "collections": ["sensitive_data", "analysis_results", "model_data"]
    },
    "Data Analyst": {
        "permissions": ["read"],
        "collections": ["sensitive_data", "analysis_results"]
    },
    "Viewer": {
        "permissions": ["read"],
        "collections": ["analysis_results"]
    }
}