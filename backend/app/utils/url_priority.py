"""URL prioritization for security scanning.

Scores discovered URLs by their likelihood to contain vulnerabilities,
so we can focus active scanning on the most important pages first.
"""

import re
from urllib.parse import parse_qs, urlparse

# Patterns that indicate high-risk pages
HIGH_RISK_PATTERNS = [
    # Authentication pages
    (r"/login", 100, "Login page"),
    (r"/signin", 100, "Sign-in page"),
    (r"/auth", 100, "Authentication page"),
    (r"/register", 95, "Registration page"),
    (r"/signup", 95, "Sign-up page"),
    (r"/forgot[-_]?password", 90, "Password recovery page"),
    (r"/reset[-_]?password", 90, "Password reset page"),
    # Admin panels
    (r"/admin", 95, "Admin panel"),
    (r"/dashboard", 85, "Dashboard"),
    (r"/manage", 80, "Management page"),
    (r"/console", 80, "Console"),
    # User-related pages
    (r"/profile", 85, "User profile page"),
    (r"/account", 85, "Account page"),
    (r"/settings", 80, "Settings page"),
    (r"/user", 80, "User page"),
    # Data manipulation pages
    (r"/upload", 95, "File upload page"),
    (r"/import", 85, "Import page"),
    (r"/export", 70, "Export page"),
    (r"/download", 70, "Download page"),
    # API endpoints
    (r"/api/", 80, "API endpoint"),
    (r"/graphql", 85, "GraphQL endpoint"),
    (r"/rest/", 80, "REST endpoint"),
    # Search and forms
    (r"/search", 80, "Search page"),
    (r"/query", 75, "Query page"),
    (r"/filter", 70, "Filter page"),
    # Payment pages
    (r"/payment", 95, "Payment page"),
    (r"/checkout", 95, "Checkout page"),
    (r"/cart", 80, "Shopping cart"),
    (r"/order", 80, "Order page"),
    # Comment/feedback forms
    (r"/comment", 75, "Comment page"),
    (r"/feedback", 70, "Feedback page"),
    (r"/contact", 70, "Contact page"),
]

# URL features that increase risk score
URL_FEATURE_SCORES = {
    "has_query_params": 20,  # Pages with params are more likely to have injection points
    "has_path_params": 15,  # Pages with path variables
    "has_file_extension": 5,  # Pages serving files
    "is_post_endpoint": 25,  # POST endpoints often handle data mutation
    "has_multiple_params": 10,  # Multiple params = more attack surface
}


def score_url(url: str) -> tuple[int, list[str]]:
    """Score a URL by its security risk priority.
    
    Returns:
        Tuple of (score, list of reasons)
    """
    score = 50  # Base score
    reasons: list[str] = []
    
    parsed = urlparse(url)
    path = parsed.path.lower()
    query = parsed.query.lower()
    
    # Check against high-risk patterns
    for pattern, points, label in HIGH_RISK_PATTERNS:
        if re.search(pattern, path):
            score += points
            reasons.append(label)
            break  # Only count the first matching pattern
    
    # Check for query parameters
    params = parse_qs(query)
    if params:
        score += URL_FEATURE_SCORES["has_query_params"]
        reasons.append(f"Has {len(params)} query parameter(s)")
        
        # Check for dangerous parameter names
        param_names = set(params.keys())
        dangerous_params = {
            "id", "user", "file", "path", "url", "redirect", "callback",
            "return", "next", "dest", "destination", "goto", "target",
            "page", "search", "query", "q", "s", "keyword", "term",
            "name", "email", "username", "password", "token", "key",
            "data", "value", "input", "field", "content", "body",
            "callback", "jsonp", "format", "type", "action", "method",
        }
        dangerous_found = param_names & dangerous_params
        if dangerous_found:
            score += 15
            reasons.append(f"Dangerous params: {', '.join(dangerous_found)}")
        
        if len(params) >= 3:
            score += URL_FEATURE_SCORES["has_multiple_params"]
            reasons.append("Multiple parameters (larger attack surface)")
    
    # Check for path parameters (e.g., /users/123)
    path_parts = [p for p in path.split("/") if p]
    for part in path_parts:
        if part.isdigit() or re.match(r"^[a-f0-9]{8,}$", part):
            score += URL_FEATURE_SCORES["has_path_params"]
            reasons.append("Has path parameter (ID-like segment)")
            break
    
    # Check for file extensions
    if path_parts and "." in path_parts[-1]:
        ext = path_parts[-1].split(".")[-1].lower()
        if ext in ("php", "asp", "aspx", "jsp", "cgi", "py", "rb"):
            score += 15
            reasons.append(f"Dynamic page ({ext})")
    
    return min(score, 200), reasons


def prioritize_urls(urls: list[str], max_urls: int = 20) -> list[tuple[str, int, list[str]]]:
    """Sort URLs by security priority and return top N.
    
    Args:
        urls: List of discovered URLs
        max_urls: Maximum number of URLs to return for active scanning
        
    Returns:
        List of (url, score, reasons) tuples, sorted by score descending
    """
    scored = []
    for url in urls:
        score, reasons = score_url(url)
        scored.append((url, score, reasons))
    
    # Sort by score descending
    scored.sort(key=lambda x: x[1], reverse=True)
    
    return scored[:max_urls]


def get_scan_scope(urls: list[str], max_urls: int = 20) -> dict:
    """Get a prioritized scan scope from discovered URLs.
    
    Returns:
        Dict with 'priority_urls' (top N for active scan) and 
        'all_urls' (full list for reference)
    """
    prioritized = prioritize_urls(urls, max_urls)
    
    return {
        "priority_urls": [
            {"url": url, "score": score, "reasons": reasons}
            for url, score, reasons in prioritized
        ],
        "total_discovered": len(urls),
        "scanning": len(prioritized),
        "skipped": max(0, len(urls) - len(prioritized)),
    }
