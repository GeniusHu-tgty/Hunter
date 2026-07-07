"""
auto_graphql.py - Automated GraphQL vulnerability detection and exploitation
"""

import re
import json
from typing import Optional


def _get_session():
    """Get HTTP session with fallback."""
    try:
        from tools.probe import _get_session as _gs
        return _gs()
    except (ImportError, ModuleNotFoundError):
        import requests
        s = requests.Session()
        s.verify = False
        s.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'})
        return s


def discover_endpoint(base_url: str) -> dict:
    """Discover GraphQL endpoint on target."""
    session = _get_session()
    endpoints_found = []

    # Common GraphQL endpoint paths
    common_paths = [
        '/graphql', '/graphiql', '/api/graphql', '/v1/graphql',
        '/v2/graphql', '/query', '/gql', '/graph',
        '/graphql/console', '/playground', '/altair',
    ]

    for path in common_paths:
        url = base_url.rstrip('/') + path
        try:
            # Try introspection query
            resp = session.post(url, json={"query": "{__typename}"}, timeout=8)
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    if 'data' in data or 'errors' in data:
                        endpoints_found.append({
                            "url": url,
                            "status": resp.status_code,
                            "has_graphql": True
                        })
                except json.JSONDecodeError:
                    pass

            # Also try GET with query param
            resp_get = session.get(url, params={"query": "{__typename}"}, timeout=8)
            if resp_get.status_code == 200:
                try:
                    data = resp_get.json()
                    if 'data' in data or 'errors' in data:
                        if not any(e["url"] == url for e in endpoints_found):
                            endpoints_found.append({
                                "url": url,
                                "method": "GET",
                                "has_graphql": True
                            })
                except json.JSONDecodeError:
                    pass
        except Exception:
            continue

    return {
        "base_url": base_url,
        "endpoints": endpoints_found,
        "found": len(endpoints_found) > 0
    }


def introspect(endpoint: str) -> dict:
    """Run full introspection query to discover schema."""
    session = _get_session()

    # Standard introspection query
    introspection_query = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields {
            name
            type {
              name
              kind
              ofType {
                name
                kind
              }
            }
            args {
              name
              type { name kind }
            }
          }
          inputFields {
            name
            type { name kind }
          }
          enumValues {
            name
          }
        }
        directives {
          name
          locations
          args {
            name
            type { name kind }
          }
        }
      }
    }
    """

    try:
        resp = session.post(endpoint, json={"query": introspection_query}, timeout=15)
        data = resp.json()

        if 'errors' in data:
            # Introspection may be disabled
            return {
                "endpoint": endpoint,
                "introspection_disabled": True,
                "errors": data['errors'],
                "types": [],
                "queries": [],
                "mutations": []
            }

        schema = data.get('data', {}).get('__schema', {})
        types = schema.get('types', [])

        # Extract useful types (exclude built-in)
        user_types = [t for t in types if not t['name'].startswith('__')]

        # Extract queries and mutations
        query_type_name = schema.get('queryType', {}).get('name', 'Query')
        mutation_type_name = schema.get('mutationType', {}).get('name', 'Mutation')

        query_type = next((t for t in types if t['name'] == query_type_name), None)
        mutation_type = next((t for t in types if t['name'] == mutation_type_name), None)

        queries = query_type.get('fields', []) if query_type else []
        mutations = mutation_type.get('fields', []) if mutation_type else []

        return {
            "endpoint": endpoint,
            "introspection_disabled": False,
            "total_types": len(types),
            "user_types": [t['name'] for t in user_types],
            "queries": [{"name": q["name"], "args": [a["name"] for a in q.get("args", [])]} for q in queries],
            "mutations": [{"name": m["name"], "args": [a["name"] for a in m.get("args", [])]} for m in mutations],
            "raw_types": user_types
        }

    except Exception as e:
        return {"endpoint": endpoint, "error": str(e)}


def find_private_data(endpoint: str, schema: dict = None) -> dict:
    """Try to access private/unauthorized data through GraphQL."""
    if not schema:
        schema = introspect(endpoint)

    session = _get_session()
    findings = []

    queries = schema.get("queries", [])

    # Try each query to find data leaks
    for q in queries:
        qname = q["name"]
        args = q.get("args", [])

        # Try query without authentication
        query_str = _build_query(qname, args)
        try:
            resp = session.post(endpoint, json={"query": query_str}, timeout=10)
            data = resp.json()

            if 'data' in data and data['data'].get(qname):
                result_data = data['data'][qname]
                # Check if we got actual data
                if result_data and (isinstance(result_data, list) and len(result_data) > 0 or isinstance(result_data, dict)):
                    findings.append({
                        "query": qname,
                        "accessible": True,
                        "data_preview": str(result_data)[:200],
                        "type": "unauthenticated_access"
                    })
        except Exception:
            continue

    # Try to find hidden/private fields
    private_findings = _probe_private_fields(endpoint, session)
    findings.extend(private_findings)

    return {
        "endpoint": endpoint,
        "findings": findings,
        "private_data_found": len(findings) > 0
    }


def _build_query(query_name: str, args: list = None) -> str:
    """Build a GraphQL query string."""
    if args:
        arg_str = ", ".join([f'{a}: ""' for a in args])
        return f"{{ {query_name}({arg_str}) {{ id name email username role isAdmin password }} }}"
    return f"{{ {query_name} {{ id name email username role isAdmin password }} }}"


def _probe_private_fields(endpoint: str, session) -> list:
    """Probe for private fields like isAdmin, role, password."""
    findings = []

    # Common queries that might leak data
    test_queries = [
        ('{"query": "{ users { id username email role isAdmin } }"}', 'users_with_admin_field'),
        ('{"query": "{ user(id: 1) { id username email role isAdmin password } }"}', 'user_admin_fields'),
        ('{"query": "{ posts { id title content published private } }"}', 'private_posts'),
        ('{"query": "{ posts(isPublished: false) { id title content } }"}', 'unpublished_posts'),
    ]

    for query_json_str, test_name in test_queries:
        try:
            resp = session.post(endpoint, json=json.loads(query_json_str), timeout=10)
            data = resp.json()

            if 'data' in data and data['data']:
                for key, val in data['data'].items():
                    if val:
                        findings.append({
                            "test": test_name,
                            "query": key,
                            "data_preview": str(val)[:200],
                            "type": "private_field_access"
                        })
        except Exception:
            continue

    return findings


def test_batching(endpoint: str) -> dict:
    """Test for GraphQL batching (query batching attack)."""
    session = _get_session()

    # Try sending multiple queries in one request
    batch_query = [
        {"query": "{__typename}"},
        {"query": "{__typename}"},
        {"query": "{__typename}"}
    ]

    try:
        resp = session.post(endpoint, json=batch_query, timeout=10)
        data = resp.json()

        if isinstance(data, list) and len(data) == 3:
            return {
                "batching_supported": True,
                "severity": "medium",
                "details": "Server accepts batched queries - may bypass rate limiting"
            }
    except Exception:
        pass

    return {"batching_supported": False}


def test_depth_limit(endpoint: str, max_depth: int = 20) -> dict:
    """Test for query depth limit bypass (DoS potential)."""
    session = _get_session()

    # Build deeply nested query
    depth = max_depth
    query = "__typename " * depth
    nested_query = "{" + " ".join([f"a{i}{{" for i in range(depth)]) + "__typename" + "}" * (depth + 1)

    try:
        resp = session.post(endpoint, json={"query": nested_query}, timeout=15)
        data = resp.json()

        if 'errors' not in data or any('depth' not in str(e).lower() for e in data.get('errors', [])):
            return {
                "depth_limit": False,
                "severity": "medium",
                "details": f"Query with depth {max_depth} accepted - potential DoS via deep nesting"
            }
    except Exception:
        pass

    return {"depth_limit": True}


def test_field_suggestions(endpoint: str) -> dict:
    """Test if server leaks field names via suggestions."""
    session = _get_session()

    # Query with typo to trigger suggestions
    query = "{ users { id nme } }"  # 'nme' is typo for 'name'

    try:
        resp = session.post(endpoint, json={"query": query}, timeout=10)
        data = resp.json()

        if 'errors' in data:
            error_msg = str(data['errors'])
            if 'did you mean' in error_msg.lower() or 'suggestion' in error_msg.lower():
                return {
                    "suggestions_enabled": True,
                    "severity": "low",
                    "details": f"Field suggestions leak schema info: {error_msg[:200]}",
                    "suggestions": error_msg
                }
    except Exception:
        pass

    return {"suggestions_enabled": False}


def full_scan(base_url: str) -> dict:
    """Full GraphQL security scan."""
    results = {
        "base_url": base_url,
        "endpoint_discovery": None,
        "introspection": None,
        "private_data": None,
        "batching": None,
        "depth_limit": None,
        "field_suggestions": None,
        "findings_count": 0,
        "severity": "info"
    }

    # 1. Discover endpoint
    discovery = discover_endpoint(base_url)
    results["endpoint_discovery"] = discovery

    if not discovery["found"]:
        results["error"] = "No GraphQL endpoint found"
        return results

    endpoint = discovery["endpoints"][0]["url"]

    # 2. Introspection
    intro = introspect(endpoint)
    results["introspection"] = intro
    if not intro.get("introspection_disabled"):
        results["findings_count"] += 1
        results["severity"] = "medium"

    # 3. Find private data
    private = find_private_data(endpoint, intro)
    results["private_data"] = private
    if private["private_data_found"]:
        results["findings_count"] += len(private["findings"])
        results["severity"] = "high"

    # 4. Test batching
    batch = test_batching(endpoint)
    results["batching"] = batch
    if batch.get("batching_supported"):
        results["findings_count"] += 1

    # 5. Test depth limit
    depth = test_depth_limit(endpoint)
    results["depth_limit"] = depth
    if not depth.get("depth_limit"):
        results["findings_count"] += 1

    # 6. Test field suggestions
    suggestions = test_field_suggestions(endpoint)
    results["field_suggestions"] = suggestions
    if suggestions.get("suggestions_enabled"):
        results["findings_count"] += 1

    return results


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python auto_graphql.py <base_url>")
        sys.exit(1)

    url = sys.argv[1]
    result = full_scan(url)
    print(json.dumps(result, indent=2, default=str))
