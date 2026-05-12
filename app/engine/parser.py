"""Parsers for Terraform HCL and CloudFormation JSON/YAML."""

import json
import yaml


def parse_terraform(content: str) -> dict:
    """Parse Terraform HCL content into a normalized resource dictionary.

    Attempts HCL2 parsing first, falls back to JSON if the file is .tf.json format.
    Returns a dict of {resource_type: {resource_name: {config}}}.
    """
    try:
        import hcl2
        import io
        parsed = hcl2.load(io.StringIO(content))
        return _normalize_terraform(parsed)
    except Exception:
        pass

    try:
        parsed = json.loads(content)
        if "resource" in parsed:
            return _normalize_terraform_json(parsed)
        return _normalize_terraform(parsed)
    except Exception:
        pass

    return {}


def _normalize_terraform(parsed: dict) -> dict:
    """Normalize HCL2-parsed Terraform into {type: {name: config}}."""
    resources = {}
    raw_resources = parsed.get("resource", [])

    if isinstance(raw_resources, list):
        for block in raw_resources:
            if isinstance(block, dict):
                for resource_type, instances in block.items():
                    if resource_type not in resources:
                        resources[resource_type] = {}
                    if isinstance(instances, dict):
                        for name, config in instances.items():
                            resources[resource_type][name] = _unwrap_hcl2(config)
                    elif isinstance(instances, list):
                        for inst in instances:
                            if isinstance(inst, dict):
                                for name, config in inst.items():
                                    resources[resource_type][name] = _unwrap_hcl2(config)
    elif isinstance(raw_resources, dict):
        for resource_type, instances in raw_resources.items():
            resources[resource_type] = {}
            if isinstance(instances, dict):
                for name, config in instances.items():
                    resources[resource_type][name] = _unwrap_hcl2(config)

    return resources


def _unwrap_hcl2(value):
    """HCL2 parser wraps scalar values in single-element lists. Unwrap them."""
    if isinstance(value, list) and len(value) == 1:
        return _unwrap_hcl2(value[0])
    if isinstance(value, dict):
        return {k: _unwrap_hcl2(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_unwrap_hcl2(v) for v in value]
    return value


def _normalize_terraform_json(parsed: dict) -> dict:
    """Normalize Terraform JSON format into {type: {name: config}}."""
    resources = {}
    for resource_type, instances in parsed.get("resource", {}).items():
        resources[resource_type] = {}
        if isinstance(instances, dict):
            for name, config in instances.items():
                resources[resource_type][name] = config
    return resources


def parse_cloudformation(content: str) -> dict:
    """Parse CloudFormation JSON/YAML into a normalized resource dictionary.

    Returns a dict of {resource_name: {Type: str, Properties: dict}}.
    """
    try:
        parsed = json.loads(content)
    except (json.JSONDecodeError, ValueError):
        try:
            parsed = yaml.safe_load(content)
        except yaml.YAMLError:
            return {}

    if not isinstance(parsed, dict):
        return {}

    return parsed.get("Resources", {})


def detect_format(filename: str, content: str) -> str:
    """Detect whether the file is Terraform or CloudFormation.

    Returns 'terraform' or 'cloudformation'.
    """
    lower = filename.lower()

    if lower.endswith((".tf", ".tf.json")):
        return "terraform"
    if lower.endswith((".template", ".cfn.json", ".cfn.yaml", ".cfn.yml")):
        return "cloudformation"

    try:
        parsed = json.loads(content)
        if "AWSTemplateFormatVersion" in parsed or "Resources" in parsed:
            return "cloudformation"
    except Exception:
        pass

    try:
        parsed = yaml.safe_load(content)
        if isinstance(parsed, dict) and ("AWSTemplateFormatVersion" in parsed or "Resources" in parsed):
            return "cloudformation"
    except Exception:
        pass

    if "resource" in content and "{" in content:
        return "terraform"

    return "terraform"
