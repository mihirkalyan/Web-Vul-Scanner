"""
Link Extractor Plugin

Response analyzer plugin that extracts links and forms from HTML responses
and reports them for crawler discovery.
"""

from typing import Optional
from bs4 import BeautifulSoup

from ..models import ScanRequest, ScanResponse
from ..plugin import ScanPlugin, PluginResult, PluginType, register
from ..scope_checker import ScopeChecker


@register(plugin_type=PluginType.RESPONSE_ANALYZER)
class LinkExtractorPlugin(ScanPlugin):
    """
    Extract links and forms from HTML responses.
    
    Parses response body for <a> and <form> elements, resolves relative URLs,
    and filters results by scope.
    """
    
    name = "LinkExtractor"
    version = "1.0.0"
    description = "Extract links and forms from HTML responses"
    plugin_type = PluginType.RESPONSE_ANALYZER
    author = "Scanner Team"
    
    def __init__(self, scope_checker: Optional[ScopeChecker] = None, **kwargs):
        """
        Initialize plugin.
        
        Args:
            scope_checker: ScopeChecker instance for URL filtering
        """
        super().__init__(**kwargs)
        self.scope_checker = scope_checker
    
    def validate_config(self) -> bool:
        """Validate configuration."""
        return True
    
    async def execute(self, request: ScanRequest, 
                     response: Optional[ScanResponse] = None, 
                     **kwargs) -> PluginResult:
        """
        Extract links and forms from response.
        
        Args:
            request: Original scan request
            response: Response to analyze
            **kwargs: Additional arguments
        
        Returns:
            PluginResult with extracted links and forms
        """
        if not response or not response.body:
            return PluginResult(
                success=True,
                message="No response body to parse"
            )
        
        # Check content type
        content_type = response.get_header("Content-Type") or ""
        if "html" not in content_type.lower():
            return PluginResult(
                success=True,
                message="Response is not HTML"
            )
        
        try:
            soup = BeautifulSoup(response.body, "html.parser")
            links = []
            forms = []
            
            # Extract links
            for tag in soup.find_all("a", href=True):
                href = tag.get("href", "").strip()
                if href and not href.startswith(("#", "javascript:", "mailto:")):
                    try:
                        from urllib.parse import urljoin
                        absolute_url = urljoin(request.url, href)
                        
                        # Filter by scope if checker provided
                        if self.scope_checker:
                            if self.scope_checker.is_in_scope(absolute_url):
                                links.append(absolute_url)
                        else:
                            links.append(absolute_url)
                    except Exception as e:
                        self.log("debug", f"Error processing link {href}: {str(e)}")
            
            # Extract forms
            for form_tag in soup.find_all("form"):
                form_info = {
                    "url": request.url,
                    "method": (form_tag.get("method", "GET")).upper(),
                    "action": form_tag.get("action", ""),
                    "inputs": []
                }
                
                # Resolve form action to absolute URL
                if form_info["action"]:
                    from urllib.parse import urljoin
                    form_info["action_url"] = urljoin(
                        request.url, 
                        form_info["action"]
                    )
                else:
                    form_info["action_url"] = request.url
                
                # Extract input fields
                for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                    input_name = input_tag.get("name")
                    if input_name:
                        form_info["inputs"].append({
                            "name": input_name,
                            "type": input_tag.get("type", "text").lower(),
                            "value": input_tag.get("value", "")
                        })
                
                forms.append(form_info)
            
            self.log("debug", f"Extracted {len(links)} links and {len(forms)} forms")
            
            return PluginResult(
                success=True,
                message=f"Extracted {len(links)} links and {len(forms)} forms",
                data={
                    "links": links,
                    "forms": forms,
                    "unique_links": len(set(links)),
                    "form_count": len(forms)
                }
            )
        
        except Exception as e:
            error_msg = f"Error parsing HTML: {str(e)}"
            self.log("error", error_msg)
            return PluginResult(
                success=False,
                message=error_msg
            )


@register(plugin_type=PluginType.RESPONSE_ANALYZER)
class FormDetectorPlugin(ScanPlugin):
    """
    Detect and analyze forms in HTML responses.
    
    Focuses on form discovery and field enumeration for vulnerability testing.
    """
    
    name = "FormDetector"
    version = "1.0.0"
    description = "Detect and analyze HTML forms"
    plugin_type = PluginType.RESPONSE_ANALYZER
    author = "Scanner Team"
    
    def validate_config(self) -> bool:
        """Validate configuration."""
        return True
    
    async def execute(self, request: ScanRequest,
                     response: Optional[ScanResponse] = None,
                     **kwargs) -> PluginResult:
        """
        Analyze forms in response.
        
        Args:
            request: Original scan request
            response: Response to analyze
            **kwargs: Additional arguments
        
        Returns:
            PluginResult with form analysis
        """
        if not response or not response.body:
            return PluginResult(success=True)
        
        content_type = response.get_header("Content-Type") or ""
        if "html" not in content_type.lower():
            return PluginResult(success=True)
        
        try:
            soup = BeautifulSoup(response.body, "html.parser")
            forms = []
            
            for form_tag in soup.find_all("form"):
                form_data = {
                    "form_index": len(forms),
                    "method": (form_tag.get("method", "GET")).upper(),
                    "action": form_tag.get("action", ""),
                    "id": form_tag.get("id"),
                    "name": form_tag.get("name"),
                    "class": form_tag.get("class", []),
                    "fields": {
                        "text": [],
                        "password": [],
                        "hidden": [],
                        "checkbox": [],
                        "radio": [],
                        "select": [],
                        "textarea": [],
                        "button": [],
                        "other": []
                    },
                    "total_fields": 0
                }
                
                # Analyze form fields
                for input_tag in form_tag.find_all(["input", "textarea", "select"]):
                    field_type = input_tag.get("type", "text").lower()
                    if field_type not in form_data["fields"]:
                        field_type = "other"
                    
                    field_info = {
                        "name": input_tag.get("name"),
                        "type": field_type,
                        "id": input_tag.get("id"),
                        "class": input_tag.get("class", []),
                        "value": input_tag.get("value", ""),
                        "required": "required" in input_tag.attrs,
                        "disabled": "disabled" in input_tag.attrs
                    }
                    
                    if field_info["name"]:
                        form_data["fields"][field_type].append(field_info)
                        form_data["total_fields"] += 1
                
                forms.append(form_data)
            
            return PluginResult(
                success=True,
                message=f"Detected {len(forms)} form(s)",
                data={
                    "forms": forms,
                    "total_forms": len(forms),
                    "total_fields": sum(f["total_fields"] for f in forms)
                }
            )
        
        except Exception as e:
            error_msg = f"Form detection error: {str(e)}"
            self.log("error", error_msg)
            return PluginResult(success=False, message=error_msg)
