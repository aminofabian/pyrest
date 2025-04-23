def api_response(data=None, message=None, status_code=200, errors=None, success=None):
    """
    Standardize API responses for consistent frontend handling
    """
    # If success is not explicitly provided, determine based on status code and errors
    if success is None:
        success = status_code < 400 and not errors
    
    response = {
        'success': success,
        'message': message,
        'data': data,
    }
    
    if errors:
        response['errors'] = errors
        
    return response 