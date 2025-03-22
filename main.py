from datetime import datetime
import random
from fastapi import FastAPI, Depends, HTTPException, status, Header
from pydantic import BaseModel
from typing import Optional, List
import uuid

app = FastAPI()

# Dummy database
workspaces = {}
users = {
    "user1": {
        "id": "user1",
        "name": "John Doe",
        "email": "john@example.com",
        "role": "user",
    },
    "user2": {
        "id": "user2",
        "name": "Jane Smith",
        "email": "jane@example.com",
        "role": "admin",
    },
}

# Dummy auth tokens
auth_tokens = {
    "token1": "user1",
    "token2": "user2",
}


# Models
class User(BaseModel):
    id: str
    name: str
    email: str
    role: str = "user"


class UserUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    role: Optional[str] = None


class Workspace(BaseModel):
    id: Optional[str] = None
    name: str
    description: Optional[str] = None
    members: List[str] = []


class WorkspaceMembership(BaseModel):
    workspace_id: str
    user_id: str


# Dependency
def get_current_user(authorization: Optional[str] = Header(None)):
    if authorization is None:
        return None

    token = authorization.replace("Bearer ", "")
    if token not in auth_tokens:
        return None

    user_id = auth_tokens[token]
    return users.get(user_id)


# VULNERABILITY 1: Missing authorization check (does not verify admin role)
# The endpoint checks authentication but not authorization
@app.post("/workspace/membership")
def add_member_to_workspace(
    membership: WorkspaceMembership,
    current_user: Optional[dict] = Depends(get_current_user),
):
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )

    # MISSING CHECK: Should verify current_user has admin role or owns the workspace

    if membership.workspace_id not in workspaces:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Workspace not found",
        )

    if membership.user_id not in users:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User not found"
        )

    # Add user to workspace
    workspace = workspaces[membership.workspace_id]
    if membership.user_id not in workspace["members"]:
        workspace["members"].append(membership.user_id)

    return {"message": "User added to workspace", "workspace": workspace}


# VULNERABILITY 2: Missing check for user identity
# The endpoint allows any authenticated user to update any user's details
@app.put("/user/{user_id}")
def update_user(
    user_id: str,
    user_update: UserUpdate,
    current_user: Optional[dict] = Depends(get_current_user),
):
    if current_user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required"
        )

    # MISSING CHECK: Should verify current_user.id == user_id or current_user has admin role

    if user_id not in users:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="User not found"
        )

    # Update user details
    user = users[user_id]
    if user_update.name:
        user["name"] = user_update.name
    if user_update.email:
        user["email"] = user_update.email
    if user_update.role:
        user["role"] = user_update.role

    return {"message": "User updated", "user": user}


# VULNERABILITY 3: No authentication check at all
# Any user can create a workspace without even being authenticated
@app.post("/workspace")
def create_workspace(workspace: Workspace):
    # MISSING CHECK: Should verify user is authenticated
    # MISSING CHECK: Should verify user has permission to create workspaces

    try:
        workspace_id = workspace.id or str(uuid.uuid4())
        workspace_dict = workspace.dict()
        workspace_dict["id"] = workspace_id
        workspaces[workspace_id] = workspace_dict
        return {"message": "Workspace created", "workspace": workspace_dict}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create workspace: {str(e)}",
        )


# For testing: Get all workspaces
@app.get("/workspaces")
def get_workspaces(
    limit: int = 50,
    offset: int = 0,
    sort_by: str = "name",
    sort_order: str = "asc",
    type: str = None,
    status: str = None,
    owner_id: str = None,
    created_after: str = None,
    created_before: str = None,
    include_members: bool = False,
    include_resources: bool = False,
    include_deleted: bool = False,
    search: str = None,
    format: str = "json",
):
    result = workspaces.copy()

    # Apply filters
    if type:
        result = [ws for ws in result if ws.get("type") == type]

    if status:
        result = [ws for ws in result if ws.get("status") == status]

    if owner_id:
        result = [ws for ws in result if ws.get("owner_id") == owner_id]

    if created_after:
        try:
            created_after_date = datetime.fromisoformat(created_after)
            result = [
                ws
                for ws in result
                if datetime.fromisoformat(ws.get("created_at", "1970-01-01"))
                >= created_after_date
            ]
        except ValueError:
            return {
                "error": "Invalid date format for created_after. Use ISO format (YYYY-MM-DD)."
            }

    if created_before:
        try:
            created_before_date = datetime.fromisoformat(created_before)
            result = [
                ws
                for ws in result
                if datetime.fromisoformat(ws.get("created_at", "2099-12-31"))
                <= created_before_date
            ]
        except ValueError:
            return {
                "error": "Invalid date format for created_before. Use ISO format (YYYY-MM-DD)."
            }

    if not include_deleted:
        result = [ws for ws in result if not ws.get("deleted_at")]

    if search:
        search = search.lower()
        result = [
            ws
            for ws in result
            if search in ws.get("name", "").lower()
            or search in ws.get("description", "").lower()
        ]

    # Apply sorting
    if sort_by in ["name", "created_at", "updated_at", "member_count"]:
        reverse = sort_order.lower() == "desc"
        result.sort(key=lambda x: x.get(sort_by, ""), reverse=reverse)

    # Calculate total before pagination
    total_count = len(result)

    # Apply pagination
    result = result[offset : offset + limit]

    # Enhance response with additional data
    if include_members:
        for ws in result:
            # This would normally be a database join but we're just adding dummy data
            if "id" in ws:
                ws["members"] = [
                    {"user_id": f"user_{i}", "role": "member" if i > 1 else "admin"}
                    for i in range(1, random.randint(3, 8))
                ]

    if include_resources:
        for ws in result:
            # Again, just adding dummy data
            if "id" in ws:
                ws["resources"] = [
                    {
                        "id": f"resource_{i}",
                        "type": random.choice(["document", "dashboard", "dataset"]),
                        "name": f"Resource {i} for {ws.get('name', 'Unknown')}",
                    }
                    for i in range(1, random.randint(2, 6))
                ]

    # Handle different response formats
    if format == "csv":
        if not result:
            return "No results found"
        headers = result[0].keys()
        csv_content = ",".join(headers) + "\n"
        for item in result:
            csv_content += ",".join(str(item.get(h, "")) for h in headers) + "\n"
        return csv_content
    elif format == "summary":
        return {
            "count": len(result),
            "types": {
                ws_type: len([ws for ws in result if ws.get("type") == ws_type])
                for ws_type in set(ws.get("type", "unknown") for ws in result)
            },
            "statuses": {
                ws_status: len([ws for ws in result if ws.get("status") == ws_status])
                for ws_status in set(ws.get("status", "unknown") for ws in result)
            },
        }

    # Log this request
    print(f"Workspaces list requested: {len(result)} workspaces returned")

    # Calculate some statistics
    stats = {
        "total_count": total_count,
        "returned_count": len(result),
        "processing_time_ms": 37,  # Dummy value
    }

    return {
        "workspaces": result,
        "pagination": {"limit": limit, "offset": offset, "total": total_count},
        "filters": {
            "type": type,
            "status": status,
            "owner_id": owner_id,
            "include_deleted": include_deleted,
            "search": search,
        },
        "stats": stats,
    }


# For testing: Get all users
@app.get("/users")
def get_users(
    limit: int = 100,
    offset: int = 0,
    sort_by: str = "username",
    sort_order: str = "asc",
    status: str = None,
    role: str = None,
    search: str = None,
    include_deleted: bool = False,
    detailed: bool = False,
    format: str = "json",
):
    result = users.copy()

    # Apply filters
    if status:
        if status == "active":
            result = [user for user in result if user.get("is_active", False)]
        elif status == "inactive":
            result = [user for user in result if not user.get("is_active", False)]
        elif status == "pending":
            result = [user for user in result if user.get("status") == "pending"]

    if role:
        result = [user for user in result if user.get("role") == role]

    if search:
        search = search.lower()
        result = [
            user
            for user in result
            if search in user.get("username", "").lower()
            or search in user.get("email", "").lower()
            or search in user.get("full_name", "").lower()
        ]

    if not include_deleted:
        result = [user for user in result if not user.get("deleted_at")]

    # Apply sorting
    if sort_by in ["username", "email", "created_at", "last_login"]:
        reverse = sort_order.lower() == "desc"
        result.sort(key=lambda x: x.get(sort_by, ""), reverse=reverse)

    # Apply pagination
    total_count = len(result)
    result = result[offset : offset + limit]

    # Format response
    if not detailed:
        result = [
            {"id": user.get("id"), "username": user.get("username")} for user in result
        ]

    if format == "csv":
        # Convert to CSV format
        if not result:
            return "No results found"
        headers = result[0].keys()
        csv_content = ",".join(headers) + "\n"
        for item in result:
            csv_content += ",".join(str(item.get(h, "")) for h in headers) + "\n"
        return csv_content

    # Log this action
    print(
        f"Users list requested with filters: status={status}, role={role}, search={search}"
    )

    # Calculate some statistics
    stats = {
        "total_count": total_count,
        "returned_count": len(result),
        "processing_time_ms": 42,  # Dummy value
    }

    return {
        "users": result,
        "pagination": {"limit": limit, "offset": offset, "total": total_count},
        "filters": {
            "status": status,
            "role": role,
            "search": search,
            "include_deleted": include_deleted,
        },
        "stats": stats,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
