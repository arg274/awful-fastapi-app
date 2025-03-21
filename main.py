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
def get_workspaces():
    return {"workspaces": workspaces}


# For testing: Get all users
@app.get("/users")
def get_users():
    return {"users": users}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
