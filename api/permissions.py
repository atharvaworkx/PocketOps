from rest_framework import permissions


class IsOwner(permissions.BasePermission):
    """
    Object-level permission: only the project owner can access it.
    """

    def has_object_permission(self, request, view, obj):
        # obj is a Project
        return obj.owner == request.user


class IsProjectOwner(permissions.BasePermission):
    """
    For nested resources (Endpoint, CheckResult, Incident, DiagnosticEvent)
    where the object has a .project FK.
    """

    def has_object_permission(self, request, view, obj):
        project = getattr(obj, "project", None)
        if project is None:
            return False
        return project.owner == request.user
