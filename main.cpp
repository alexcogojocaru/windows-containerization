#include <Windows.h>
#include <securitybaseapi.h>
#include <stdio.h>

int main (int argc, char** argv)
{
    LPCSTR boundaryDescName = "debug_boundary_desc";
    LPCSTR namespaceName    = "debug_namespace";

    HANDLE hBoundaryDesc = CreateBoundaryDescriptorA(
        boundaryDescName, 
        CREATE_BOUNDARY_DESCRIPTOR_ADD_APPCONTAINER_SID
    );
    if (hBoundaryDesc == NULL)
    {
        printf_s("CreateBoundaryDescriptorA error: %d\n", GetLastError());
        return 1;
    }

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID pSid = NULL;

    BOOL result = AllocateAndInitializeSid(
        &ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &pSid
    );
    if (result == FALSE)
    {
        printf_s("AllocateAndInitializeSid error: %d\n", GetLastError());
        return 1;
    }

    result = AddSIDToBoundaryDescriptor(&hBoundaryDesc, pSid);
    if (result == FALSE)
    {
        printf_s("AddSIDToBoundaryDescriptor error: %d\n", GetLastError());
        return 1;
    }

    PSECURITY_ATTRIBUTES pSecurityAttrs = NULL;
    HANDLE hNamespace = CreatePrivateNamespaceA(pSecurityAttrs, (LPVOID)hBoundaryDesc, namespaceName);
    if (hNamespace == NULL)
    {
        printf_s("CreatePrivateNamespaceA error: %d\n", GetLastError());
        return 1;
    }

    ClosePrivateNamespace(hNamespace, PRIVATE_NAMESPACE_FLAG_DESTROY);

    return 0;
}