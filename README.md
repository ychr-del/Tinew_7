Tinew 7.exe

NtCreateToken

Overview
NtCreateTokenFull is a research-oriented C# project designed to explore advanced Windows privilege escalation techniques. It demonstrates how to combine LSASS SYSTEM token theft with custom token forging via NtCreateToken, resulting in a two-stage escalation path that culminates in TrustedInstaller-level access.  

This project is intended for educational and research purposes only, providing insight into Windows internals and token mechanics.

Key Features
- LSASS SYSTEM token theft  
  Extracts a SYSTEM-level token from the Local Security Authority Subsystem Service (LSASS).

- NtCreateToken forging  
  Uses the undocumented NtCreateToken syscall to craft a new token with arbitrary attributes such as user SID, groups, and privileges.

- TrustedInstaller token creation  
  Demonstrates forging a token with TrustedInstaller rights, enabling full control over protected system resources.

- Two-stage escalation  
  - Stage 1: SYSTEM token theft.  
  - Stage 2: TrustedInstaller token forging.  

Technical Details
- Token structures manipulated:  
  - TOKEN_USER — defines the user SID.  
  - TOKEN_GROUPS — specifies group memberships.  
  - TOKEN_PRIVILEGES — sets privileges such as SeDebugPrivilege, SeTakeOwnershipPrivilege, and SeRestorePrivilege.  

- Privilege set:  
  The forged token is configured with a comprehensive set of high-level privileges, enabling operations normally restricted to system services.  

- Security context:  
  By directly creating tokens, the project bypasses common defenses that rely on token integrity and duplication restrictions.  

Compilation
The project is written in C# and requires the .NET compiler:

`
csc /langversion:8 NtCreateTokenFull.cs
`

This produces an executable that demonstrates the token manipulation techniques.

Usage
1. Compile the project using the command above.  
2. Run the executable in a controlled environment (e.g., a test VM).  
3. Observe the escalation sequence:  
   - SYSTEM token theft from LSASS.  
   - Token forging via NtCreateToken.  
   - TrustedInstaller-level access demonstration.
 4. Type "whoami" into the launched command prompt to verify it.

Disclaimer
This project is for educational and research purposes only.  
Do not use it in production environments or for unauthorized access. Misuse may violate laws and regulations.
